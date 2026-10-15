package main

import (
	"bufio"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	mgmtDialTimeout     = 5 * time.Second
	mgmtIOTimeout       = 10 * time.Second
	mgmtStartupAttempts = 10
	mgmtStartupDelay    = 2 * time.Second
)

type clientStatus struct {
	CommonName              string
	RealAddress             string
	BytesReceived           string
	BytesSent               string
	ConnectedSince          string
	VirtualAddress          string
	VirtualAddressIPv6      string
	LastRef                 string
	ConnectedSinceFormatted string
	LastRefFormatted        string
	ConnectedTo             string

	connectedSinceUnix int64
	lastRefUnix        int64
}

// Column layout of OpenVPN 2.4; used only if the status output has no HEADER lines.
var (
	defaultClientListColumns   = []string{"Common Name", "Real Address", "Virtual Address", "Virtual IPv6 Address", "Bytes Received", "Bytes Sent", "Connected Since", "Connected Since (time_t)", "Username", "Client ID", "Peer ID"}
	defaultRoutingTableColumns = []string{"Virtual Address", "Common Name", "Real Address", "Last Ref", "Last Ref (time_t)"}
)

// mgmtDial connects to a management interface and reads the welcome message.
func mgmtDial(addr string) (net.Conn, *bufio.Reader, error) {
	conn, err := net.DialTimeout("tcp", addr, mgmtDialTimeout)
	if err != nil {
		return nil, nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(mgmtIOTimeout)); err != nil {
		conn.Close()
		return nil, nil, err
	}

	reader := bufio.NewReader(conn)
	// >INFO:OpenVPN Management Interface Version 3 -- type 'help' for more info
	if _, err := mgmtReadUntil(reader, func(line string) bool { return strings.HasPrefix(line, ">INFO:") }); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("reading welcome message: %w", err)
	}

	return conn, reader, nil
}

// mgmtReadUntil reads lines until done returns true for one of them.
func mgmtReadUntil(reader *bufio.Reader, done func(line string) bool) (string, error) {
	var out strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			line = strings.TrimRight(line, "\r\n")
			out.WriteString(line)
			out.WriteByte('\n')
			if done(line) {
				return out.String(), nil
			}
		}
		if err != nil {
			return out.String(), err
		}
	}
}

// mgmtCommand sends one command to a management interface and returns the response.
func mgmtCommand(addr, command string, done func(line string) bool) (string, error) {
	conn, reader, err := mgmtDial(addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(command + "\n")); err != nil {
		return "", err
	}

	return mgmtReadUntil(reader, done)
}

func isMgmtEnd(line string) bool {
	return line == "END" || strings.HasPrefix(line, "ERROR:")
}

func isMgmtResult(line string) bool {
	return strings.HasPrefix(line, "SUCCESS:") || strings.HasPrefix(line, "ERROR:")
}

func mgmtTableColumns(columns []string) map[string]int {
	m := make(map[string]int, len(columns))
	for i, name := range columns {
		// field 0 of a record is the record type (CLIENT_LIST, ROUTING_TABLE)
		m[strings.TrimSpace(name)] = i + 1
	}
	return m
}

func mgmtField(record []string, columns map[string]int, name string) string {
	i, ok := columns[name]
	if !ok || i >= len(record) {
		return ""
	}
	return strings.TrimSpace(record[i])
}

// mgmtTime returns unix time from a time_t column, falling back to the human readable column.
func mgmtTime(timeT, human string) int64 {
	if ts, err := strconv.ParseInt(timeT, 10, 64); err == nil && ts > 0 {
		return ts
	}
	for _, layout := range []string{stringDateFormat, time.ANSIC} {
		if t, err := time.ParseInLocation(layout, human, time.Local); err == nil {
			return t.Unix()
		}
	}
	return 0
}

func formatMgmtTime(ts int64, raw string) string {
	if ts > 0 {
		return time.Unix(ts, 0).Format(stringDateFormat)
	}
	return raw
}

func normalizeVirtualAddress(s string) string {
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap().String()
	}
	return s
}

// normalizeRealAddress converts the "Real Address" column to netip.AddrPort/Addr
// string form. It strips "[AF_INET]"/"[AF_INET6]" prefixes, understands "[v6]:port",
// "v4:port", "v6:port" (the last colon is the port) and unmaps "::ffff:a.b.c.d".
// Unparseable values are returned unchanged.
func normalizeRealAddress(raw string) string {
	s := strings.TrimSpace(raw)
	for _, prefix := range []string{"[AF_INET6]", "[AF_INET]"} {
		s = strings.TrimPrefix(s, prefix)
	}

	if ap, err := netip.ParseAddrPort(s); err == nil {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String()
	}

	// OpenVPN prints native IPv6 peers without a port; prefer that reading when the
	// value is a valid address on its own ("2001:db8::1:1194" is ambiguous).
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap().String()
	}

	if i := strings.LastIndex(s, ":"); i > 0 {
		host, portStr := s[:i], s[i+1:]
		port, perr := strconv.ParseUint(portStr, 10, 16)
		addr, aerr := netip.ParseAddr(host)
		if perr == nil && aerr == nil {
			return netip.AddrPortFrom(addr.Unmap(), uint16(port)).String()
		}
	}

	return raw
}

type mgmtRoute struct {
	virtualAddress string
	commonName     string
	realAddress    string
	lastRef        int64
	lastRefRaw     string
}

// parseMgmtStatus parses the output of the "status 3" (tab separated) management
// command. "status 2" (comma separated) output is understood as well.
// Columns are taken from the HEADER lines because they differ across OpenVPN versions.
func parseMgmtStatus(text, serverName string) []clientStatus {
	clientColumns := mgmtTableColumns(defaultClientListColumns)
	routeColumns := mgmtTableColumns(defaultRoutingTableColumns)

	var sessions []clientStatus
	var routes []mgmtRoute

scan:
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, ">") {
			continue
		}

		sep := "\t"
		if !strings.Contains(line, "\t") {
			sep = ","
		}
		record := strings.Split(line, sep)

		switch record[0] {
		case "END":
			break scan
		case "HEADER":
			if len(record) < 2 {
				continue
			}
			switch record[1] {
			case "CLIENT_LIST":
				clientColumns = mgmtTableColumns(record[2:])
			case "ROUTING_TABLE":
				routeColumns = mgmtTableColumns(record[2:])
			}
		case "CLIENT_LIST":
			connectedSinceRaw := mgmtField(record, clientColumns, "Connected Since")
			s := clientStatus{
				CommonName:         mgmtField(record, clientColumns, "Common Name"),
				RealAddress:        normalizeRealAddress(mgmtField(record, clientColumns, "Real Address")),
				BytesReceived:      mgmtField(record, clientColumns, "Bytes Received"),
				BytesSent:          mgmtField(record, clientColumns, "Bytes Sent"),
				VirtualAddress:     normalizeVirtualAddress(mgmtField(record, clientColumns, "Virtual Address")),
				VirtualAddressIPv6: normalizeVirtualAddress(mgmtField(record, clientColumns, "Virtual IPv6 Address")),
				ConnectedTo:        serverName,
				connectedSinceUnix: mgmtTime(mgmtField(record, clientColumns, "Connected Since (time_t)"), connectedSinceRaw),
			}
			s.ConnectedSince = formatMgmtTime(s.connectedSinceUnix, connectedSinceRaw)
			sessions = append(sessions, s)
		case "ROUTING_TABLE":
			lastRefRaw := mgmtField(record, routeColumns, "Last Ref")
			routes = append(routes, mgmtRoute{
				virtualAddress: mgmtField(record, routeColumns, "Virtual Address"),
				commonName:     mgmtField(record, routeColumns, "Common Name"),
				realAddress:    normalizeRealAddress(mgmtField(record, routeColumns, "Real Address")),
				lastRef:        mgmtTime(mgmtField(record, routeColumns, "Last Ref (time_t)"), lastRefRaw),
				lastRefRaw:     lastRefRaw,
			})
		}
	}

	for _, route := range routes {
		// iroute entries (networks behind a client) are printed as network/bits;
		// cached host routes to such networks get the "C" flag appended ("10.20.0.5C",
		// "fd00:1::5C" - addresses are printed in lower case, so "C" is always the flag)
		if route.virtualAddress == "" || strings.Contains(route.virtualAddress, "/") || strings.HasSuffix(route.virtualAddress, "C") {
			continue
		}

		i := matchMgmtSession(sessions, route.commonName, route.realAddress)
		if i < 0 {
			continue
		}
		s := &sessions[i]

		if s.LastRef == "" || route.lastRef > s.lastRefUnix {
			s.lastRefUnix = route.lastRef
			s.LastRef = formatMgmtTime(route.lastRef, route.lastRefRaw)
		}

		vaddr, err := netip.ParseAddr(route.virtualAddress)
		if err != nil {
			// dev tap: the routing table holds MAC addresses ("02:00:5e:10:00:01"); the MAC is
			// reported only when OpenVPN knows no IP address of the client (no ifconfig-push)
			if s.VirtualAddress == "" {
				s.VirtualAddress = route.virtualAddress
			}
			continue
		}
		vaddr = vaddr.Unmap()

		// CLIENT_LIST virtual addresses win; the routing table is a fallback for older versions
		if vaddr.Is4() && s.VirtualAddress == "" {
			s.VirtualAddress = vaddr.String()
		}
		if vaddr.Is6() && s.VirtualAddressIPv6 == "" {
			s.VirtualAddressIPv6 = vaddr.String()
		}
	}

	return sessions
}

// matchMgmtSession finds the session of a routing table entry by CommonName+RealAddress
// (safe for duplicate-cn); falls back to CommonName when it is unambiguous.
func matchMgmtSession(sessions []clientStatus, commonName, realAddress string) int {
	candidate := -1
	count := 0
	for i := range sessions {
		if sessions[i].CommonName != commonName {
			continue
		}
		if sessions[i].RealAddress == realAddress {
			return i
		}
		candidate = i
		count++
	}
	if count == 1 {
		return candidate
	}
	return -1
}

// updateConnectionMetrics exports per-connection metrics. Metric names and labels are unchanged;
// ovpn_client_connection_info has one series per virtual address (IPv4 and IPv6).
func updateConnectionMetrics(clients []clientStatus) {
	bytesSent := map[string]float64{}
	bytesReceived := map[string]float64{}

	for _, c := range clients {
		ovpnClientConnectionFrom.WithLabelValues(c.CommonName, c.RealAddress).Set(float64(c.connectedSinceUnix))

		lastRef := c.lastRefUnix
		if lastRef == 0 {
			lastRef = c.connectedSinceUnix
		}
		for _, virtualAddress := range []string{c.VirtualAddress, c.VirtualAddressIPv6} {
			if virtualAddress != "" {
				ovpnClientConnectionInfo.WithLabelValues(c.CommonName, virtualAddress).Set(float64(lastRef))
			}
		}

		sent, _ := strconv.ParseFloat(c.BytesSent, 64)
		received, _ := strconv.ParseFloat(c.BytesReceived, 64)
		bytesSent[c.CommonName] += sent
		bytesReceived[c.CommonName] += received
	}

	for name, v := range bytesSent {
		ovpnClientBytesSent.WithLabelValues(name).Set(v)
	}
	for name, v := range bytesReceived {
		ovpnClientBytesReceived.WithLabelValues(name).Set(v)
	}
}

// Tunnel addresses of the OpenVPN servers by management alias, learned from "state" together
// with the client list. A server that is not reachable keeps its last known addresses.
var (
	ovpnServerAddrsMu sync.RWMutex
	ovpnServerAddrs   = map[string][]netip.Addr{}
)

// parseMgmtState returns the tun/tap addresses of a server from the output of the "state"
// management command, e.g. "1792037878,CONNECTED,SUCCESS,172.29.11.10,,,,,fd78:29:12::10":
// field 4 is the local IPv4 address, field 9 the local IPv6 address (both from the server
// config: ifconfig/server and ifconfig-ipv6/server-ipv6). ok is false unless the server is CONNECTED.
func parseMgmtState(out string) (addrs []netip.Addr, ok bool) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(strings.TrimRight(line, "\r"), ",")
		if len(fields) < 4 || fields[1] != "CONNECTED" {
			continue
		}
		ok = true
		for _, i := range []int{3, 8} {
			if i < len(fields) {
				if addr, err := netip.ParseAddr(fields[i]); err == nil {
					addrs = append(addrs, addr.Unmap())
				}
			}
		}
	}
	return addrs, ok
}

func setOvpnServerAddrs(server string, addrs []netip.Addr) {
	ovpnServerAddrsMu.Lock()
	defer ovpnServerAddrsMu.Unlock()
	ovpnServerAddrs[server] = addrs
}

// lookupOvpnServerAddr returns the server that uses addr (or "") and whether an address of
// the same family is known for any server.
func lookupOvpnServerAddr(addr netip.Addr) (server string, familyKnown bool) {
	ovpnServerAddrsMu.RLock()
	defer ovpnServerAddrsMu.RUnlock()
	for _, srv := range slices.Sorted(maps.Keys(ovpnServerAddrs)) {
		for _, a := range ovpnServerAddrs[srv] {
			if a.Is4() != addr.Is4() {
				continue
			}
			familyKnown = true
			if a == addr && server == "" {
				server = srv
			}
		}
	}
	return server, familyKnown
}

func (oAdmin *OvpnAdmin) mgmtGetActiveClients() []clientStatus {
	var activeClients []clientStatus

	for _, srv := range slices.Sorted(maps.Keys(oAdmin.mgmtInterfaces)) {
		addr := oAdmin.mgmtInterfaces[srv]
		out, err := mgmtCommand(addr, "status 3", isMgmtEnd)
		if err != nil {
			log.Warnf("openvpn mgmt interface for %s is not reachable by addr %s: %v", srv, addr, err)
			continue
		}
		log.Trace(out)
		activeClients = append(activeClients, parseMgmtStatus(out, srv)...)

		state, err := mgmtCommand(addr, "state", isMgmtEnd)
		if err != nil {
			log.Warnf("openvpn mgmt interface for %s: state: %v", srv, err)
			continue
		}
		if serverAddrs, ok := parseMgmtState(state); ok {
			setOvpnServerAddrs(srv, serverAddrs)
		}
	}

	updateConnectionMetrics(activeClients)

	return activeClients
}

func (oAdmin *OvpnAdmin) mgmtKillUserConnection(username, serverName string) {
	addr, ok := oAdmin.mgmtInterfaces[serverName]
	if !ok {
		log.Errorf("openvpn mgmt interface for %s is not configured", serverName)
		return
	}
	if strings.ContainsAny(username, "\r\n") {
		log.Errorf("refusing to kill session of invalid user %q", username)
		return
	}

	out, err := mgmtCommand(addr, "kill "+username, isMgmtResult)
	if err != nil {
		log.Errorf("openvpn mgmt interface for %s is not reachable by addr %s: %v", serverName, addr, err)
		return
	}
	log.Debugf("mgmt kill %s on %s: %s", username, serverName, strings.TrimSpace(out))
}

// parseMgmtVersion extracts "2.6.12" from the output of the "version" command.
func parseMgmtVersion(out string) string {
	const marker = "OpenVPN Version:"
	for _, line := range strings.Split(out, "\n") {
		i := strings.Index(line, marker)
		if i < 0 {
			continue
		}
		fields := strings.Fields(line[i+len(marker):])
		if len(fields) >= 2 && fields[0] == "OpenVPN" {
			return fields[1]
		}
		if len(fields) >= 1 {
			return fields[0]
		}
	}
	return ""
}

// mgmtCheckVersions waits for the management interfaces to become available at
// startup and warns when servers run different OpenVPN versions.
func (oAdmin *OvpnAdmin) mgmtCheckVersions() {
	type serverVersion struct {
		name    string
		version string
	}

	var serverVersions []serverVersion

	for _, srv := range slices.Sorted(maps.Keys(oAdmin.mgmtInterfaces)) {
		addr := oAdmin.mgmtInterfaces[srv]

		var out string
		var err error
		for attempt := 1; attempt <= mgmtStartupAttempts; attempt++ {
			out, err = mgmtCommand(addr, "version", isMgmtEnd)
			if err == nil {
				log.Debugf("mgmtCheckVersions: successful connection to %s/%s", srv, addr)
				break
			}
			log.Warnf("mgmtCheckVersions: openvpn mgmt interface for %s is not reachable by addr %s: %v", srv, addr, err)
			if attempt < mgmtStartupAttempts {
				time.Sleep(mgmtStartupDelay)
			}
		}
		if err != nil {
			continue
		}

		log.Trace(out)

		if v := parseMgmtVersion(out); v != "" {
			serverVersions = append(serverVersions, serverVersion{srv, v})
		}
	}

	if len(serverVersions) == 0 {
		return
	}

	for _, v := range serverVersions[1:] {
		if v.version != serverVersions[0].version {
			log.Warn("mgmtCheckVersions: servers have different versions of openvpn")
			for _, sv := range serverVersions {
				log.Infof("server name: %s, version: %s", sv.name, sv.version)
			}
			return
		}
	}
}

func isUserConnected(username string, connectedUsers []clientStatus) (bool, []string) {
	var connections []string
	var connected = false

	for _, connectedUser := range connectedUsers {
		if connectedUser.CommonName == username {
			connected = true
			connections = append(connections, connectedUser.ConnectedTo)
		}
	}
	return connected, connections
}
