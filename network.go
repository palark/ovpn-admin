package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

type OpenvpnServer struct {
	Host     string
	Port     string
	Protocol string
}

// Values parsed once at startup by initNetworkConfig. They are used everywhere
// instead of the raw flag strings.
var (
	// ovpnNetworkV4 is the IPv4 client pool (--ovpn.network), always masked.
	ovpnNetworkV4 netip.Prefix
	// ovpnNetworkV6 is the IPv6 client pool (--ovpn.network.ipv6), always masked.
	// The zero value (IsValid() == false) means IPv6 is disabled.
	ovpnNetworkV6 netip.Prefix
	// ovpnServers is the parsed --ovpn.server list.
	ovpnServers []OpenvpnServer
)

// openvpnServerProtocols is the whitelist of protocols accepted in --ovpn.server
var openvpnServerProtocols = map[string]bool{
	"udp":         true,
	"udp4":        true,
	"udp6":        true,
	"tcp":         true,
	"tcp4":        true,
	"tcp6":        true,
	"tcp-client":  true,
	"tcp4-client": true,
	"tcp6-client": true,
}

var hostnameRegexp = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)

// initNetworkConfig parses --ovpn.network, --ovpn.network.ipv6 and --ovpn.server
// and stores the results in package-level variables.
func initNetworkConfig() error {
	v4, err := parseOvpnNetworkV4(*openvpnNetwork)
	if err != nil {
		return fmt.Errorf("--ovpn.network: %w", err)
	}

	v6, err := parseOvpnNetworkV6(*openvpnNetworkIPv6)
	if err != nil {
		return fmt.Errorf("--ovpn.network.ipv6: %w", err)
	}

	servers, err := parseOvpnServers(*openvpnServer)
	if err != nil {
		return fmt.Errorf("--ovpn.server: %w", err)
	}

	ovpnNetworkV4 = v4
	ovpnNetworkV6 = v6
	ovpnServers = servers

	log.Infof("OpenVPN IPv4 network: %s", ovpnNetworkV4)
	if ovpnNetworkV6.IsValid() {
		log.Infof("OpenVPN IPv6 network: %s", ovpnNetworkV6)
	}

	return nil
}

// parseOvpnNetworkV4 parses an IPv4 pool given as "A.B.C.D/24" or "A.B.C.D/255.255.255.0".
func parseOvpnNetworkV4(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	addrStr, maskStr, ok := strings.Cut(s, "/")
	if !ok {
		return netip.Prefix{}, fmt.Errorf("%q must be in NETWORK/PREFIX or NETWORK/NETMASK form, e.g. 172.16.100.0/24", s)
	}

	addr, err := netip.ParseAddr(addrStr)
	if err != nil || !addr.Is4() {
		return netip.Prefix{}, fmt.Errorf("%q is not an IPv4 network", s)
	}

	bits, err := parseIPv4Netmask(maskStr)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q: %w", s, err)
	}
	if bits < 1 || bits > 30 {
		return netip.Prefix{}, fmt.Errorf("%q: prefix length must be between 1 and 30", s)
	}

	prefix := netip.PrefixFrom(addr, bits)
	masked := prefix.Masked()
	if masked.Addr() != addr {
		log.Warnf("OpenVPN network %s has host bits set, using %s", s, masked)
	}

	return masked, nil
}

// parseOvpnNetworkV6 parses an IPv6 pool (OpenVPN server-ipv6). An empty string disables IPv6.
func parseOvpnNetworkV6(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, nil
	}

	prefix, err := netip.ParsePrefix(s)
	if err != nil || !prefix.Addr().Is6() || prefix.Addr().Is4In6() {
		return netip.Prefix{}, fmt.Errorf("%q is not an IPv6 prefix, e.g. fd00:16:100::/64", s)
	}
	if prefix.Bits() < 64 || prefix.Bits() > 124 {
		return netip.Prefix{}, fmt.Errorf("%q: prefix length must be between 64 and 124", s)
	}

	masked := prefix.Masked()
	if masked.Addr() != prefix.Addr() {
		log.Warnf("OpenVPN IPv6 network %s has host bits set, using %s", s, masked)
	}

	return masked, nil
}

// parseIPv4Netmask accepts a dotted contiguous netmask ("255.255.255.0") or a
// prefix length ("24") and returns the prefix length.
func parseIPv4Netmask(mask string) (int, error) {
	mask = strings.TrimSpace(mask)
	if mask == "" {
		return 0, fmt.Errorf("netmask is empty")
	}

	if isDecimal(mask) {
		bits, err := strconv.Atoi(mask)
		if err != nil || bits < 0 || bits > 32 {
			return 0, fmt.Errorf("prefix length %q must be between 0 and 32", mask)
		}
		return bits, nil
	}

	addr, err := netip.ParseAddr(mask)
	if err != nil || !addr.Is4() {
		return 0, fmt.Errorf("netmask %q is not a valid IPv4 netmask", mask)
	}
	b := addr.As4()
	ones, size := net.IPMask(b[:]).Size()
	if size == 0 {
		return 0, fmt.Errorf("netmask %q is not contiguous", mask)
	}

	return ones, nil
}

// parseIPv6PrefixLen accepts "64" (or "/64") and returns the prefix length 0..128.
func parseIPv6PrefixLen(s string) (int, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "/")
	if !isDecimal(s) {
		return 0, fmt.Errorf("prefix length %q must be a number between 0 and 128", s)
	}
	bits, err := strconv.Atoi(s)
	if err != nil || bits < 0 || bits > 128 {
		return 0, fmt.Errorf("prefix length %q must be a number between 0 and 128", s)
	}
	return bits, nil
}

func isDecimal(s string) bool {
	if s == "" || len(s) > 3 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ipv4Netmask returns the dotted netmask for an IPv4 prefix length.
func ipv4Netmask(bits int) string {
	return net.IP(net.CIDRMask(bits, 32)).String()
}

// ipv4Broadcast returns the broadcast address of an IPv4 prefix.
func ipv4Broadcast(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	n := binary.BigEndian.Uint32(a[:]) | (uint32(1)<<(32-p.Bits()) - 1)
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], n)
	return netip.AddrFrom4(out)
}

// serverAddress returns the address OpenVPN assigns to itself in a pool (network+1).
func serverAddress(p netip.Prefix) netip.Addr {
	return p.Masked().Addr().Next()
}

// parseOvpnServers parses all --ovpn.server values.
func parseOvpnServers(values []string) ([]OpenvpnServer, error) {
	servers := make([]OpenvpnServer, 0, len(values))
	for _, v := range values {
		server, err := parseOvpnServer(v)
		if err != nil {
			return nil, err
		}
		servers = append(servers, server)
	}
	return servers, nil
}

// parseOvpnServer parses "HOST:PORT:PROTOCOL". IPv6 literal hosts must be
// bracketed ("[2001:db8::1]:1194:udp"); the host is returned without brackets.
func parseOvpnServer(s string) (OpenvpnServer, error) {
	orig := s
	s = strings.TrimSpace(s)

	var host, rest string
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return OpenvpnServer{}, fmt.Errorf("%q: missing closing bracket", orig)
		}
		host = s[1:end]
		var ok bool
		rest, ok = strings.CutPrefix(s[end+1:], ":")
		if !ok {
			return OpenvpnServer{}, fmt.Errorf("%q must be in HOST:PORT:PROTOCOL form", orig)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is6() {
			return OpenvpnServer{}, fmt.Errorf("%q: brackets must enclose an IPv6 address", orig)
		}
		host = addr.String()
	} else {
		if strings.Count(s, ":") > 2 {
			if _, err := netip.ParseAddr(s); err == nil || looksLikeUnbracketedIPv6(s) {
				return OpenvpnServer{}, fmt.Errorf("%q: IPv6 addresses must be enclosed in brackets, e.g. [2001:db8::1]:1194:udp", orig)
			}
			return OpenvpnServer{}, fmt.Errorf("%q must be in HOST:PORT:PROTOCOL form", orig)
		}
		var ok bool
		host, rest, ok = strings.Cut(s, ":")
		if !ok {
			return OpenvpnServer{}, fmt.Errorf("%q must be in HOST:PORT:PROTOCOL form", orig)
		}
		if host == "" || len(host) > 253 || !hostnameRegexp.MatchString(host) {
			return OpenvpnServer{}, fmt.Errorf("%q: invalid host %q", orig, host)
		}
	}

	port, protocol, ok := strings.Cut(rest, ":")
	if !ok || strings.Contains(protocol, ":") {
		return OpenvpnServer{}, fmt.Errorf("%q must be in HOST:PORT:PROTOCOL form", orig)
	}

	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNum == 0 {
		return OpenvpnServer{}, fmt.Errorf("%q: invalid port %q", orig, port)
	}

	protocol = strings.ToLower(protocol)
	if !openvpnServerProtocols[protocol] {
		return OpenvpnServer{}, fmt.Errorf("%q: unsupported protocol %q (allowed: udp, udp4, udp6, tcp, tcp4, tcp6, tcp-client, tcp4-client, tcp6-client)", orig, protocol)
	}

	return OpenvpnServer{Host: host, Port: strconv.FormatUint(portNum, 10), Protocol: protocol}, nil
}

// looksLikeUnbracketedIPv6 reports whether "2001:db8::1:1194:udp" starts with an IPv6 literal.
func looksLikeUnbracketedIPv6(s string) bool {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return false
	}
	j := strings.LastIndex(s[:i], ":")
	if j < 0 {
		return false
	}
	_, err := netip.ParseAddr(s[:j])
	return err == nil
}

// trimBrackets removes optional brackets around an IPv6 literal ("[::1]" -> "::1").
func trimBrackets(host string) string {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host[1 : len(host)-1]
	}
	return host
}

// listenAddress builds the address for http.ListenAndServe. An empty host
// listens on all interfaces (IPv4 and IPv6).
func listenAddress(host, port string) string {
	return net.JoinHostPort(trimBrackets(host), port)
}

// bindURL builds a printable URL for the listen address.
func bindURL(host, port, baseURL string) string {
	h := trimBrackets(host)
	if h == "" {
		h = "::"
	}
	return "http://" + net.JoinHostPort(h, port) + baseURL
}
