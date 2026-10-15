package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"unicode"

	log "github.com/sirupsen/logrus"
)

const ccdDynamicAddress = "dynamic"

type ccdRoute struct {
	Address     string `json:"Address"`
	Mask        string `json:"Mask"`
	Description string `json:"Description"`
}

// IsIPv6 reports whether the route is an IPv6 route (rendered as route-ipv6).
// The family is decided by Address.
func (r ccdRoute) IsIPv6() bool {
	return strings.Contains(r.Address, ":")
}

type Ccd struct {
	User              string     `json:"User"`
	ClientAddress     string     `json:"ClientAddress"`
	ClientAddressIPv6 string     `json:"ClientAddressIPv6"`
	CustomRoutes      []ccdRoute `json:"CustomRoutes"`
}

// ccdTemplateData is passed to ccd.tpl. It embeds Ccd so custom templates
// using .ClientAddress/.CustomRoutes keep working.
type ccdTemplateData struct {
	Ccd
	// Netmask is the dotted netmask of --ovpn.network
	Netmask string
	// IPv6PrefixLen is the prefix length of --ovpn.network.ipv6 (0 when IPv6 is disabled)
	IPv6PrefixLen int
}

// userNotFoundError is returned when a username is syntactically valid but does not exist
type userNotFoundError struct {
	username string
}

func (e userNotFoundError) Error() string {
	return fmt.Sprintf("User \"%s\" not found", e.username)
}

// ccdMutex serializes ccd modifications so concurrent requests cannot assign the same static address
var ccdMutex sync.Mutex

// checkCcdUser makes sure username is safe to use as a file name and exists.
func checkCcdUser(username string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	if !checkUserExist(username) {
		return userNotFoundError{username: username}
	}
	return nil
}

func getCcdTemplate() (*template.Template, error) {
	if *ccdTemplatePath != "" {
		return template.ParseFiles(*ccdTemplatePath)
	}
	ccdTplBytes, err := templateFiles.ReadFile("templates/ccd.tpl")
	if err != nil {
		return nil, fmt.Errorf("ccdTpl not found in embedded templates: %w", err)
	}
	return template.New("ccd").Parse(string(ccdTplBytes))
}

// renderCcd renders a validated ccd with ccd.tpl
func renderCcd(ccd Ccd) (string, error) {
	t, err := getCcdTemplate()
	if err != nil {
		return "", err
	}

	data := ccdTemplateData{Ccd: ccd}
	if ovpnNetworkV4.IsValid() {
		data.Netmask = ipv4Netmask(ovpnNetworkV4.Bits())
	}
	if ovpnNetworkV6.IsValid() {
		data.IPv6PrefixLen = ovpnNetworkV6.Bits()
	}

	var out bytes.Buffer
	if err := t.Execute(&out, data); err != nil {
		return "", err
	}
	return out.String(), nil
}

// readCcdText returns the raw ccd of a user; username must be validated by the caller.
func readCcdText(username string) string {
	if *storageBackend == "kubernetes.secrets" {
		return app.secretGetCcd(username)
	}
	path := filepath.Join(*ccdDir, username)
	if fExist(path) {
		return fRead(path)
	}
	return ""
}

func (oAdmin *OvpnAdmin) getCcd(username string) (Ccd, error) {
	if err := checkCcdUser(username); err != nil {
		return Ccd{}, err
	}
	return parseCcdText(username, readCcdText(username)), nil
}

func (oAdmin *OvpnAdmin) modifyCcd(ccd Ccd) (bool, string) {
	ccdMutex.Lock()
	defer ccdMutex.Unlock()

	normalized, err := validateCcd(ccd)
	if err != nil {
		log.Debugf("modify ccd for user %q: %s", ccd.User, err)
		return false, err.Error()
	}

	text, err := renderCcd(normalized)
	if err != nil {
		log.Errorf("modifyCcd: render ccd for user %s: %v", normalized.User, err)
		return false, "failed to render ccd"
	}

	if *storageBackend == "kubernetes.secrets" {
		if err := app.secretUpdateCcd(normalized.User, []byte(text)); err != nil {
			log.Errorf("modifyCcd: %v", err)
			return false, "failed to write ccd"
		}
	} else {
		if err := os.MkdirAll(*ccdDir, 0755); err != nil {
			log.Errorf("modifyCcd: create ccd dir: %v", err)
			return false, "failed to write ccd"
		}
		if err := fWrite(filepath.Join(*ccdDir, normalized.User), text); err != nil {
			log.Errorf("modifyCcd: fWrite(): %v", err)
			return false, "failed to write ccd"
		}
	}

	return true, "ccd updated successfully"
}

// parseCcdText parses a ccd file. It understands ifconfig-push, ifconfig-ipv6-push,
// push "route ..." and push "route-ipv6 ..." and ignores everything else.
func parseCcdText(username, text string) Ccd {
	ccd := Ccd{
		User:              username,
		ClientAddress:     ccdDynamicAddress,
		ClientAddressIPv6: ccdDynamicAddress,
		CustomRoutes:      []ccdRoute{},
	}

	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		switch fields[0] {
		case "ifconfig-push":
			if len(fields) >= 2 {
				ccd.ClientAddress = fields[1]
			}
		case "ifconfig-ipv6-push":
			if len(fields) >= 2 {
				addr, _, _ := strings.Cut(fields[1], "/")
				ccd.ClientAddressIPv6 = addr
			}
		case "push":
			if route, ok := parseCcdPushRoute(line); ok {
				ccd.CustomRoutes = append(ccd.CustomRoutes, route)
			}
		}
	}

	return ccd
}

// parseCcdPushRoute parses `push "route ADDR MASK" # description` and
// `push "route-ipv6 ADDR/BITS" # description` lines.
func parseCcdPushRoute(line string) (ccdRoute, bool) {
	start := strings.IndexAny(line, `"'`)
	if start < 0 {
		return ccdRoute{}, false
	}
	quote := line[start]
	length := strings.IndexByte(line[start+1:], quote)
	if length < 0 {
		return ccdRoute{}, false
	}
	inner := strings.Fields(line[start+1 : start+1+length])
	tail := strings.TrimSpace(line[start+1+length+1:])

	description := ""
	if strings.HasPrefix(tail, "#") || strings.HasPrefix(tail, ";") {
		description = strings.TrimSpace(tail[1:])
	}

	if len(inner) < 2 {
		return ccdRoute{}, false
	}

	switch inner[0] {
	case "route":
		mask := "255.255.255.255"
		if len(inner) >= 3 {
			mask = inner[2]
		}
		return ccdRoute{Address: inner[1], Mask: mask, Description: description}, true
	case "route-ipv6":
		addr, bits, ok := strings.Cut(inner[1], "/")
		if !ok {
			bits = "128"
		}
		return ccdRoute{Address: addr, Mask: bits, Description: description}, true
	}

	return ccdRoute{}, false
}

// validateCcd checks a ccd received from the API and returns its normalized form.
// Syntax and range checks go first, uniqueness of static addresses is checked last.
func validateCcd(ccd Ccd) (Ccd, error) {
	if err := checkCcdUser(ccd.User); err != nil {
		return Ccd{}, err
	}

	out := Ccd{User: ccd.User, CustomRoutes: []ccdRoute{}}

	var staticAddrs []netip.Addr

	v4, err := normalizeClientAddressIPv4(ccd.ClientAddress)
	if err != nil {
		return Ccd{}, err
	}
	out.ClientAddress = ccdDynamicAddress
	if v4.IsValid() {
		out.ClientAddress = v4.String()
		staticAddrs = append(staticAddrs, v4)
	}

	v6, err := normalizeClientAddressIPv6(ccd.ClientAddressIPv6)
	if err != nil {
		return Ccd{}, err
	}
	out.ClientAddressIPv6 = ccdDynamicAddress
	if v6.IsValid() {
		out.ClientAddressIPv6 = v6.String()
		staticAddrs = append(staticAddrs, v6)
	}

	for _, route := range ccd.CustomRoutes {
		normalized, err := normalizeCcdRoute(route)
		if err != nil {
			return Ccd{}, err
		}
		out.CustomRoutes = append(out.CustomRoutes, normalized)
	}

	if len(staticAddrs) > 0 {
		inUse, err := staticAddressesInUse(ccd.User)
		if err != nil {
			log.Errorf("checking static addresses for user %s: %v", ccd.User, err)
			return Ccd{}, errors.New("cannot verify that the static address is not assigned to another user")
		}
		for _, addr := range staticAddrs {
			if owner, taken := inUse[canonicalAddr(addr)]; taken {
				log.Warnf("IP %s already assigned to user %s", addr, owner)
				field := "ClientAddress"
				if addr.Is6() {
					field = "ClientAddressIPv6"
				}
				return Ccd{}, fmt.Errorf("%s \"%s\" already assigned to another user", field, addr)
			}
		}
	}

	return out, nil
}

func isDynamicAddress(s string) bool {
	return s == "" || strings.EqualFold(s, ccdDynamicAddress)
}

// normalizeClientAddressIPv4 returns the zero Addr for "dynamic".
func normalizeClientAddressIPv4(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if isDynamicAddress(s) {
		return netip.Addr{}, nil
	}

	if !ovpnNetworkV4.IsValid() {
		return netip.Addr{}, errors.New("OpenVPN IPv4 network (--ovpn.network) is not configured")
	}

	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("ClientAddress \"%s\" is not a valid IPv4 address", s)
	}

	network := ovpnNetworkV4
	switch {
	case !network.Contains(addr):
		return netip.Addr{}, fmt.Errorf("ClientAddress \"%s\" does not belong to the OpenVPN network %s", s, network)
	case addr == network.Addr():
		return netip.Addr{}, fmt.Errorf("ClientAddress \"%s\" is the network address of %s", s, network)
	case addr == ipv4Broadcast(network):
		return netip.Addr{}, fmt.Errorf("ClientAddress \"%s\" is the broadcast address of %s", s, network)
	case addr == serverAddress(network):
		return netip.Addr{}, fmt.Errorf("ClientAddress \"%s\" is reserved for the OpenVPN server", s)
	}

	return addr, nil
}

// normalizeClientAddressIPv6 returns the zero Addr for "dynamic".
func normalizeClientAddressIPv6(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if isDynamicAddress(s) {
		return netip.Addr{}, nil
	}

	if !ovpnNetworkV6.IsValid() {
		return netip.Addr{}, fmt.Errorf("ClientAddressIPv6 \"%s\": IPv6 is not enabled on this server (--ovpn.network.ipv6 is not set)", s)
	}

	network := ovpnNetworkV6

	addrStr, bitsStr, hasBits := strings.Cut(s, "/")
	if hasBits {
		bits, err := parseIPv6PrefixLen(bitsStr)
		if err != nil || bits != network.Bits() {
			return netip.Addr{}, fmt.Errorf("ClientAddressIPv6 \"%s\": prefix length must be omitted or equal to /%d", s, network.Bits())
		}
	}

	addr, err := netip.ParseAddr(addrStr)
	if err != nil || !addr.Is6() || addr.Is4In6() || addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("ClientAddressIPv6 \"%s\" is not a valid IPv6 address", s)
	}

	switch {
	case !network.Contains(addr):
		return netip.Addr{}, fmt.Errorf("ClientAddressIPv6 \"%s\" does not belong to the OpenVPN IPv6 network %s", s, network)
	case addr == network.Addr():
		return netip.Addr{}, fmt.Errorf("ClientAddressIPv6 \"%s\" is the network address of %s", s, network)
	case addr == serverAddress(network):
		return netip.Addr{}, fmt.Errorf("ClientAddressIPv6 \"%s\" is reserved for the OpenVPN server", s)
	}

	return addr, nil
}

// normalizeCcdRoute validates a route and converts it to canonical form:
// IPv4 -> dotted netmask, IPv6 -> prefix length; "fd00:1::/64" with an empty Mask
// becomes Address "fd00:1::", Mask "64".
func normalizeCcdRoute(route ccdRoute) (ccdRoute, error) {
	addrStr := strings.TrimSpace(route.Address)
	maskStr := strings.TrimSpace(route.Mask)
	description := strings.TrimSpace(route.Description)

	if strings.IndexFunc(description, unicode.IsControl) >= 0 {
		return ccdRoute{}, fmt.Errorf("CustomRoute.Description for \"%s\" must not contain line breaks or control characters", addrStr)
	}

	var addr netip.Addr
	cidrBits := -1
	if strings.Contains(addrStr, "/") {
		prefix, err := netip.ParsePrefix(addrStr)
		if err != nil {
			return ccdRoute{}, fmt.Errorf("CustomRoute.Address \"%s\" must be a valid IP address or network in CIDR notation", addrStr)
		}
		addr = prefix.Addr()
		cidrBits = prefix.Bits()
	} else {
		var err error
		addr, err = netip.ParseAddr(addrStr)
		if err != nil {
			return ccdRoute{}, fmt.Errorf("CustomRoute.Address \"%s\" must be a valid IP address", addrStr)
		}
	}
	if addr.Zone() != "" {
		return ccdRoute{}, fmt.Errorf("CustomRoute.Address \"%s\" must not contain a zone", addrStr)
	}

	var bits int
	if addr.Is4() {
		if maskStr != "" {
			b, err := parseIPv4Netmask(maskStr)
			if err != nil {
				return ccdRoute{}, fmt.Errorf("CustomRoute.Mask \"%s\" must be a valid IPv4 netmask, e.g. 255.255.255.0", maskStr)
			}
			if cidrBits >= 0 && b != cidrBits {
				return ccdRoute{}, fmt.Errorf("CustomRoute.Mask \"%s\" conflicts with the prefix length in Address \"%s\"", maskStr, addrStr)
			}
			bits = b
		} else if cidrBits >= 0 {
			bits = cidrBits
		} else {
			return ccdRoute{}, fmt.Errorf("CustomRoute.Mask for \"%s\" must be a valid IPv4 netmask, e.g. 255.255.255.0", addrStr)
		}
	} else {
		if maskStr != "" {
			b, err := parseIPv6PrefixLen(maskStr)
			if err != nil {
				return ccdRoute{}, fmt.Errorf("CustomRoute.Mask \"%s\" must be an IPv6 prefix length between 0 and 128", maskStr)
			}
			if cidrBits >= 0 && b != cidrBits {
				return ccdRoute{}, fmt.Errorf("CustomRoute.Mask \"%s\" conflicts with the prefix length in Address \"%s\"", maskStr, addrStr)
			}
			bits = b
		} else if cidrBits >= 0 {
			bits = cidrBits
		} else {
			return ccdRoute{}, fmt.Errorf("CustomRoute.Mask for \"%s\" must be an IPv6 prefix length between 0 and 128", addrStr)
		}
	}

	network := netip.PrefixFrom(addr, bits).Masked()
	if network.Addr() != addr {
		return ccdRoute{}, fmt.Errorf("CustomRoute.Address \"%s\" has host bits set for prefix length /%d (did you mean %s?)", addr, bits, network.Addr())
	}

	if addr.Is4() {
		return ccdRoute{Address: addr.String(), Mask: ipv4Netmask(bits), Description: description}, nil
	}
	return ccdRoute{Address: addr.String(), Mask: strconv.Itoa(bits), Description: description}, nil
}

// canonicalAddr makes addresses comparable regardless of their textual form.
func canonicalAddr(addr netip.Addr) netip.Addr {
	return addr.Unmap().WithZone("")
}

// checkStaticAddressIsFree reports whether staticAddress (IPv4 or IPv6) is not
// assigned statically to any user other than username.
func checkStaticAddressIsFree(staticAddress string, username string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(staticAddress))
	if err != nil {
		return false
	}

	inUse, err := staticAddressesInUse(username)
	if err != nil {
		log.Error(err)
		return false
	}

	if owner, taken := inUse[canonicalAddr(addr)]; taken {
		log.Warnf("IP %s already assigned to user %s", staticAddress, owner)
		return false
	}
	return true
}

// staticAddressesInUse returns the static client addresses of both families
// assigned to users other than username, mapped to their owner.
func staticAddressesInUse(username string) (map[netip.Addr]string, error) {
	inUse := map[netip.Addr]string{}

	add := func(ccd Ccd) {
		for _, s := range []string{ccd.ClientAddress, ccd.ClientAddressIPv6} {
			if isDynamicAddress(s) {
				continue
			}
			if addr, err := netip.ParseAddr(s); err == nil {
				inUse[canonicalAddr(addr)] = ccd.User
			}
		}
	}

	if *storageBackend == "kubernetes.secrets" {
		if app.KubeClient == nil {
			return nil, errors.New("kubernetes client is not initialized")
		}

		// the same secrets updateCcdOnDisk writes to the ccd dir of OpenVPN
		labelSelector := fmt.Sprintf("%s=,%s=%s", labelKeyIndexTxt, labelKeyType, labelValueClientAuth)

		secrets, err := app.secretsGetByLabels(labelSelector)
		if err != nil {
			return nil, err
		}

		for _, secret := range secrets.Items {
			otherUser := secret.Labels[labelKeyName]
			// rotated and deleted certificates keep a copy of the ccd
			if otherUser == username || secret.Labels["revokedForever"] == "true" {
				continue
			}
			dataCCD, ok := secret.Data["ccd"]
			if !ok || len(dataCCD) == 0 {
				continue
			}
			add(parseCcdText(otherUser, string(dataCCD)))
		}
		return inUse, nil
	}

	entries, err := os.ReadDir(*ccdDir)
	if errors.Is(err, fs.ErrNotExist) {
		return inUse, nil
	}
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.Name() == username || entry.IsDir() {
			continue
		}
		if !entry.Type().IsRegular() && entry.Type()&fs.ModeSymlink == 0 {
			continue
		}
		content, err := os.ReadFile(filepath.Join(*ccdDir, entry.Name()))
		if err != nil {
			log.Warnf("checking static addresses: %v", err)
			continue
		}
		add(parseCcdText(entry.Name(), string(content)))
	}

	return inUse, nil
}
