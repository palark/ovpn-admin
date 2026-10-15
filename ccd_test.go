package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func setupCcdTest(t *testing.T, ipv6 bool) string {
	t.Helper()
	v6 := ""
	if ipv6 {
		v6 = "fd00:16:100::/64"
	}
	setNetworks(t, "172.16.100.0/24", v6)
	setupUsers(t, "alice", "bob", "dots.user")
	return setupCcdDir(t, map[string]string{
		"alice": "ifconfig-push 172.16.100.10 255.255.255.0\nifconfig-ipv6-push fd00:16:100::10/64\n",
		"bob":   "ifconfig-push 172.16.100.20 255.255.255.0\nifconfig-ipv6-push fd00:16:100::20/64\n",
	})
}

func TestCcdJSONBackwardCompatible(t *testing.T) {
	var ccd Ccd
	if err := json.Unmarshal([]byte(`{"User":"alice","ClientAddress":"dynamic","CustomRoutes":[{"Address":"10.1.0.0","Mask":"255.255.0.0","Description":"lan"}]}`), &ccd); err != nil {
		t.Fatal(err)
	}
	if ccd.ClientAddressIPv6 != "" || len(ccd.CustomRoutes) != 1 {
		t.Fatalf("unexpected ccd: %+v", ccd)
	}

	out, err := json.Marshal(Ccd{User: "alice", ClientAddress: "dynamic", ClientAddressIPv6: "fd00:16:100::10", CustomRoutes: []ccdRoute{}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"User":"alice","ClientAddress":"dynamic","ClientAddressIPv6":"fd00:16:100::10","CustomRoutes":[]}`
	if string(out) != want {
		t.Errorf("json = %s, want %s", out, want)
	}
}

func TestValidateCcdOK(t *testing.T) {
	setupCcdTest(t, true)

	tests := []struct {
		name string
		in   Ccd
		want Ccd
	}{
		{
			name: "dynamic",
			in:   Ccd{User: "alice", ClientAddress: "dynamic", ClientAddressIPv6: "dynamic"},
			want: Ccd{User: "alice", ClientAddress: "dynamic", ClientAddressIPv6: "dynamic", CustomRoutes: []ccdRoute{}},
		},
		{
			name: "missing addresses mean dynamic",
			in:   Ccd{User: "alice"},
			want: Ccd{User: "alice", ClientAddress: "dynamic", ClientAddressIPv6: "dynamic", CustomRoutes: []ccdRoute{}},
		},
		{
			name: "own static addresses are not a conflict",
			in:   Ccd{User: "alice", ClientAddress: " 172.16.100.10 ", ClientAddressIPv6: "fd00:16:100:0::10"},
			want: Ccd{User: "alice", ClientAddress: "172.16.100.10", ClientAddressIPv6: "fd00:16:100::10", CustomRoutes: []ccdRoute{}},
		},
		{
			name: "static addresses with prefix length",
			in:   Ccd{User: "dots.user", ClientAddress: "172.16.100.254", ClientAddressIPv6: "fd00:16:100::ffff/64"},
			want: Ccd{User: "dots.user", ClientAddress: "172.16.100.254", ClientAddressIPv6: "fd00:16:100::ffff", CustomRoutes: []ccdRoute{}},
		},
		{
			name: "routes",
			in: Ccd{User: "alice", ClientAddress: "dynamic", ClientAddressIPv6: "dynamic", CustomRoutes: []ccdRoute{
				{Address: "10.1.0.0", Mask: "255.255.0.0", Description: "lan"},
				{Address: "10.2.0.0", Mask: "16", Description: "  office lan 2  "},
				{Address: "10.3.0.0/24", Mask: "", Description: ""},
				{Address: "0.0.0.0", Mask: "0.0.0.0", Description: "default"},
				{Address: "fd00:1::", Mask: "64", Description: "lan6"},
				{Address: "fd00:2::/48", Mask: "", Description: "cidr"},
				{Address: "fd00:3::/56", Mask: "56", Description: "cidr and mask"},
				{Address: "FD00:4:0::", Mask: "/64", Description: ""},
				{Address: "2001:db8::5", Mask: "128", Description: "host"},
			}},
			want: Ccd{User: "alice", ClientAddress: "dynamic", ClientAddressIPv6: "dynamic", CustomRoutes: []ccdRoute{
				{Address: "10.1.0.0", Mask: "255.255.0.0", Description: "lan"},
				{Address: "10.2.0.0", Mask: "255.255.0.0", Description: "office lan 2"},
				{Address: "10.3.0.0", Mask: "255.255.255.0", Description: ""},
				{Address: "0.0.0.0", Mask: "0.0.0.0", Description: "default"},
				{Address: "fd00:1::", Mask: "64", Description: "lan6"},
				{Address: "fd00:2::", Mask: "48", Description: "cidr"},
				{Address: "fd00:3::", Mask: "56", Description: "cidr and mask"},
				{Address: "fd00:4::", Mask: "64", Description: ""},
				{Address: "2001:db8::5", Mask: "128", Description: "host"},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateCcd(tt.in)
			if err != nil {
				t.Fatalf("validateCcd() unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("validateCcd() =\n%+v\nwant\n%+v", got, tt.want)
			}
		})
	}
}

func TestValidateCcdErrors(t *testing.T) {
	setupCcdTest(t, true)

	route := func(addr, mask string) Ccd {
		return Ccd{User: "alice", CustomRoutes: []ccdRoute{{Address: addr, Mask: mask}}}
	}

	tests := []struct {
		name    string
		in      Ccd
		wantErr string
	}{
		{"path traversal", Ccd{User: "../../etc/passwd"}, "Username can only contains"},
		{"dot dot", Ccd{User: ".."}, "Username can only contains"},
		{"dot", Ccd{User: "."}, "Username can only contains"},
		{"slash", Ccd{User: "alice/../bob"}, "Username can only contains"},
		{"backslash", Ccd{User: `alice\bob`}, "Username can only contains"},
		{"empty user", Ccd{User: ""}, "Username can only contains"},
		{"unknown user", Ccd{User: "carol"}, `User "carol" not found`},

		{"v4 not an address", Ccd{User: "alice", ClientAddress: "abc"}, "not a valid IPv4 address"},
		{"v4 is ipv6", Ccd{User: "alice", ClientAddress: "fd00:16:100::5"}, "not a valid IPv4 address"},
		{"v4 out of network", Ccd{User: "alice", ClientAddress: "10.0.0.5"}, "does not belong to the OpenVPN network 172.16.100.0/24"},
		{"v4 network address", Ccd{User: "alice", ClientAddress: "172.16.100.0"}, "network address"},
		{"v4 broadcast address", Ccd{User: "alice", ClientAddress: "172.16.100.255"}, "broadcast address"},
		{"v4 server address", Ccd{User: "alice", ClientAddress: "172.16.100.1"}, "reserved for the OpenVPN server"},
		{"v4 taken", Ccd{User: "alice", ClientAddress: "172.16.100.20"}, `ClientAddress "172.16.100.20" already assigned to another user`},

		{"v6 not an address", Ccd{User: "alice", ClientAddressIPv6: "zzz"}, "not a valid IPv6 address"},
		{"v6 is ipv4", Ccd{User: "alice", ClientAddressIPv6: "172.16.100.5"}, "not a valid IPv6 address"},
		{"v6 out of network", Ccd{User: "alice", ClientAddressIPv6: "fd00:99::5"}, "does not belong to the OpenVPN IPv6 network fd00:16:100::/64"},
		{"v6 network address", Ccd{User: "alice", ClientAddressIPv6: "fd00:16:100::"}, "network address"},
		{"v6 server address", Ccd{User: "alice", ClientAddressIPv6: "fd00:16:100::1"}, "reserved for the OpenVPN server"},
		{"v6 wrong prefix length", Ccd{User: "alice", ClientAddressIPv6: "fd00:16:100::5/48"}, "prefix length"},
		{"v6 taken other form", Ccd{User: "alice", ClientAddressIPv6: "FD00:16:100:0:0:0:0:20"}, `ClientAddressIPv6 "fd00:16:100::20" already assigned to another user`},

		{"route bad address", route("300.1.1.1", "255.0.0.0"), "must be a valid IP address"},
		{"route bad cidr", route("10.0.0.0/33", ""), "CIDR"},
		{"route v4 host bits", route("10.1.2.3", "255.255.0.0"), "host bits set"},
		{"route v4 host bits cidr", route("10.1.2.3/16", ""), "did you mean 10.1.0.0?"},
		{"route v4 non contiguous mask", route("10.0.0.0", "255.0.255.0"), "valid IPv4 netmask"},
		{"route v4 bad mask", route("10.0.0.0", "255.255.255.256"), "valid IPv4 netmask"},
		{"route v4 prefix too long", route("10.0.0.0", "33"), "valid IPv4 netmask"},
		{"route v4 empty mask", route("10.0.0.0", ""), "valid IPv4 netmask"},
		{"route v4 conflicting mask", route("10.0.0.0/8", "255.255.0.0"), "conflicts"},
		{"route v6 host bits", route("fd00:1::1", "64"), "host bits set"},
		{"route v6 host bits cidr", route("fd00:1::1/64", ""), "did you mean fd00:1::?"},
		{"route v6 bad prefix", route("fd00:1::", "129"), "prefix length between 0 and 128"},
		{"route v6 dotted mask", route("fd00:1::", "255.255.0.0"), "prefix length between 0 and 128"},
		{"route v6 empty mask", route("fd00:1::", ""), "prefix length between 0 and 128"},
		{"route v6 conflicting mask", route("fd00:1::/64", "48"), "conflicts"},
		{"route v6 zone", route("fe80::%eth0", "64"), "zone"},
		{"route description newline", Ccd{User: "alice", CustomRoutes: []ccdRoute{{Address: "10.0.0.0", Mask: "255.0.0.0", Description: "lan\npush \"redirect-gateway def1\""}}}, "control characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateCcd(tt.in)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("validateCcd(%+v) error = %v, want error containing %q", tt.in, err, tt.wantErr)
			}
		})
	}
}

// setOvpnServerAddrsForTest replaces the server addresses learned from the management interfaces.
func setOvpnServerAddrsForTest(t *testing.T, addrs map[string][]string) {
	t.Helper()
	ovpnServerAddrsMu.Lock()
	old := ovpnServerAddrs
	ovpnServerAddrs = map[string][]netip.Addr{}
	for srv, list := range addrs {
		for _, a := range list {
			ovpnServerAddrs[srv] = append(ovpnServerAddrs[srv], netip.MustParseAddr(a))
		}
	}
	ovpnServerAddrsMu.Unlock()
	t.Cleanup(func() {
		ovpnServerAddrsMu.Lock()
		ovpnServerAddrs = old
		ovpnServerAddrsMu.Unlock()
	})
}

func TestValidateCcdServerAddress(t *testing.T) {
	setupCcdTest(t, true)

	v4 := func(a string) Ccd { return Ccd{User: "dots.user", ClientAddress: a} }
	v6 := func(a string) Ccd { return Ccd{User: "dots.user", ClientAddressIPv6: a} }
	tests := []struct {
		name    string
		servers map[string][]string
		in      Ccd
		wantErr string // "" = valid
	}{
		// a tap server with "ifconfig 172.16.100.50" and "ifconfig-ipv6 fd00:16:100::50/64"
		{"learned v4 address", map[string][]string{"main": {"172.16.100.50", "fd00:16:100::50"}}, v4("172.16.100.50"), `is the address of the OpenVPN server "main"`},
		{"network+1 is free when the address is known", map[string][]string{"main": {"172.16.100.50", "fd00:16:100::50"}}, v4("172.16.100.1"), ""},
		{"learned v6 address", map[string][]string{"main": {"172.16.100.50", "fd00:16:100::50"}}, v6("fd00:16:100:0::50"), `is the address of the OpenVPN server "main"`},
		{"v6 network+1 is free when the address is known", map[string][]string{"main": {"172.16.100.50", "fd00:16:100::50"}}, v6("fd00:16:100::1"), ""},
		{"second server", map[string][]string{"main": {"172.16.100.50"}, "backup": {"172.16.100.60"}}, v4("172.16.100.60"), `is the address of the OpenVPN server "backup"`},
		// nothing known for a family: network+1 is assumed
		{"v6 unknown falls back to network+1", map[string][]string{"main": {"172.16.100.50"}}, v6("fd00:16:100::1"), "is reserved for the OpenVPN server"},
		{"nothing learned", nil, v4("172.16.100.1"), "is reserved for the OpenVPN server"},
		{"nothing learned, other address", nil, v4("172.16.100.50"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setOvpnServerAddrsForTest(t, tt.servers)
			_, err := validateCcd(tt.in)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("validateCcd(%+v) = %v, want no error", tt.in, err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("validateCcd(%+v) error = %v, want error containing %q", tt.in, err, tt.wantErr)
			}
		})
	}
}

func TestValidateCcdSyntaxBeforeUniqueness(t *testing.T) {
	setupCcdTest(t, true)
	// the address is taken by bob, but the bad route must be reported first
	_, err := validateCcd(Ccd{User: "alice", ClientAddress: "172.16.100.20", CustomRoutes: []ccdRoute{{Address: "10.1.2.3", Mask: "255.255.0.0"}}})
	if err == nil || !strings.Contains(err.Error(), "host bits") {
		t.Errorf("validateCcd() error = %v, want host bits error", err)
	}
}

func TestValidateCcdIPv6Disabled(t *testing.T) {
	setupCcdTest(t, false)

	if _, err := validateCcd(Ccd{User: "alice", ClientAddressIPv6: "fd00:16:100::50"}); err == nil || !strings.Contains(err.Error(), "IPv6 is not enabled") {
		t.Errorf("validateCcd() error = %v, want IPv6 is not enabled", err)
	}

	// dynamic IPv6 and IPv6 routes are fine without an IPv6 pool
	got, err := validateCcd(Ccd{User: "alice", ClientAddressIPv6: "dynamic", CustomRoutes: []ccdRoute{{Address: "fd00:1::/64"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientAddressIPv6 != "dynamic" || got.CustomRoutes[0] != (ccdRoute{Address: "fd00:1::", Mask: "64"}) {
		t.Errorf("validateCcd() = %+v", got)
	}
}

func TestValidateCcdNetworkNotConfigured(t *testing.T) {
	setupCcdTest(t, false)
	ovpnNetworkV4 = netip.Prefix{} // not configured, must not panic (restored by setupCcdTest cleanup)

	if _, err := validateCcd(Ccd{User: "alice", ClientAddress: "172.16.100.5"}); err == nil {
		t.Error("validateCcd() without --ovpn.network: want error")
	}
}

func TestParseCcdText(t *testing.T) {
	text := strings.Join([]string{
		"ifconfig-push",
		"ifconfig-push 172.16.100.10 255.255.255.0",
		"ifconfig-ipv6-push fd00:16:100::10/64 fd00:16:100::1",
		"push",
		`push "route"`,
		`push "route 10.0.0.0 255.0.0.0" # my office lan`,
		`push "route-ipv6 fd00:1::/64"`,
		`push "dhcp-option DNS 1.1.1.1"`,
		`push "redirect-gateway def1 ipv6" # all traffic`,
		`push "route 192.168.1.0 255.255.255.0"`,
		"# comment line",
		"; another comment",
		`push "route-ipv6 2001:db8::5"   ;  host route`,
		`push "route 10.9.0.0 255.255.0.0" #`,
		"  push   \"route 10.8.0.0 255.255.0.0\"  #   spaced   desc  \r",
		`push 'route 10.7.0.0 255.255.0.0' # single quotes # with hash`,
		`push "route 10.6.0.0`,
		`push "route 10.5.0.1" # host`,
		"iroute 10.20.0.0 255.255.0.0",
		"",
	}, "\n")

	got := parseCcdText("alice", text)
	want := Ccd{
		User:              "alice",
		ClientAddress:     "172.16.100.10",
		ClientAddressIPv6: "fd00:16:100::10",
		CustomRoutes: []ccdRoute{
			{Address: "10.0.0.0", Mask: "255.0.0.0", Description: "my office lan"},
			{Address: "fd00:1::", Mask: "64", Description: ""},
			{Address: "192.168.1.0", Mask: "255.255.255.0", Description: ""},
			{Address: "2001:db8::5", Mask: "128", Description: "host route"},
			{Address: "10.9.0.0", Mask: "255.255.0.0", Description: ""},
			{Address: "10.8.0.0", Mask: "255.255.0.0", Description: "spaced   desc"},
			{Address: "10.7.0.0", Mask: "255.255.0.0", Description: "single quotes # with hash"},
			{Address: "10.5.0.1", Mask: "255.255.255.255", Description: "host"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseCcdText() =\n%+v\nwant\n%+v", got, want)
	}
}

func TestParseCcdTextEmptyAndLegacy(t *testing.T) {
	got := parseCcdText("bob", "")
	want := Ccd{User: "bob", ClientAddress: "dynamic", ClientAddressIPv6: "dynamic", CustomRoutes: []ccdRoute{}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseCcdText(empty) = %+v, want %+v", got, want)
	}

	// output of the previous ccd.tpl
	legacy := "\nifconfig-push 172.16.100.10 255.255.255.0\npush \"route 10.0.0.0 255.0.0.0\" # lan"
	got = parseCcdText("bob", legacy)
	want = Ccd{User: "bob", ClientAddress: "172.16.100.10", ClientAddressIPv6: "dynamic", CustomRoutes: []ccdRoute{{Address: "10.0.0.0", Mask: "255.0.0.0", Description: "lan"}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseCcdText(legacy) = %+v, want %+v", got, want)
	}
}

func TestRenderCcd(t *testing.T) {
	setupCcdDir(t, nil)
	setNetworks(t, "10.8.0.0/22", "fd00:16:100::/64")

	got, err := renderCcd(Ccd{
		User:              "alice",
		ClientAddress:     "10.8.1.10",
		ClientAddressIPv6: "fd00:16:100::10",
		CustomRoutes: []ccdRoute{
			{Address: "10.1.0.0", Mask: "255.255.0.0", Description: "lan"},
			{Address: "fd00:1::", Mask: "64", Description: "lan6"},
			{Address: "10.2.0.0", Mask: "255.255.0.0"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "ifconfig-push 10.8.1.10 255.255.252.0\n" +
		"ifconfig-ipv6-push fd00:16:100::10/64\n" +
		"push \"route 10.1.0.0 255.255.0.0\" # lan\n" +
		"push \"route-ipv6 fd00:1::/64\" # lan6\n" +
		"push \"route 10.2.0.0 255.255.0.0\"\n"
	if got != want {
		t.Errorf("renderCcd() =\n%q\nwant\n%q", got, want)
	}

	got, err = renderCcd(Ccd{User: "alice", ClientAddress: "dynamic", ClientAddressIPv6: "dynamic", CustomRoutes: []ccdRoute{}})
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("renderCcd(dynamic) = %q, want empty", got)
	}
}

func TestRenderCcdRoundTrip(t *testing.T) {
	setupCcdTest(t, true)

	inputs := []Ccd{
		{User: "alice"},
		{User: "alice", ClientAddress: "172.16.100.10"},
		{User: "alice", ClientAddressIPv6: "fd00:16:100::10"},
		{User: "alice", ClientAddress: "172.16.100.10", ClientAddressIPv6: "fd00:16:100::abcd", CustomRoutes: []ccdRoute{
			{Address: "10.1.0.0", Mask: "255.255.0.0", Description: "lan with   spaces"},
			{Address: "fd00:1::/64", Description: "lan6 # hash"},
			{Address: "192.168.0.0", Mask: "24"},
			{Address: "2001:db8::/32", Mask: "32", Description: `quote " inside`},
		}},
	}

	for _, in := range inputs {
		normalized, err := validateCcd(in)
		if err != nil {
			t.Fatalf("validateCcd(%+v): %v", in, err)
		}
		text, err := renderCcd(normalized)
		if err != nil {
			t.Fatal(err)
		}
		if got := parseCcdText(normalized.User, text); !reflect.DeepEqual(got, normalized) {
			t.Errorf("round trip mismatch\nrendered:\n%s\ngot:  %+v\nwant: %+v", text, got, normalized)
		}
	}
}

func TestRenderCcdLegacyCustomTemplate(t *testing.T) {
	setupCcdDir(t, nil)
	setNetworks(t, "172.16.100.0/24", "")

	tpl := filepath.Join(t.TempDir(), "ccd.tpl")
	legacy := `{{- if (ne .ClientAddress "dynamic") }}
ifconfig-push {{ .ClientAddress }} 255.255.255.0
{{- end }}
{{- range $route := .CustomRoutes }}
push "route {{ $route.Address }} {{ $route.Mask }}" # {{ $route.Description }}
{{- end }}`
	if err := os.WriteFile(tpl, []byte(legacy), 0644); err != nil {
		t.Fatal(err)
	}
	setFlag(t, ccdTemplatePath, tpl)

	got, err := renderCcd(Ccd{User: "alice", ClientAddress: "172.16.100.10", ClientAddressIPv6: "dynamic", CustomRoutes: []ccdRoute{{Address: "10.0.0.0", Mask: "255.0.0.0", Description: "lan"}}})
	if err != nil {
		t.Fatal(err)
	}
	want := "\nifconfig-push 172.16.100.10 255.255.255.0\npush \"route 10.0.0.0 255.0.0.0\" # lan"
	if got != want {
		t.Errorf("renderCcd(legacy template) = %q, want %q", got, want)
	}
}

func TestModifyAndGetCcd(t *testing.T) {
	dir := setupCcdTest(t, true)
	oAdmin := &OvpnAdmin{}

	ok, msg := oAdmin.modifyCcd(Ccd{User: "dots.user", ClientAddress: "172.16.100.30", ClientAddressIPv6: "fd00:16:100::30", CustomRoutes: []ccdRoute{{Address: "fd00:1::/64", Description: "lan6"}}})
	if !ok {
		t.Fatalf("modifyCcd() failed: %s", msg)
	}

	content, err := os.ReadFile(filepath.Join(dir, "dots.user"))
	if err != nil {
		t.Fatal(err)
	}
	want := "ifconfig-push 172.16.100.30 255.255.255.0\nifconfig-ipv6-push fd00:16:100::30/64\npush \"route-ipv6 fd00:1::/64\" # lan6\n"
	if string(content) != want {
		t.Errorf("ccd file = %q, want %q", content, want)
	}

	got, err := oAdmin.getCcd("dots.user")
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientAddress != "172.16.100.30" || got.ClientAddressIPv6 != "fd00:16:100::30" || len(got.CustomRoutes) != 1 {
		t.Errorf("getCcd() = %+v", got)
	}

	// another user cannot take the same IPv6 address written in another form
	if ok, msg := oAdmin.modifyCcd(Ccd{User: "alice", ClientAddressIPv6: "fd00:16:100:0:0:0:0:30"}); ok || !strings.Contains(msg, "already assigned") {
		t.Errorf("modifyCcd(duplicate) = %v, %q", ok, msg)
	}

	// path traversal never reaches the filesystem
	for _, name := range []string{"../evil", "..", "x/y"} {
		if ok, _ := oAdmin.modifyCcd(Ccd{User: name}); ok {
			t.Errorf("modifyCcd(%q) succeeded", name)
		}
		if _, err := oAdmin.getCcd(name); err == nil {
			t.Errorf("getCcd(%q) succeeded", name)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "evil")); err == nil {
		t.Error("file written outside of ccd dir")
	}

	if _, err := oAdmin.getCcd("carol"); err == nil {
		t.Error("getCcd(unknown user) succeeded")
	}
}

func TestCheckStaticAddressIsFree(t *testing.T) {
	setupUsers(t, "alice", "bob")
	dir := setupCcdDir(t, map[string]string{
		"alice": "ifconfig-push 172.16.100.10 255.255.255.0\n",
		"bob":   "ifconfig-ipv6-push fd00:16:100:0:0:0:0:20/64\npush \"route 10.0.0.0 255.0.0.0\" # 172.16.100.99\n",
	})
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0755); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		addr, user string
		want       bool
	}{
		{"fd00:16:100::20", "alice", false},
		{"FD00:16:100::0020", "alice", false},
		{"fd00:16:100::20", "bob", true},
		{"172.16.100.10", "alice", true},
		{"172.16.100.10", "bob", false},
		{"::ffff:172.16.100.10", "bob", false},
		{"172.16.100.99", "alice", true},
		{"172.16.100.11", "alice", true},
		{"fd00:16:100::21", "alice", true},
		{"not-an-ip", "alice", false},
	}
	for _, tt := range tests {
		if got := checkStaticAddressIsFree(tt.addr, tt.user); got != tt.want {
			t.Errorf("checkStaticAddressIsFree(%q, %q) = %v, want %v", tt.addr, tt.user, got, tt.want)
		}
	}

	setFlag(t, ccdDir, filepath.Join(dir, "does-not-exist"))
	if !checkStaticAddressIsFree("172.16.100.10", "bob") {
		t.Error("checkStaticAddressIsFree() with missing ccd dir = false, want true")
	}
}
