package main

import (
	"net/url"
	"strings"
	"testing"
)

func TestParseOvpnServer(t *testing.T) {
	tests := []struct {
		in      string
		want    OpenvpnServer
		wantErr string
	}{
		{in: "127.0.0.1:7777:tcp", want: OpenvpnServer{"127.0.0.1", "7777", "tcp"}},
		{in: "vpn.example.com:1194:udp", want: OpenvpnServer{"vpn.example.com", "1194", "udp"}},
		{in: " vpn:1194:tcp-client ", want: OpenvpnServer{"vpn", "1194", "tcp-client"}},
		{in: "vpn:01194:TCP6", want: OpenvpnServer{"vpn", "1194", "tcp6"}},
		{in: "[2001:db8::1]:1194:udp6", want: OpenvpnServer{"2001:db8::1", "1194", "udp6"}},
		{in: "[2001:DB8:0::1]:443:tcp", want: OpenvpnServer{"2001:db8::1", "443", "tcp"}},
		{in: "[::1]:1194:tcp6-client", want: OpenvpnServer{"::1", "1194", "tcp6-client"}},

		{in: "2001:db8::1:1194:udp", wantErr: "brackets"},
		{in: "2001:db8::1", wantErr: "brackets"},
		{in: "[2001:db8::1:1194:udp", wantErr: "missing closing bracket"},
		{in: "[1.2.3.4]:1194:udp", wantErr: "must enclose an IPv6"},
		{in: "[]:1194:udp", wantErr: "must enclose an IPv6"},
		{in: "[2001:db8::1]1194:udp", wantErr: "HOST:PORT:PROTOCOL"},
		{in: "[2001:db8::1]:1194", wantErr: "HOST:PORT:PROTOCOL"},
		{in: "host:1194:udp:extra", wantErr: "HOST:PORT:PROTOCOL"},
		{in: "host:1194", wantErr: "HOST:PORT:PROTOCOL"},
		{in: "host", wantErr: "HOST:PORT:PROTOCOL"},
		{in: "", wantErr: "HOST:PORT:PROTOCOL"},
		{in: ":1194:udp", wantErr: "invalid host"},
		{in: "ho st:1194:udp", wantErr: "invalid host"},
		{in: "host\nremote evil:1194:udp", wantErr: "invalid host"},
		{in: "host:0:udp", wantErr: "invalid port"},
		{in: "host:65536:udp", wantErr: "invalid port"},
		{in: "host:-1:udp", wantErr: "invalid port"},
		{in: "host:abc:udp", wantErr: "invalid port"},
		{in: "host:1194:sctp", wantErr: "unsupported protocol"},
		{in: "host:1194:tcp-server", wantErr: "unsupported protocol"},
		{in: "host:1194:", wantErr: "unsupported protocol"},
	}

	for _, tt := range tests {
		got, err := parseOvpnServer(tt.in)
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("parseOvpnServer(%q) error = %v, want error containing %q", tt.in, err, tt.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseOvpnServer(%q) unexpected error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseOvpnServer(%q) = %+v, want %+v", tt.in, got, tt.want)
		}
	}
}

func TestParseOvpnServers(t *testing.T) {
	got, err := parseOvpnServers([]string{"a:1:udp", "[fd00::1]:2:tcp"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1].Host != "fd00::1" {
		t.Errorf("parseOvpnServers() = %+v", got)
	}

	if _, err := parseOvpnServers([]string{"a:1:udp", "bad"}); err == nil {
		t.Error("parseOvpnServers() with an invalid entry: want error")
	}
}

func TestParseOvpnNetworkV4(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "172.16.100.0/24", want: "172.16.100.0/24"},
		{in: "172.16.100.0/255.255.255.0", want: "172.16.100.0/24"},
		{in: "10.8.0.0/255.255.252.0", want: "10.8.0.0/22"},
		{in: " 10.0.0.0/8 ", want: "10.0.0.0/8"},
		{in: "172.16.100.5/24", want: "172.16.100.0/24"},
		{in: "172.16.100.0/30", want: "172.16.100.0/30"},

		{in: "172.16.100.0", wantErr: true},
		{in: "172.16.100.0/", wantErr: true},
		{in: "172.16.100.0/33", wantErr: true},
		{in: "172.16.100.0/31", wantErr: true},
		{in: "172.16.100.0/0", wantErr: true},
		{in: "172.16.100.0/255.0.255.0", wantErr: true},
		{in: "172.16.100.0/255.255.255.256", wantErr: true},
		{in: "172.16.100.0/-1", wantErr: true},
		{in: "fd00::/64", wantErr: true},
		{in: "::ffff:172.16.100.0/120", wantErr: true},
		{in: "abc/24", wantErr: true},
		{in: "", wantErr: true},
	}

	for _, tt := range tests {
		got, err := parseOvpnNetworkV4(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseOvpnNetworkV4(%q) = %s, want error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseOvpnNetworkV4(%q) unexpected error: %v", tt.in, err)
			continue
		}
		if got.String() != tt.want {
			t.Errorf("parseOvpnNetworkV4(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}
}

func TestParseOvpnNetworkV6(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "", want: "invalid Prefix"},
		{in: "  ", want: "invalid Prefix"},
		{in: "fd00:16:100::/64", want: "fd00:16:100::/64"},
		{in: "fd00:16:100::1/64", want: "fd00:16:100::/64"},
		{in: "2001:DB8::/124", want: "2001:db8::/124"},

		{in: "fd00::/63", wantErr: true},
		{in: "fd00::/125", wantErr: true},
		{in: "fd00::", wantErr: true},
		{in: "10.0.0.0/24", wantErr: true},
		{in: "::ffff:10.0.0.0/120", wantErr: true},
		{in: "garbage", wantErr: true},
	}

	for _, tt := range tests {
		got, err := parseOvpnNetworkV6(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseOvpnNetworkV6(%q) = %s, want error", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseOvpnNetworkV6(%q) unexpected error: %v", tt.in, err)
			continue
		}
		if got.String() != tt.want {
			t.Errorf("parseOvpnNetworkV6(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}
}

func TestInitNetworkConfig(t *testing.T) {
	setFlag(t, openvpnNetwork, "10.8.0.0/255.255.255.0")
	setFlag(t, openvpnNetworkIPv6, "fd00:16:100::/64")
	setFlag(t, openvpnServer, []string{"[2001:db8::1]:1194:udp", "vpn.example.com:443:tcp"})
	oldV4, oldV6, oldServers := ovpnNetworkV4, ovpnNetworkV6, ovpnServers
	t.Cleanup(func() { ovpnNetworkV4, ovpnNetworkV6, ovpnServers = oldV4, oldV6, oldServers })

	if err := initNetworkConfig(); err != nil {
		t.Fatal(err)
	}
	if ovpnNetworkV4.String() != "10.8.0.0/24" || ovpnNetworkV6.String() != "fd00:16:100::/64" || len(ovpnServers) != 2 {
		t.Errorf("initNetworkConfig() = %s %s %+v", ovpnNetworkV4, ovpnNetworkV6, ovpnServers)
	}

	for flag, value := range map[*string]string{
		openvpnNetwork:     "10.8.0.0",
		openvpnNetworkIPv6: "fd00::/48",
	} {
		old := *flag
		*flag = value
		if err := initNetworkConfig(); err == nil {
			t.Errorf("initNetworkConfig() with %q: want error", value)
		}
		*flag = old
	}

	setFlag(t, openvpnServer, []string{"2001:db8::1:1194:udp"})
	if err := initNetworkConfig(); err == nil {
		t.Error("initNetworkConfig() with unbracketed IPv6 server: want error")
	}
}

func TestIPv4Helpers(t *testing.T) {
	p, err := parseOvpnNetworkV4("10.8.0.0/22")
	if err != nil {
		t.Fatal(err)
	}
	if got := ipv4Netmask(p.Bits()); got != "255.255.252.0" {
		t.Errorf("ipv4Netmask() = %s", got)
	}
	if got := ipv4Broadcast(p).String(); got != "10.8.3.255" {
		t.Errorf("ipv4Broadcast() = %s", got)
	}
	if got := serverAddress(p).String(); got != "10.8.0.1" {
		t.Errorf("serverAddress() = %s", got)
	}
}

func TestListenAddress(t *testing.T) {
	tests := []struct {
		host, port, base string
		addr, url        string
	}{
		{"", "8080", "/", ":8080", "http://[::]:8080/"},
		{"0.0.0.0", "8080", "/", "0.0.0.0:8080", "http://0.0.0.0:8080/"},
		{"::", "8080", "/", "[::]:8080", "http://[::]:8080/"},
		{"::1", "9000", "/admin/", "[::1]:9000", "http://[::1]:9000/admin/"},
		{"[fd00::1]", "8080", "/", "[fd00::1]:8080", "http://[fd00::1]:8080/"},
		{"localhost", "8080", "/", "localhost:8080", "http://localhost:8080/"},
	}

	for _, tt := range tests {
		if got := listenAddress(tt.host, tt.port); got != tt.addr {
			t.Errorf("listenAddress(%q, %q) = %q, want %q", tt.host, tt.port, got, tt.addr)
		}
		got := bindURL(tt.host, tt.port, tt.base)
		if got != tt.url {
			t.Errorf("bindURL(%q, %q, %q) = %q, want %q", tt.host, tt.port, tt.base, got, tt.url)
		}
		if _, err := url.Parse(got); err != nil {
			t.Errorf("bindURL(%q) is not a valid URL: %v", tt.host, err)
		}
	}
}
