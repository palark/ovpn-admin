package main

import (
	"bufio"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func tsv(fields ...string) string {
	return strings.Join(fields, "\t")
}

func fmtTS(ts int64) string {
	return time.Unix(ts, 0).Format(stringDateFormat)
}

// OpenVPN 2.6 "status 3" output: IPv4-only client, dual-stack client with two routing
// entries, iroute entry, cached ("C" flag) host routes behind a client, duplicate-cn
// sessions, IPv6 and v4-mapped real addresses.
var mgmtStatus26 = strings.Join([]string{
	tsv("TITLE", "OpenVPN 2.6.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] [DCO]"),
	tsv("TIME", "2024-05-01 12:00:00", "1714564800"),
	tsv("HEADER", "CLIENT_LIST", "Common Name", "Real Address", "Virtual Address", "Virtual IPv6 Address", "Bytes Received", "Bytes Sent", "Connected Since", "Connected Since (time_t)", "Username", "Client ID", "Peer ID", "Data Channel Cipher"),
	tsv("CLIENT_LIST", "alice", "198.51.100.7:51234", "172.16.100.10", "", "1000", "2000", "2024-05-01 11:00:00", "1714561200", "UNDEF", "0", "0", "AES-256-GCM"),
	tsv("CLIENT_LIST", "bob", "2001:db8::77", "172.16.100.11", "fd00:16:100::1000", "3000", "4000", "2024-05-01 11:10:00", "1714561800", "UNDEF", "1", "1", "AES-256-GCM"),
	tsv("CLIENT_LIST", "carol", "203.0.113.5:40001", "172.16.100.12", "", "10", "20", "2024-05-01 11:13:20", "1714562000", "UNDEF", "2", "2", "AES-256-GCM"),
	tsv("CLIENT_LIST", "carol", "203.0.113.5:40002", "172.16.100.13", "", "30", "40", "2024-05-01 11:15:00", "1714562100", "UNDEF", "3", "3", "CHACHA20-POLY1305"),
	tsv("CLIENT_LIST", "BRENDEN", "::ffff:192.0.2.9:61000", "172.16.100.14", "", "5", "6", "2024-05-01 11:16:40", "1714562200", "UNDEF", "4", "4", "AES-256-GCM"),
	tsv("HEADER", "ROUTING_TABLE", "Virtual Address", "Common Name", "Real Address", "Last Ref", "Last Ref (time_t)"),
	tsv("ROUTING_TABLE", "172.16.100.10", "alice", "198.51.100.7:51234", "2024-05-01 11:59:00", "1714564740"),
	tsv("ROUTING_TABLE", "10.20.0.0/16", "alice", "198.51.100.7:51234", "2024-05-01 11:59:50", "1714564790"),
	tsv("ROUTING_TABLE", "fd00:1::5C", "alice", "198.51.100.7:51234", "2024-05-01 11:59:55", "1714564795"),
	tsv("ROUTING_TABLE", "10.20.0.5C", "alice", "198.51.100.7:51234", "2024-05-01 11:59:56", "1714564796"),
	tsv("ROUTING_TABLE", "fd00:16:100::1000", "bob", "2001:db8::77", "2024-05-01 11:59:10", "1714564750"),
	tsv("ROUTING_TABLE", "172.16.100.11", "bob", "2001:db8::77", "2024-05-01 11:58:20", "1714564700"),
	tsv("ROUTING_TABLE", "172.16.100.13", "carol", "203.0.113.5:40002", "2024-05-01 11:56:40", "1714564600"),
	tsv("ROUTING_TABLE", "172.16.100.12", "carol", "203.0.113.5:40001", "2024-05-01 11:55:00", "1714564500"),
	tsv("ROUTING_TABLE", "172.16.100.14", "BRENDEN", "192.0.2.9:61000", "2024-05-01 11:53:20", "1714564400"),
	tsv("GLOBAL_STATS", "Max bcast/mcast queue length", "0"),
	tsv("GLOBAL_STATS", "dco_enabled", "1"),
	"END",
	"",
}, "\r\n")

func TestParseMgmtStatus26(t *testing.T) {
	got := parseMgmtStatus(mgmtStatus26, "main")

	want := []clientStatus{
		{CommonName: "alice", RealAddress: "198.51.100.7:51234", BytesReceived: "1000", BytesSent: "2000", ConnectedSince: fmtTS(1714561200), VirtualAddress: "172.16.100.10", LastRef: fmtTS(1714564740), ConnectedTo: "main", connectedSinceUnix: 1714561200, lastRefUnix: 1714564740},
		{CommonName: "bob", RealAddress: "2001:db8::77", BytesReceived: "3000", BytesSent: "4000", ConnectedSince: fmtTS(1714561800), VirtualAddress: "172.16.100.11", VirtualAddressIPv6: "fd00:16:100::1000", LastRef: fmtTS(1714564750), ConnectedTo: "main", connectedSinceUnix: 1714561800, lastRefUnix: 1714564750},
		{CommonName: "carol", RealAddress: "203.0.113.5:40001", BytesReceived: "10", BytesSent: "20", ConnectedSince: fmtTS(1714562000), VirtualAddress: "172.16.100.12", LastRef: fmtTS(1714564500), ConnectedTo: "main", connectedSinceUnix: 1714562000, lastRefUnix: 1714564500},
		{CommonName: "carol", RealAddress: "203.0.113.5:40002", BytesReceived: "30", BytesSent: "40", ConnectedSince: fmtTS(1714562100), VirtualAddress: "172.16.100.13", LastRef: fmtTS(1714564600), ConnectedTo: "main", connectedSinceUnix: 1714562100, lastRefUnix: 1714564600},
		{CommonName: "BRENDEN", RealAddress: "192.0.2.9:61000", BytesReceived: "5", BytesSent: "6", ConnectedSince: fmtTS(1714562200), VirtualAddress: "172.16.100.14", LastRef: fmtTS(1714564400), ConnectedTo: "main", connectedSinceUnix: 1714562200, lastRefUnix: 1714564400},
	}

	if len(got) != len(want) {
		t.Fatalf("parseMgmtStatus() returned %d sessions, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("session %d:\ngot  %+v\nwant %+v", i, got[i], want[i])
		}
	}
}

// OpenVPN 2.4: no "Data Channel Cipher" column, ctime-like human dates; the IPv6
// virtual address is only known from the routing table.
// dev tap: the routing table holds MAC addresses, CLIENT_LIST has the address from
// ifconfig-push (dave) or nothing (erin gets its address from DHCP behind the bridge).
func TestParseMgmtStatusTap(t *testing.T) {
	status := strings.Join([]string{
		tsv("HEADER", "CLIENT_LIST", "Common Name", "Real Address", "Virtual Address", "Virtual IPv6 Address", "Bytes Received", "Bytes Sent", "Connected Since", "Connected Since (time_t)", "Username", "Client ID", "Peer ID", "Data Channel Cipher"),
		tsv("CLIENT_LIST", "dave", "198.51.100.20:1194", "172.29.11.50", "", "100", "200", "2024-05-01 11:00:00", "1714561200", "UNDEF", "0", "0", "AES-256-GCM"),
		tsv("CLIENT_LIST", "erin", "198.51.100.21:1194", "", "", "300", "400", "2024-05-01 11:10:00", "1714561800", "UNDEF", "1", "1", "AES-256-GCM"),
		tsv("HEADER", "ROUTING_TABLE", "Virtual Address", "Common Name", "Real Address", "Last Ref", "Last Ref (time_t)"),
		tsv("ROUTING_TABLE", "02:ab:cd:ef:00:01", "dave", "198.51.100.20:1194", "2024-05-01 11:59:00", "1714564740"),
		tsv("ROUTING_TABLE", "02:ab:cd:ef:00:02", "erin", "198.51.100.21:1194", "2024-05-01 11:58:20", "1714564700"),
		"END",
	}, "\n")

	got := parseMgmtStatus(status, "main")
	if len(got) != 2 {
		t.Fatalf("got %d sessions, want 2: %+v", len(got), got)
	}
	if got[0].VirtualAddress != "172.29.11.50" || got[0].LastRef != fmtTS(1714564740) {
		t.Errorf("dave: VirtualAddress=%q LastRef=%q, want 172.29.11.50 and the Last Ref of its MAC route", got[0].VirtualAddress, got[0].LastRef)
	}
	if got[1].VirtualAddress != "02:ab:cd:ef:00:02" || got[1].LastRef != fmtTS(1714564700) {
		t.Errorf("erin: VirtualAddress=%q LastRef=%q, want its MAC and the Last Ref of its MAC route", got[1].VirtualAddress, got[1].LastRef)
	}
}

func TestParseMgmtStatus24RoutingFallback(t *testing.T) {
	status := strings.Join([]string{
		tsv("TITLE", "OpenVPN 2.4.12 x86_64-pc-linux-gnu"),
		tsv("HEADER", "CLIENT_LIST", "Common Name", "Real Address", "Virtual Address", "Virtual IPv6 Address", "Bytes Received", "Bytes Sent", "Connected Since", "Connected Since (time_t)", "Username", "Client ID", "Peer ID"),
		tsv("CLIENT_LIST", "dave", "[AF_INET6]2001:db8::5:51234", "", "", "1", "2", "Wed May  1 11:00:00 2024", "1714561200", "UNDEF", "0", "0"),
		tsv("HEADER", "ROUTING_TABLE", "Virtual Address", "Common Name", "Real Address", "Last Ref", "Last Ref (time_t)"),
		tsv("ROUTING_TABLE", "fd00:16:100::1001", "dave", "2001:db8::5:51234", "Wed May  1 11:59:00 2024", "1714564740"),
		tsv("ROUTING_TABLE", "172.16.100.20", "dave", "2001:db8::5:51234", "Wed May  1 11:58:00 2024", "1714564680"),
		"END",
	}, "\n")

	got := parseMgmtStatus(status, "second")
	if len(got) != 1 {
		t.Fatalf("got %d sessions", len(got))
	}
	s := got[0]
	if s.RealAddress != "[2001:db8::5]:51234" || s.VirtualAddress != "172.16.100.20" || s.VirtualAddressIPv6 != "fd00:16:100::1001" || s.LastRef != fmtTS(1714564740) || s.ConnectedTo != "second" {
		t.Errorf("unexpected session %+v", s)
	}
}

func TestParseMgmtStatusHeaderDrivenColumns(t *testing.T) {
	// columns in an unusual order and without time_t: must still be parsed by name
	status := strings.Join([]string{
		tsv("HEADER", "CLIENT_LIST", "Real Address", "Common Name", "Connected Since", "Bytes Sent", "Bytes Received", "Virtual Address"),
		tsv("CLIENT_LIST", "198.51.100.1:1000", "erin", "2024-05-01 11:00:00", "7", "8", "172.16.100.30"),
		tsv("HEADER", "ROUTING_TABLE", "Common Name", "Real Address", "Virtual Address", "Last Ref"),
		tsv("ROUTING_TABLE", "erin", "198.51.100.1:1000", "172.16.100.30", "2024-05-01 11:30:00"),
		"END",
	}, "\n")

	got := parseMgmtStatus(status, "main")
	if len(got) != 1 {
		t.Fatalf("got %d sessions", len(got))
	}
	s := got[0]
	if s.CommonName != "erin" || s.RealAddress != "198.51.100.1:1000" || s.BytesSent != "7" || s.BytesReceived != "8" ||
		s.VirtualAddress != "172.16.100.30" || s.ConnectedSince != "2024-05-01 11:00:00" || s.LastRef != "2024-05-01 11:30:00" {
		t.Errorf("unexpected session %+v", s)
	}
}

func TestParseMgmtStatusCommaSeparated(t *testing.T) {
	status := "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID\n" +
		"CLIENT_LIST,frank,198.51.100.2:2000,172.16.100.40,,1,2,2024-05-01 11:00:00,1714561200,UNDEF,0,0\n" +
		"END\n"
	got := parseMgmtStatus(status, "main")
	if len(got) != 1 || got[0].CommonName != "frank" || got[0].VirtualAddress != "172.16.100.40" {
		t.Errorf("parseMgmtStatus(status 2) = %+v", got)
	}
}

func TestParseMgmtStatusMalformed(t *testing.T) {
	for _, status := range []string{
		"",
		"CLIENT_LIST",
		"HEADER",
		"ROUTING_TABLE\t\t\t",
		"CLIENT_LIST\tx\n" + tsv("ROUTING_TABLE", "172.16.100.2", "x"),
		">INFO:OpenVPN Management Interface Version 5\nEND",
	} {
		_ = parseMgmtStatus(status, "main") // must not panic
	}
}

func TestNormalizeRealAddress(t *testing.T) {
	tests := map[string]string{
		"198.51.100.7:51234":               "198.51.100.7:51234",
		"[AF_INET]198.51.100.7:51234":      "198.51.100.7:51234",
		"198.51.100.7":                     "198.51.100.7",
		"  198.51.100.7:1  ":               "198.51.100.7:1",
		"[AF_INET6]2001:db8::5":            "2001:db8::5",
		"2001:db8::77":                     "2001:db8::77",
		"[2001:db8::5]:1194":               "[2001:db8::5]:1194",
		"[AF_INET6][2001:db8::5]:1194":     "[2001:db8::5]:1194",
		"2001:db8::5:51234":                "[2001:db8::5]:51234",
		"::ffff:192.0.2.9:61000":           "192.0.2.9:61000",
		"::ffff:192.0.2.9":                 "192.0.2.9",
		"[::ffff:192.0.2.9]:61000":         "192.0.2.9:61000",
		"[AF_INET6]::ffff:192.0.2.9:61000": "192.0.2.9:61000",
		"garbage":                          "garbage",
		"":                                 "",
	}
	for in, want := range tests {
		if got := normalizeRealAddress(in); got != want {
			t.Errorf("normalizeRealAddress(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMgmtReadUntil(t *testing.T) {
	// "END" inside a line (e.g. a common name) must not stop reading
	input := ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n" +
		"CLIENT_LIST\tBRENDEN\r\n" +
		"END\r\n" +
		"garbage after END\r\n"
	r := bufio.NewReader(strings.NewReader(input))

	welcome, err := mgmtReadUntil(r, func(l string) bool { return strings.HasPrefix(l, ">INFO:") })
	if err != nil || !strings.HasPrefix(welcome, ">INFO:") {
		t.Fatalf("welcome = %q, %v", welcome, err)
	}

	out, err := mgmtReadUntil(r, isMgmtEnd)
	if err != nil {
		t.Fatal(err)
	}
	if out != "CLIENT_LIST\tBRENDEN\nEND\n" {
		t.Errorf("mgmtReadUntil() = %q", out)
	}

	// EOF before the terminator returns an error
	if _, err := mgmtReadUntil(bufio.NewReader(strings.NewReader("CLIENT_LIST\tx\n")), isMgmtEnd); err == nil {
		t.Error("mgmtReadUntil() on truncated input: want error")
	}
}

func TestParseMgmtVersion(t *testing.T) {
	out := "OpenVPN Version: OpenVPN 2.6.12 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO]\nManagement Interface Version: 5\nEND\n"
	if got := parseMgmtVersion(out); got != "2.6.12" {
		t.Errorf("parseMgmtVersion() = %q", got)
	}
	if got := parseMgmtVersion("OpenVPN Version:\nEND\n"); got != "" {
		t.Errorf("parseMgmtVersion(short) = %q", got)
	}
}

func TestUpdateConnectionMetrics(t *testing.T) {
	for _, vec := range []*prometheus.GaugeVec{ovpnClientConnectionInfo, ovpnClientConnectionFrom, ovpnClientBytesSent, ovpnClientBytesReceived} {
		vec.Reset()
		t.Cleanup(vec.Reset)
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(ovpnClientConnectionInfo, ovpnClientConnectionFrom, ovpnClientBytesSent)

	updateConnectionMetrics(parseMgmtStatus(mgmtStatus26, "main"))

	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	series := map[string][]string{}
	values := map[string]float64{}
	for _, mf := range families {
		for _, m := range mf.GetMetric() {
			var labels []string
			for _, l := range m.GetLabel() {
				labels = append(labels, l.GetName()+"="+l.GetValue())
			}
			key := strings.Join(labels, ",")
			series[mf.GetName()] = append(series[mf.GetName()], key)
			values[mf.GetName()+"{"+key+"}"] = m.GetGauge().GetValue()
		}
	}
	for _, s := range series {
		sort.Strings(s)
	}

	info := strings.Join(series["ovpn_client_connection_info"], " ")
	for _, want := range []string{"client=bob,ip=172.16.100.11", "client=bob,ip=fd00:16:100::1000", "client=alice,ip=172.16.100.10"} {
		if !strings.Contains(info, want) {
			t.Errorf("ovpn_client_connection_info has no series %s: %s", want, info)
		}
	}
	if len(series["ovpn_client_connection_info"]) != 6 {
		t.Errorf("ovpn_client_connection_info series = %v", series["ovpn_client_connection_info"])
	}
	if v := values["ovpn_client_connection_info{client=bob,ip=fd00:16:100::1000}"]; v != 1714564750 {
		t.Errorf("bob IPv6 last ref = %v", v)
	}
	if v := values["ovpn_client_connection_from{client=BRENDEN,ip=192.0.2.9:61000}"]; v != 1714562200 {
		t.Errorf("BRENDEN connected since = %v", v)
	}
	if v := values["ovpn_client_bytes_sent{client=carol}"]; v != 60 {
		t.Errorf("carol bytes sent = %v, want 60 (sum of sessions)", v)
	}
}
