package main

import (
	"net"
	"testing"
)

func TestIsRandomMAC(t *testing.T) {
	cases := map[string]bool{
		"42:63:62:B7:9E:98": true,  // Android randomized
		"f6:cd:3f:99:55:37": true,  // lowercase
		"D0:C6:5B:8B:50:00": false, // vendor OUI
		"03:00:00:00:00:00": false, // multicast
		"":                  false,
		"not-a-mac":         false,
	}
	for mac, want := range cases {
		if got := isRandomMAC(mac); got != want {
			t.Errorf("isRandomMAC(%q) = %v, want %v", mac, got, want)
		}
	}
}

func TestFit(t *testing.T) {
	cases := []struct {
		s    string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"AVM Fritz!Box 7360 (Linux 3.10)", 10, "AVM Fritz…"},
		{"ñandúñandú", 5, "ñand…"},
	}
	for _, c := range cases {
		if got := fit(c.s, c.n); got != c.want {
			t.Errorf("fit(%q, %d) = %q, want %q", c.s, c.n, got, c.want)
		}
	}
}

func TestDeviceTypeEmoji(t *testing.T) {
	cases := []struct {
		name string
		h    Host
		want string
	}{
		{"gateway wins over OS", Host{Gateway: true, OS: "Linux 3.10"}, "🖧"},
		{"nmap phone class", Host{OSType: "phone", OS: "Linux"}, "📱"},
		{"android in OS", Host{OS: "Android 13"}, "📱"},
		{"tv", Host{OS: "Tizen 5"}, "📺"},
		{"rtsp camera", Host{OS: "Linux 3.2", Ports: []string{"80/tcp", "554/tcp"}}, "📷"},
		{"dns server as router", Host{OS: "Linux", Ports: []string{"53/tcp"}}, "🖧"},
		{"many ports linux", Host{OS: "Linux", Ports: []string{"1/tcp", "2/tcp", "3/tcp", "4/tcp", "5/tcp", "6/tcp"}}, "🖧"},
		{"computer", Host{OS: "Linux 5.0 - 6.2", Ports: []string{"22/tcp"}}, "💻"},
		{"known OS beats random MAC", Host{OS: "Apple macOS 14", MAC: "9A:4F:AB:1A:B9:51"}, "💻"},
		{"random MAC only", Host{MAC: "42:63:62:B7:9E:98"}, "📱?"},
		{"unknown", Host{MAC: "2C:F4:32:AA:0B:9F", OS: "lwIP 2.0"}, "❓"},
	}
	for _, c := range cases {
		if got := deviceTypeEmoji(c.h); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestParseBtmgmt(t *testing.T) {
	out := "Discovery started\r\n" +
		"hci0 dev_found: F8:3F:51:78:BB:09 type LE Public rssi -79 flags 0x0020\r\n" +
		"name [TV] Samsung 6 Series (55)\r\n" +
		"hci0 dev_found: AA:BB:CC:DD:EE:FF type LE Random rssi -90 flags 0x0004\r\n" +
		"hci0 dev_found: D2:BD:F1:B2:84:D0 type LE Random rssi -60 flags 0x0000\r\n" +
		"name Mi Smart Band 4\r\n"
	got := parseBtmgmt(out)
	want := map[string]string{
		"f8:3f:51:78:bb:09": "[TV] Samsung 6 Series (55)",
		"d2:bd:f1:b2:84:d0": "Mi Smart Band 4",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for mac, name := range want {
		if got[mac] != name {
			t.Errorf("%s: got %q, want %q", mac, got[mac], name)
		}
	}
}

func TestParseMDNSPTR(t *testing.T) {
	q := []byte{3, '1', '0', '9', 3, '1', '0', '0', 3, '1', '6', '8', 3, '1', '9', '2', 7, 'i', 'n', '-', 'a', 'd', 'd', 'r', 4, 'a', 'r', 'p', 'a', 0}
	resp := []byte{0, 0, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0}
	resp = append(resp, q...)
	resp = append(resp, 0, 12, 0, 1)               // question PTR IN
	resp = append(resp, 0xC0, 12)                  // answer owner: pointer to question name
	resp = append(resp, 0, 12, 0, 1, 0, 0, 0, 120) // PTR, IN, TTL
	rdata := []byte{6, 'l', 'e', 'n', 'o', 'v', 'o', 5, 'l', 'o', 'c', 'a', 'l', 0}
	resp = append(resp, 0, byte(len(rdata)))
	resp = append(resp, rdata...)

	if got := parseMDNSPTR(resp); got != "lenovo" {
		t.Errorf("got %q, want lenovo", got)
	}
	for _, bad := range [][]byte{nil, resp[:12], resp[:len(resp)-3]} {
		if got := parseMDNSPTR(bad); got != "" {
			t.Errorf("truncated response: got %q, want empty", got)
		}
	}
}

func TestParseNBStat(t *testing.T) {
	resp := []byte{0x13, 0x37, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0x20, 'C', 'K'}
	for i := 0; i < 30; i++ {
		resp = append(resp, 'A')
	}
	resp = append(resp, 0, 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 0x41)
	entry := func(name string, suffix byte, flags uint16) []byte {
		b := []byte(name + "               ")[:15]
		return append(b, suffix, byte(flags>>8), byte(flags))
	}
	resp = append(resp, 3)
	resp = append(resp, entry("WORKGROUP", 0x00, 0x8400)...)   // group
	resp = append(resp, entry("DESKTOP-ABC", 0x20, 0x0400)...) // server service
	resp = append(resp, entry("DESKTOP-ABC", 0x00, 0x0400)...) // workstation

	if got := parseNBStat(resp); got != "DESKTOP-ABC" {
		t.Errorf("got %q, want DESKTOP-ABC", got)
	}
	if got := parseNBStat(resp[:20]); got != "" {
		t.Errorf("truncated response: got %q, want empty", got)
	}
}

func TestParseDefaultRoute(t *testing.T) {
	data := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n" +
		"wlan0\t00000000\t0164A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
	iface, gw := parseDefaultRoute(data)
	if iface != "wlan0" || gw != "192.168.100.1" {
		t.Errorf("got (%q, %q), want (wlan0, 192.168.100.1)", iface, gw)
	}
	if iface, gw := parseDefaultRoute(""); iface != "" || gw != "" {
		t.Errorf("empty input: got (%q, %q)", iface, gw)
	}
}

func TestNetworkCIDR(t *testing.T) {
	cases := map[string]string{
		"192.168.100.230/24": "192.168.100.0/24",
		"10.0.0.77/27":       "10.0.0.64/27",
		"172.16.5.9/16":      "172.16.5.0/24", // clamped
	}
	for in, want := range cases {
		ip, ipnet, _ := net.ParseCIDR(in)
		ipnet.IP = ip
		if got := networkCIDR(ipnet); got != want {
			t.Errorf("networkCIDR(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestSortByIP(t *testing.T) {
	hosts := []Host{{IP: "192.168.100.230"}, {IP: "192.168.100.13"}, {IP: "192.168.100.1"}, {IP: "192.168.100.105"}}
	sortByIP(hosts)
	want := []string{"192.168.100.1", "192.168.100.13", "192.168.100.105", "192.168.100.230"}
	for i, h := range hosts {
		if h.IP != want[i] {
			t.Fatalf("got order %v, want %v", hosts, want)
		}
	}
}
