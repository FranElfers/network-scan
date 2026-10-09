package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Ullaakut/nmap/v3"
)

// -v disables the [*] step logs (enabled by default).
var disableLogs = flag.Bool("v", false, "Disable verbose logs for different steps")

func logStep(format string, args ...interface{}) {
	if !*disableLogs {
		fmt.Printf("[*] "+format+"\n", args...)
	}
}

// Host represents a network device
type Host struct {
	IP            string
	MAC           string
	Name          string // from mDNS or NetBIOS
	OS            string
	OSType        string // nmap OS class type, e.g. "phone", "router"
	Ports         []string
	Version       string
	BluetoothName string
	Gateway       bool // host is this machine's default gateway
}

func (h Host) hasPort(port string) bool {
	for _, p := range h.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// deviceTypeEmoji returns an emoji based on host characteristics
func deviceTypeEmoji(h Host) string {
	os := strings.ToLower(h.OS)
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(os, s) {
				return true
			}
		}
		return false
	}
	switch {
	case h.IP == "BT only":
		return "📡"
	case h.Gateway:
		return "🖧"
	case h.OSType == "phone" || has("android", "ios"):
		return "📱"
	case h.OSType == "media device" || has("tizen", "webos", "roku"):
		return "📺"
	case h.hasPort("554/tcp"): // RTSP: IP camera or DVR
		return "📷"
	case h.OSType == "router" || h.OSType == "WAP" || has("router") || h.hasPort("53/tcp") || has("linux") && len(h.Ports) > 5: // heuristic: DNS or many ports might indicate router
		return "🖧"
	case has("windows", "macos", "linux"):
		return "💻"
	case isRandomMAC(h.MAC): // phones randomize their Wi-Fi MAC per network
		return "📱?"
	}
	return "❓"
}

// isRandomMAC reports whether mac is a locally administered unicast address,
// as used by Android/iOS/Windows MAC randomization.
func isRandomMAC(mac string) bool {
	hw, err := net.ParseMAC(mac)
	return err == nil && len(hw) > 0 && hw[0]&0x02 != 0 && hw[0]&0x01 == 0
}

// fit truncates s to n runes, marking the cut with an ellipsis.
func fit(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// scanNetwork runs a single nmap discovery + service scan on target.
func scanNetwork(target string) ([]Host, error) {
	logStep("Scanning %s...", target)
	scanner, err := nmap.NewScanner(context.Background(),
		nmap.WithTargets(target),
		nmap.WithDisabledDNSResolution(),
		nmap.WithServiceInfo(),
		nmap.WithOSDetection(),
		nmap.WithOSScanGuess(),
		nmap.WithVersionLight(),
		nmap.WithTimingTemplate(nmap.TimingAggressive),
		nmap.WithMostCommonPorts(50),
		nmap.WithMaxRetries(1),
	)
	if err != nil {
		return nil, fmt.Errorf("Error creating nmap scanner: %v", err)
	}
	run, _, err := scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("Error running nmap: %v", err)
	}

	var hosts []Host
	for _, x := range run.Hosts {
		if x.Status.State != "up" {
			continue
		}
		var h Host
		for _, a := range x.Addresses {
			switch a.AddrType {
			case "ipv4":
				h.IP = a.Addr
			case "mac":
				h.MAC = a.Addr
			}
		}
		for _, p := range x.Ports {
			if p.Status() != nmap.Open {
				continue
			}
			h.Ports = append(h.Ports, fmt.Sprintf("%d/%s", p.ID, p.Protocol))
			if h.OS == "" {
				h.OS = p.Service.OSType
			}
			if h.Version == "" {
				h.Version = strings.TrimSpace(p.Service.Product + " " + p.Service.Version)
			}
		}
		// Fall back to -O fingerprinting (best match first) when services gave no OS.
		if len(x.OS.Matches) > 0 {
			m := x.OS.Matches[0]
			if h.OS == "" {
				h.OS = m.Name
			}
			if len(m.Classes) > 0 {
				h.OSType = m.Classes[0].Type
			}
		}
		hosts = append(hosts, h)
	}
	logStep("Found %d live hosts", len(hosts))
	return hosts, nil
}

// getBluetoothDevices executes sudo btmgmt find and returns a map of MAC to device name
func getBluetoothDevices() map[string]string {
	btMap := make(map[string]string)
	// Check if btmgmt exists
	if _, err := exec.LookPath("btmgmt"); err != nil {
		// btmgmt not found, return empty map
		return btMap
	}

	logStep("Starting Bluetooth scan (10 seconds)...")

	// We use 'script' to allocate a pseudo-tty (PTY). This tricks btmgmt into thinking
	// it's connected to a real terminal, so it natively line-buffers its output.
	// That way, when the 10-second timeout forcefully kills it, we've captured the output.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "script", "-q", "-c", "btmgmt find", "/dev/null")
	output, err := cmd.CombinedOutput()

	// If it was just a timeout, we proceed to parse the output we captured.
	if err != nil && ctx.Err() == nil {
		logStep("Bluetooth scan failed: %v", err)
		return btMap
	}

	// btmgmt prints MAC and name on different lines:
	// hci0 dev_found: F8:3F:51:78:BB:09 type LE Public rssi -79 flags 0x0020
	// name [TV] Samsung 6 Series (55)
	macRegex := regexp.MustCompile(`(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}`)
	var currentMAC string

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "name ") {
			if name := strings.TrimSpace(strings.TrimPrefix(line, "name ")); name != "" && currentMAC != "" {
				btMap[strings.ToLower(currentMAC)] = name
			}
		} else if mac := macRegex.FindString(line); mac != "" {
			currentMAC = mac
		}
	}

	logStep("Found %d named Bluetooth devices", len(btMap))
	return btMap
}

// udpQuery sends payload to addr and returns the first reply, or nil on timeout/error.
func udpQuery(addr string, payload []byte) []byte {
	conn, err := net.Dial("udp4", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	if _, err := conn.Write(payload); err != nil {
		return nil
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

// readDNSName decodes a (possibly compressed) DNS name at off; returns the name and the offset after it.
func readDNSName(msg []byte, off int) (string, int, bool) {
	var labels []string
	end := -1
	for jumps := 0; jumps < 16; {
		if off >= len(msg) {
			return "", 0, false
		}
		l := int(msg[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, "."), end, true
		case l&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, false
			}
			if end < 0 {
				end = off + 2
			}
			off = int(binary.BigEndian.Uint16(msg[off:]) & 0x3FFF)
			jumps++
		default:
			if off+1+l > len(msg) {
				return "", 0, false
			}
			labels = append(labels, string(msg[off+1:off+1+l]))
			off += 1 + l
		}
	}
	return "", 0, false
}

// mdnsName asks the host directly (unicast to port 5353) for the PTR of its IP.
func mdnsName(ip string) string {
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		return ""
	}
	q := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0} // header: 1 question
	for _, label := range []string{
		fmt.Sprint(v4[3]), fmt.Sprint(v4[2]), fmt.Sprint(v4[1]), fmt.Sprint(v4[0]), "in-addr", "arpa",
	} {
		q = append(append(q, byte(len(label))), label...)
	}
	q = append(q, 0, 0, 12, 0, 1) // PTR, IN

	resp := udpQuery(ip+":5353", q)
	if len(resp) < 12 || binary.BigEndian.Uint16(resp[6:]) == 0 {
		return ""
	}
	off := 12
	for i := binary.BigEndian.Uint16(resp[4:]); i > 0; i-- { // skip questions
		_, next, ok := readDNSName(resp, off)
		if !ok {
			return ""
		}
		off = next + 4
	}
	_, off, ok := readDNSName(resp, off) // answer owner name
	if !ok || off+10 > len(resp) || binary.BigEndian.Uint16(resp[off:]) != 12 {
		return ""
	}
	name, _, ok := readDNSName(resp, off+10)
	if !ok {
		return ""
	}
	return strings.TrimSuffix(name, ".local")
}

// netbiosName sends a NetBIOS node status request and returns the unique workstation name.
func netbiosName(ip string) string {
	q := []byte{0x13, 0x37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20, 'C', 'K'} // "*" encoded
	for i := 0; i < 30; i++ {
		q = append(q, 'A')
	}
	q = append(q, 0, 0, 0x21, 0, 1) // NBSTAT, IN

	resp := udpQuery(ip+":137", q)
	if len(resp) < 12 {
		return ""
	}
	_, off, ok := readDNSName(resp, 12)
	if !ok || off+11 > len(resp) {
		return ""
	}
	off += 10 // type, class, ttl, rdlength
	count := int(resp[off])
	off++
	for i := 0; i < count && off+18 <= len(resp); i, off = i+1, off+18 {
		suffix, flags := resp[off+15], binary.BigEndian.Uint16(resp[off+16:])
		if suffix == 0x00 && flags&0x8000 == 0 { // workstation, unique (not group)
			return strings.TrimSpace(string(resp[off : off+15]))
		}
	}
	return ""
}

// resolveNames fills Host.Name via mDNS, falling back to NetBIOS, querying all hosts in parallel.
func resolveNames(hosts []Host) {
	logStep("Resolving names via mDNS/NetBIOS...")
	var wg sync.WaitGroup
	for i := range hosts {
		wg.Add(1)
		go func(h *Host) {
			defer wg.Done()
			if h.Name = mdnsName(h.IP); h.Name == "" {
				h.Name = netbiosName(h.IP)
			}
		}(&hosts[i])
	}
	wg.Wait()
}

// defaultGateway returns the IPv4 default gateway from /proc/net/route, or "" if unknown.
func defaultGateway() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		var gw uint32
		if _, err := fmt.Sscanf(f[2], "%x", &gw); err != nil || gw == 0 {
			continue
		}
		// /proc/net/route stores addresses in host (little-endian) byte order.
		return net.IPv4(byte(gw), byte(gw>>8), byte(gw>>16), byte(gw>>24)).String()
	}
	return ""
}

// getLocalNetwork attempts to auto-detect the local network CIDR
func getLocalNetwork() string {
	// Simple approach: get first non-loopback IPv4 address and assume /24
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil || ip.IsLoopback() {
			continue
		}
		if ipv4 := ip.To4(); ipv4 != nil {
			return fmt.Sprintf("%d.%d.%d.0/24", ipv4[0], ipv4[1], ipv4[2])
		}
	}
	return ""
}

func main() {
	flag.Parse()

	if os.Geteuid() != 0 {
		fmt.Printf("Error: must run as root (nmap needs it for MAC addresses and OS detection). Try: sudo %s\n", os.Args[0])
		os.Exit(1)
	}

	var target string
	if flag.NArg() > 0 {
		target = flag.Arg(0)
	} else {
		target = getLocalNetwork()
		if target == "" {
			fmt.Println("Error: Could not auto-detect network. Please provide a target (e.g., 192.168.1.0/24)")
			os.Exit(1)
		}
	}

	var wg sync.WaitGroup
	var hosts []Host
	var btDevices map[string]string
	var nmapErr error

	wg.Add(2)
	go func() {
		defer wg.Done()
		if hosts, nmapErr = scanNetwork(target); nmapErr == nil {
			resolveNames(hosts)
			gw := defaultGateway()
			for i := range hosts {
				hosts[i].Gateway = hosts[i].IP == gw
			}
		}
	}()
	go func() {
		defer wg.Done()
		btDevices = getBluetoothDevices()
	}()
	wg.Wait()

	if nmapErr != nil {
		fmt.Println(nmapErr)
		os.Exit(1)
	}

	logStep("Matching Bluetooth devices with network hosts...")
	// Match Bluetooth devices with scanned hosts
	matchedBT := make(map[string]bool)
	for i := range hosts {
		macLower := strings.ToLower(hosts[i].MAC)
		if btName, found := btDevices[macLower]; found {
			hosts[i].BluetoothName = btName
			matchedBT[macLower] = true
		}
	}

	// Add unmatched Bluetooth devices to the list
	for mac, btName := range btDevices {
		if !matchedBT[mac] {
			hosts = append(hosts, Host{IP: "BT only", MAC: strings.ToUpper(mac), Version: btName})
		}
	}

	// Print header
	const row = "%-15s %-17s %-20s %-25s %-25s %-25s %s\n"
	fmt.Printf(row, "IP", "MAC", "Name", "OS", "Ports", "Version", "Device")
	fmt.Printf(row, "---", "---", "----", "--", "-----", "-------", "-----")

	// Print each host
	for _, h := range hosts {
		portsStr := strings.Join(h.Ports, ",")
		if portsStr == "" {
			portsStr = "none"
		}
		versionStr := h.Version
		if versionStr == "" {
			versionStr = "-"
		}
		fmt.Printf(row, h.IP, h.MAC, fit(h.Name, 20), fit(h.OS, 25), fit(portsStr, 25), fit(versionStr, 25), deviceTypeEmoji(h))
		// Print Bluetooth name below if available
		if h.BluetoothName != "" {
			fmt.Printf(row, "", "", "", "", "", fit(h.BluetoothName, 25), "")
		}
	}
}
