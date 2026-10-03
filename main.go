package main

import (
	"bufio"
	"context"
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
	OS            string
	Ports         []string
	Version       string
	BluetoothName string
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
	case has("android", "ios"):
		return "📱"
	case has("tizen", "webos", "roku"):
		return "📺"
	case has("router") || has("linux") && len(h.Ports) > 5: // heuristic: many ports might indicate router
		return "🖧"
	case has("windows", "macos", "linux"):
		return "💻"
	}
	return "❓"
}

// scanNetwork runs a single nmap discovery + service scan on target.
func scanNetwork(target string) ([]Host, error) {
	logStep("Scanning %s...", target)
	scanner, err := nmap.NewScanner(context.Background(),
		nmap.WithTargets(target),
		nmap.WithDisabledDNSResolution(),
		nmap.WithServiceInfo(),
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

	cmd := exec.CommandContext(ctx, "script", "-q", "-c", "sudo btmgmt find", "/dev/null")
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
		hosts, nmapErr = scanNetwork(target)
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
	fmt.Printf("%-15s %-17s %-10s %-25s %-25s %s\n", "IP", "MAC", "OS", "Ports", "Version", "Device")
	fmt.Printf("%-15s %-17s %-10s %-25s %-25s %s\n", "---", "---", "--", "-----", "-------", "-----")

	// Print each host
	for _, h := range hosts {
		portsStr := strings.Join(h.Ports, ",")
		if portsStr == "" {
			portsStr = "none"
		}
		versionStr := h.Version
		if versionStr == "" {
			versionStr = "(no OS)"
		}
		fmt.Printf("%-15s %-17s %-10s %-25s %-25s %s\n", h.IP, h.MAC, h.OS, portsStr, versionStr, deviceTypeEmoji(h))
		// Print Bluetooth name below if available
		if h.BluetoothName != "" {
			fmt.Printf("%-15s %-17s %-10s %-25s %-25s\n", "", "", "", "", h.BluetoothName)
		}
	}
}
