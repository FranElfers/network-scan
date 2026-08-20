package main

import (
	"bufio"
	"context"
	"encoding/xml"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

var disableLogs bool

func init() {
	// The user asked for logs "which can be disabled with the verbose flag"
	// So we use -v to disable the logs, making them enabled by default.
	flag.BoolVar(&disableLogs, "v", false, "Disable verbose logs for different steps")
}

func logStep(format string, args ...interface{}) {
	if !disableLogs {
		fmt.Printf("[*] "+format+"\n", args...)
	}
}

// Host represents a network device
type Host struct {
	IP            string
	MAC           string
	Hostname      string
	OS            string
	Ports         []string
	Version       string
	BluetoothName string
}

// deviceTypeEmoji returns an emoji based on host characteristics
func deviceTypeEmoji(h Host) string {
	if h.IP == "BT only" {
		return "📡"
	}

	// Check for mobile phone indicators
	if strings.Contains(strings.ToLower(h.Hostname), "phone") ||
		strings.Contains(strings.ToLower(h.Hostname), "android") ||
		strings.Contains(strings.ToLower(h.Hostname), "iphone") ||
		strings.Contains(strings.ToLower(h.OS), "android") ||
		strings.Contains(strings.ToLower(h.OS), "ios") {
		return "📱"
	}

	// Check for television indicators
	if strings.Contains(strings.ToLower(h.Hostname), "tv") ||
		strings.Contains(strings.ToLower(h.Hostname), "smarttv") ||
		strings.Contains(strings.ToLower(h.OS), "tizen") ||
		strings.Contains(strings.ToLower(h.OS), "webos") ||
		strings.Contains(strings.ToLower(h.OS), "roku") {
		return "📺"
	}

	// Check for router/switch indicators
	if strings.Contains(strings.ToLower(h.Hostname), "router") ||
		strings.Contains(strings.ToLower(h.Hostname), "gateway") ||
		strings.Contains(strings.ToLower(h.Hostname), "switch") ||
		strings.Contains(strings.ToLower(h.Hostname), "ap") ||
		strings.Contains(strings.ToLower(h.OS), "router") ||
		strings.Contains(strings.ToLower(h.OS), "linux") && len(h.Ports) > 5 { // Heuristic: many ports might indicate router
		// Additional check for common router vendors in MAC (we don't have vendor parsed, but we can check MAC prefixes later)
		return "🖧"
	}

	// Check for computer indicators
	if strings.Contains(strings.ToLower(h.Hostname), "computer") ||
		strings.Contains(strings.ToLower(h.Hostname), "pc") ||
		strings.Contains(strings.ToLower(h.Hostname), "mac") ||
		strings.Contains(strings.ToLower(h.Hostname), "windows") ||
		strings.Contains(strings.ToLower(h.OS), "windows") ||
		strings.Contains(strings.ToLower(h.OS), "macos") ||
		strings.Contains(strings.ToLower(h.OS), "linux") && !strings.Contains(strings.ToLower(h.Hostname), "tv") {
		return "💻"
	}

	// Default to unknown
	return "❓"
}

// parseNmapOutput parses the text output of nmap -sV -F
func parseNmapOutput(output string) []Host {
	var hosts []Host
	var currentHost *Host
	inPorts := false

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Skip empty lines
		if trimmed == "" {
			inPorts = false
			continue
		}

		// New host entry
		if strings.HasPrefix(trimmed, "Nmap scan report for") {
			if currentHost != nil {
				hosts = append(hosts, *currentHost)
			}
			currentHost = &Host{}
			inPorts = false

			// Extract hostname and IP
			// Format: "Nmap scan report for hostname (ip)" or "Nmap scan report for ip"
			parts := strings.Split(trimmed, " ")
			if len(parts) >= 5 {
				// Check if last part is parentheses
				lastPart := parts[len(parts)-1]
				if strings.HasPrefix(lastPart, "(") && strings.HasSuffix(lastPart, ")") {
					currentHost.Hostname = strings.Join(parts[4:len(parts)-1], " ")
					currentHost.IP = strings.Trim(lastPart, "()")
				} else {
					currentHost.Hostname = "" // No hostname provided
					currentHost.IP = strings.Join(parts[4:], " ")
				}
			}
			continue
		}

		if currentHost == nil {
			continue
		}

		// MAC address
		if strings.HasPrefix(trimmed, "MAC Address:") {
			// Format: "MAC Address: AA:BB:CC:DD:EE:FF (Vendor)"
			macParts := strings.Split(trimmed, " ")
			if len(macParts) >= 3 {
				currentHost.MAC = macParts[2]
				// Optionally extract vendor from parentheses
			}
			continue
		}

		// OS detection from Service Info
		if strings.HasPrefix(trimmed, "Service Info:") {
			// Format: "Service Info: OS: OS; CPE: ..."
			osMatch := regexp.MustCompile(`OS: ([^;]+)`).FindStringSubmatch(trimmed)
			if len(osMatch) >= 2 {
				currentHost.OS = strings.TrimSpace(osMatch[1])
			}
			// Also extract version/service info
			versionMatch := regexp.MustCompile(`Service Info: (.+)`).FindStringSubmatch(trimmed)
			if len(versionMatch) >= 2 {
				fullInfo := strings.TrimSpace(versionMatch[1])
				// Extract just the service/version part after OS
				if osPart := regexp.MustCompile(`OS: [^;]+`).FindString(fullInfo); osPart != "" {
					serviceInfo := strings.TrimPrefix(fullInfo, osPart)
					serviceInfo = strings.Trim(serviceInfo, "; ")
					if serviceInfo != "" {
						currentHost.Version = serviceInfo
					}
				} else {
					currentHost.Version = fullInfo
				}
			}
			continue
		}

		// Port header
		if strings.HasPrefix(trimmed, "PORT") && strings.Contains(trimmed, "STATE") {
			inPorts = true
			continue
		}

		// Port entries
		if inPorts && currentHost != nil {
			// Format: "22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)"
			if strings.Contains(trimmed, "/tcp") || strings.Contains(trimmed, "/udp") {
				portParts := strings.Fields(trimmed)
				if len(portParts) >= 2 {
					currentHost.Ports = append(currentHost.Ports, portParts[0])
				}
			}
			continue
		}
	}

	// Add the last host
	if currentHost != nil {
		hosts = append(hosts, *currentHost)
	}

	return hosts
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

	// Parse output
	// Newer btmgmt versions output MAC and name on different lines:
	// hci0 dev_found: F8:3F:51:78:BB:09 type LE Public rssi -79 flags 0x0020
	// name [TV] Samsung 6 Series (55)

	macRegex := regexp.MustCompile(`(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}`)
	var currentMAC string

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "name ") {
			if currentMAC != "" {
				name := strings.TrimSpace(strings.TrimPrefix(line, "name "))
				if name != "" {
					btMap[strings.ToLower(currentMAC)] = name
				}
			}
		} else if strings.Contains(line, "name:") {
			// Old format fallback: "[hci0] ... 11:22:33... name: MyPhone"
			mac := macRegex.FindString(line)
			if mac != "" {
				parts := strings.SplitN(line, "name:", 2)
				if len(parts) == 2 {
					name := strings.TrimSpace(parts[1])
					if name != "" {
						btMap[strings.ToLower(mac)] = name
					}
				}
			}
		} else {
			// Update current MAC from dev_found or similar lines
			mac := macRegex.FindString(line)
			if mac != "" {
				currentMAC = mac
			}
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
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil || ip.IsLoopback() {
			continue
		}
		if ipv4 := ip.To4(); ipv4 != nil {
			// Assume /24 subnet
			return fmt.Sprintf("%s.0/24", strings.Join(strings.Split(ipv4.String(), ".")[:3], "."))
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
		logStep("Starting quick ping sweep on %s...", target)

		// Run nmap ping sweep to find live hosts quickly (XML output for robust parsing)
		cmd := exec.Command("nmap", "-sn", "-oX", "-", target)
		output, err := cmd.CombinedOutput()
		if err != nil {
			nmapErr = fmt.Errorf("Error running nmap ping sweep: %v", err)
			return
		}

		type NmapRun struct {
			XMLName xml.Name `xml:"nmaprun"`
			Hosts   []struct {
				Status struct {
					State string `xml:"state,attr"`
				} `xml:"status"`
				Addresses []struct {
					Addr string `xml:"addr,attr"`
					Type string `xml:"addrtype,attr"`
				} `xml:"address"`
			} `xml:"host"`
		}

		var run NmapRun
		if err := xml.Unmarshal(output, &run); err != nil {
			nmapErr = fmt.Errorf("Error parsing nmap XML output: %v", err)
			return
		}

		var ips []string
		for _, host := range run.Hosts {
			if host.Status.State == "up" {
				for _, addr := range host.Addresses {
					if addr.Type == "ipv4" {
						ips = append(ips, addr.Addr)
						break
					}
				}
			}
		}

		if len(ips) == 0 {
			logStep("No live hosts found in ping sweep.")
			return
		}

		logStep("Found %d live hosts. Starting deep scan on them...", len(ips))

		// Run detailed scan only on live IPs
		args := []string{"-sV", "--open", "-F"}
		args = append(args, ips...)
		cmd = exec.Command("nmap", args...)
		output, err = cmd.CombinedOutput()
		if err != nil {
			nmapErr = fmt.Errorf("Error running detailed nmap scan: %v\nOutput: %s", err, string(output))
			return
		}

		hosts = parseNmapOutput(string(output))
		logStep("Found %d hosts with open ports", len(hosts))
	}()

	go func() {
		defer wg.Done()
		// Get Bluetooth devices
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
			hosts = append(hosts, Host{
				IP:            "BT only",
				MAC:           strings.ToUpper(mac),
				Version:       btName,
				BluetoothName: "", // Clear this so it doesn't print a second line
			})
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
		fmt.Printf("%-15s %-17s %-10s %-25s %-25s %s\n",
			h.IP,
			h.MAC,
			h.OS,
			portsStr,
			versionStr,
			deviceTypeEmoji(h))
		// Print Bluetooth name below if available
		if h.BluetoothName != "" {
			fmt.Printf("%-15s %-17s %-10s %-25s %-25s\n", "", "", "", "", h.BluetoothName)
		}
	}
}
