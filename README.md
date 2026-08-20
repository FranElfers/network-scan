# Network Device Scanner

Ultra-lightweight CLI scanner in Go. Map your local network (nmap) and Bluetooth devices (btmgmt), identifying each device with emojis according to its MAC and Operating System.

## Features

- Scans local network using `nmap`
- Detects Bluetooth devices using `btmgmt`
- Matches Bluetooth MAC addresses with network scan results
- Displays IP address, MAC address, hostname, OS, version info, and open ports
- Auto-detects local network when possible

## Requirements

- Go 1.16+ (tested with 1.27.0)
- nmap installed and accessible in PATH
- Bluetooth adapter with btmgmt utility (BlueZ stack)
- sudo privileges for Bluetooth scanning

## Installation

1. Clone or download this repository
2. Install Go if not already installed
3. Ensure nmap is installed (`sudo apt-get install nmap` on Ubuntu/Debian)
4. Ensure Bluetooth utilities are installed (`sudo apt-get install bluetooth bluez` on Ubuntu/Debian)
5. Build the program:

```bash
go build main.go
```

## Usage

### Basic Usage

Run without arguments to auto-detect your local network:

```bash
./main
```

Or specify a target network/CIDR:

```bash
./main 192.168.1.0/24
```

### Example Output

```
IP              MAC               Hostname             OS              Ports                Version                                 Device
---             ---               --------             --              -----                -------                                 -----
192.168.1.1     AA:BB:CC:DD:EE:FF gateway              Linux           22/tcp,80/tcp      http config (microhttpd)            🖧
192.168.1.100   11:22:33:44:55:66 myphone              Android         80/tcp,443/tcp      Android SDK built for x86           📱
                    (Bluetooth: MyPhone)
192.168.1.101   AA:BB:CC:DD:EE:00 DESKTOP-ABC123       Windows 10      135/tcp,139/tcp     Microsoft Windows                     💻
192.168.1.47    AA:BB:CC:DD:EE:99 EPSON023180          (no OS)         80/tcp              Epson Stylus NX230 printer UPnP       📺
                    (Bluetooth: EPSON Printer)
```

## Notes

- Scan time depends on network size and nmap options
- Bluetooth detection requires a working Bluetooth adapter and proper permissions
- Device detection is heuristic-based and may not be 100% accurate
- For best results, run on your local network segment
