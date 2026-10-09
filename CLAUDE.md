# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Single-file Go CLI (`main.go`, tests in `main_test.go`); the only dependency is `github.com/Ullaakut/nmap/v3`. No linter config.

- Build: `go build .` (produces `./network-scan`, named after the module)
- Run: `sudo ./network-scan [-mac] [-v] [CIDR]` (exits early if not root)
- Test: `go test .` (pure parsers/heuristics only; nothing touches the network)
- Vet/format: `go vet .` / `gofmt -l .`

Runtime needs `nmap`, and optionally `btmgmt` + `script` for Bluetooth. If `btmgmt` isn't on PATH, Bluetooth is silently skipped. The program refuses to run without root: nmap needs it for MAC addresses (ARP) and `-O`. Linux-only: routing info comes from `/proc/net/route`.

## Architecture

`main()` runs two goroutines concurrently and joins them with a `sync.WaitGroup`:

1. **Network scan** (`scanNetwork`): one nmap run (discovery + service scan, `-n`) through the `Ullaakut/nmap` library, mapped into `[]Host`. OS and Version come from the first open port's `ostype`/`product`/`version` service attributes; OS falls back to the top `-O` match, whose class type (phone/router/media device) feeds `deviceTypeEmoji`. `resolveNames` then fills `Name` per host (in parallel, 1.5s UDP timeout each) via unicast mDNS reverse-PTR to port 5353, falling back to a NetBIOS node-status query; hosts are then sorted by IP and the default gateway flagged. Errors go through the shared `nmapErr`.
2. **Bluetooth scan** (`getBluetoothDevices`): runs `btmgmt find` wrapped in `script -q -c ... /dev/null` to get a PTY (so btmgmt line-buffers), killed after a 10s context timeout; the timeout is the *expected* exit path, so output is parsed even on kill. Parses the two-line format (`dev_found` line, then `name ...` line); the old single-line `name:` format is not supported. Returns `map[lowercase MAC]name`.

Network I/O and parsing are split (`mdnsName`/`parseMDNSPTR`, `netbiosName`/`parseNBStat`, `getBluetoothDevices`/`parseBtmgmt`, `defaultRoute`/`parseDefaultRoute`) so the parsers are unit-testable; keep that split when adding probes.

After the join, hosts print as a table and BT devices as a separate `📡 Bluetooth` list sorted by name. There is deliberately no BT↔host join: Bluetooth MACs never match a phone/watch's Wi-Fi MAC. `deviceTypeEmoji` classifies via substring heuristics on OS/port count — order of the cases matters (default gateway from `/proc/net/route` → phone → TV → RTSP port 554 as camera → router (incl. 53/tcp) → computer → randomized MAC as `📱?`). Table cells are truncated with `fit` to keep columns aligned.

## Gotchas

- The `-v` flag is inverted: it **disables** the `[*]` step logs (on by default).
- The MAC column is hidden unless `-mac` is passed (MACs are still used internally for `📱?`).
- `getLocalNetwork` prefers the default-route interface (falls back to the first up, non-loopback IPv4 one) and clamps subnets larger than `/24` to the `/24` around the host IP, so a `/16` LAN is only partially scanned unless a CIDR is passed.
