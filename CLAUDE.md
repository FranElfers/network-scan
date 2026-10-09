# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Single-file Go CLI (`main.go`); the only dependency is `github.com/Ullaakut/nmap/v3`. No linter config.

- Build: `go build .` (produces `./network-scan`, named after the module)
- Run: `sudo ./network-scan [CIDR]` (exits early if not root) (auto-detects the first non-loopback IPv4 interface as `/24` if omitted)
- Vet/format: `go vet .` / `gofmt -l .`

Runtime needs `nmap`, and optionally `btmgmt` + `script` for Bluetooth. If `btmgmt` isn't on PATH, Bluetooth is silently skipped. The program refuses to run without root: nmap needs it for MAC addresses (ARP) and `-O`. MACs are the only key used to join Bluetooth results to hosts.

## Architecture

`main()` runs two goroutines concurrently and joins them with a `sync.WaitGroup`:

1. **Network scan** (`scanNetwork`): one nmap run (discovery + service scan, `-n`) through the `Ullaakut/nmap` library, mapped into `[]Host`. OS and Version come from the first open port's `ostype`/`product`/`version` service attributes; OS falls back to the top `-O` match, whose class type (phone/router/media device) feeds `deviceTypeEmoji`. `resolveNames` then fills `Name` per host via unicast mDNS reverse-PTR to port 5353, falling back to a NetBIOS node-status query. Errors go through the shared `nmapErr`.
2. **Bluetooth scan** (`getBluetoothDevices`): runs `btmgmt find` wrapped in `script -q -c ... /dev/null` to get a PTY (so btmgmt line-buffers), killed after a 10s context timeout; the timeout is the *expected* exit path, so output is parsed even on kill. Parses the two-line format (`dev_found` line, then `name ...` line); the old single-line `name:` format is not supported. Returns `map[lowercase MAC]name`.

After the join, BT names are matched to hosts by lowercase MAC; unmatched BT devices are appended as `Host{IP: "BT only"}` rows. `deviceTypeEmoji` classifies via substring heuristics on OS/port count — order of the cases matters (default gateway from `/proc/net/route` → phone → TV → RTSP port 554 as camera → router (incl. 53/tcp) → computer → randomized MAC as `📱?`). Table cells are truncated with `fit` to keep columns aligned.

## Gotchas

- The `-v` flag is inverted: it **disables** the `[*]` step logs (on by default).
- The README example output is stale (shows a Hostname column; hostnames are no longer parsed since the scan uses `-n`).
- `getLocalNetwork` just takes the first non-loopback IPv4 address; pass the CIDR explicitly on multi-homed machines (docker/VPN interfaces can win).
