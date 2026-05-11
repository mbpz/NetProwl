# NetProwl Probe Agent · Design Spec

**Date**: 2025-05-11
**Version**: v1.0
**Status**: Approved

## 1. Overview

Probe Agent (`netprowl-agent`) is a Go single-binary LAN scanner that runs on user-controlled devices (NAS, Raspberry Pi, PC/Mac). It discovers devices, grabs banners, infers service types, and streams results to the NetProwl WeChat mini-program via WebSocket.

Target platforms: Linux (amd64, arm64, armv7), macOS (amd64, arm64), Windows (amd64).

## 2. Architecture

### Communication Flow

```
Mini-program                        Probe Agent
    │                                    │
    │──── mDNS discovery ──────────────► │ (broadcasts _netprowl._tcp)
    │◄──── device info ─────────────────│
    │                                    │
    │====== WebSocket (TLS + PIN) ======│
    │                                    │
    │──── { cmd: "start_scan" } ────────►│
    │◄──── { event: "device_found" } ────│ (stream)
    │◄──── { event: "port_open" } ───────│ (stream)
    │◄──── { event: "scan_complete" } ────│
    │                                    │
    │──── { cmd: "get_devices" } ────────►│
    │◄──── { devices: [...] } ────────────│
```

### Self-Discovery

1. Agent starts → registers mDNS service (`_netprowl._tcp`) on LAN
2. Mini-program calls `wx.startLocalServiceDiscovery({ serviceType: "_netprowl._tcp" })`
3. Agent responds with host:port
4. Mini-program connects WebSocket (TLS + 6-digit PIN shown at agent startup)

### Configuration (config.yaml / env vars)

```yaml
port: 9787
tls_cert: ./cert.pem
tls_key: ./key.pem
scan_concurrency: 200
mDNS:
  service_type: "_netprowl._tcp"
  broadcast_interval: 30s
```

## 3. Data Model

```go
type Device struct {
    IP        string    `json:"ip"`
    MAC       string    `json:"mac"`
    Hostname  string    `json:"hostname"`
    Vendor    string    `json:"vendor"`   // OUI lookup
    OS        string    `json:"os"`      // inferred from TTL
    Ports     []Port    `json:"ports"`
    FirstSeen time.Time `json:"first_seen"`
    LastSeen  time.Time `json:"last_seen"`
}

type Port struct {
    Number     uint16  `json:"number"`
    Protocol   string  `json:"protocol"`  // tcp/udp
    State      string  `json:"state"`    // open/closed/filtered
    Service    string  `json:"service"`  // inferred
    Banner     string  `json:"banner"`   // raw banner text
    BannerHash string  `json:"banner_hash"` // SHA256 for cache key
}

type ScanRequest struct {
    ID        string   `json:"id"`
    IPRange   string   `json:"ip_range"`  // "192.168.1.0/24"
    Ports     []uint16 `json:"ports"`
    Timeout   int      `json:"timeout_ms"`
}
```

## 4. Command Protocol (WebSocket JSON)

**Mini-program → Agent**:
```json
{ "cmd": "start_scan", "id": "uuid", "ip_range": "192.168.1.0/24", "ports": [80,443,554,5000], "timeout_ms": 2000 }
{ "cmd": "stop_scan",  "id": "uuid" }
{ "cmd": "get_devices" }
{ "cmd": "get_banner", "ip": "192.168.1.1", "port": 554 }
```

**Agent → Mini-program**:
```json
{ "event": "device_found",  "request_id": "uuid", "data": { Device } }
{ "event": "port_open",     "request_id": "uuid", "data": { ip, port, banner, banner_hash } }
{ "event": "scan_complete", "request_id": "uuid", "data": { devices_found: 12, duration_ms: 5432 } }
{ "event": "error",        "request_id": "uuid", "data": { "message": "..." } }
```

## 5. Banner Hash Caching

- `banner_hash = SHA256(raw_banner_text)`
- SQLite cache stores parsed results keyed by hash
- Duplicate banners return cached `software`, `version`, `os`, `known_cves` directly
- Avoids re-grab on repeated scans of same device
- Cache TTL: 7 days

## 6. Project Structure

```
netprowl-agent/
├── cmd/agent/main.go          # entry point, flag parsing, config loading
├── internal/
│   ├── agent/agent.go         # Agent struct, WebSocket handler, command router
│   ├── scanner/
│   │   ├── scanner.go         # ScanManager, queue, concurrency control
│   │   ├── tcp.go            # TCP port scanner
│   │   ├── mdns.go           # mDNS service registration + broadcast
│   │   └── banner.go         # Banner grabber with protocol-specific read
│   ├── discovery/
│   │   └── oui.go            # MAC OUI vendor lookup (~800KB embedded db)
│   ├── cache/
│   │   └── sqlite.go         # SQLite banner cache + parsed results
│   └── types/
│       └── types.go          # Device, Port, ScanRequest types
├── pkg/proto/
│   └── messages.go           # JSON message definitions
├── config.yaml
├── go.mod
└── Makefile                  # cross-compile: amd64/arm64/armv7
```

## 7. Concurrency Model

- `ScanManager` holds semaphore channel (size = `scan_concurrency`)
- Each TCP connect runs in goroutine, result pushed to result channel
- Banner grabber runs after port confirmed open — sequential per device
- mDNS broadcast runs in own goroutine, refreshes every 30s

## 8. Cross-Compilation Targets

```make
netprowl-agent-linux-amd64    # x86_64 Linux
netprowl-agent-linux-arm64     # ARM64 Linux (NAS, modern Pi)
netprowl-agent-linux-armv7     # ARMv7 Raspberry Pi
netprowl-agent-darwin-amd64   # x86_64 macOS
netprowl-agent-darwin-arm64   # Apple Silicon macOS
netprowl-agent-windows-amd64.exe
```

## 9. SQLite Schema

```sql
CREATE TABLE banner_cache (
    banner_hash  TEXT PRIMARY KEY,
    raw_banner   TEXT,
    software     TEXT,
    version      TEXT,
    os           TEXT,
    cves         TEXT,      -- JSON array
    confidence   REAL,
    cached_at    DATETIME
);
```

## 10. Phase Integration

| Phase | Capability | Agent Support |
|-------|-----------|---------------|
| Phase 1 | LAN device discovery | Full (TCP scan, mDNS) |
| Phase 2 | Service fingerprint + Banner grab | Full |
| Phase 3 | Weak credential detection | Full (HTTP Basic Auth, default passwords) |
| Phase 3 | TLS/SSL audit | Full (cert inspection, cipher detection) |
| Phase 4 | Full port scan (including blocked ports) | Full (only via agent, bypasses mini-program limits) |

## 11. Out of Scope for Phase 1

- Weak credential detection (Phase 3)
- TLS auditing (Phase 3)
- Attack chain reasoning (AI layer, not agent)
- Cloud backend proxy (Shodan/FOFA, handled by cloud service)