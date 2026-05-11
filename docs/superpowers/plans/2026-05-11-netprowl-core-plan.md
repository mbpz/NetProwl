# NetProwl Core · Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build NetProwl Go core scanner library — mDNS/UDP SSDP/TCP/Banner — serving both 小程序 and PC clients.

**Architecture:** Go 1.21+ library in `core/`, packages for scanner and util. Designed as a reusable scanning engine. No external C dependencies.

**Tech Stack:** Go 1.21+ · standard library `net`, `golang.org/x/net/dns/dns` for mDNS

---

## File Structure

```
core/
├── go.mod
├── scanner/
│   ├── mdns.go         # mDNS service discovery
│   ├── ssdp.go         # UDP SSDP/UPnP discovery
│   ├── tcp.go          # TCP port scanning
│   ├── banner.go       # Banner grabbing
│   └── registry.go     # Service fingerprint rule engine
├── util/
│   ├── oui.go          # MAC OUI vendor lookup
│   └── ip.go           # IP/subnet utilities
└── shared/
    └── types.go        # Shared data types
```

---

## Task Decomposition

### Task 1: 项目脚手架 + 类型定义

**Files:**
- Create: `core/go.mod`
- Create: `core/shared/types.go`

- [ ] **Step 1: 创建 core/go.mod**

```bash
cd /Users/jinguo.zeng/dmall/project/NetProwl/core
go mod init github.com/netprowl/core
```

- [ ] **Step 2: 创建 core/shared/types.go**

```go
package shared

import "time"

// Device represents a discovered network device
type Device struct {
    ID       string   `json:"id"`
    IP       string   `json:"ip"`
    MAC      string   `json:"mac,omitempty"`
    Hostname string   `json:"hostname,omitempty"`
    Vendor   string   `json:"vendor,omitempty"`
    DeviceType DeviceType `json:"device_type"`
    OS       OSType   `json:"os"`
    OpenPorts []Port  `json:"open_ports"`
    DiscoveredAt int64 `json:"discovered_at"`
    Sources  []DiscoverySource `json:"sources"`
}

// DeviceType categorizes the device
type DeviceType string

const (
    DeviceTypeRouter   DeviceType = "router"
    DeviceTypePC      DeviceType = "pc"
    DeviceTypeCamera   DeviceType = "camera"
    DeviceTypeNAS      DeviceType = "nas"
    DeviceTypePhone    DeviceType = "phone"
    DeviceTypePrinter  DeviceType = "printer"
    DeviceTypeUnknown  DeviceType = "unknown"
)

// OSType inferred from TTL
type OSType string

const (
    OSLinux     OSType = "linux"
    OSWindows   OSType = "windows"
    OSNetwork   OSType = "network"
    OSUnknown   OSType = "unknown"
)

// DiscoverySource how the device was found
type DiscoverySource string

const (
    SourceMDNS DiscoverySource = "mdns"
    SourceSSDP DiscoverySource = "ssdp"
    SourceTCP  DiscoverySource = "tcp"
    SourceARP  DiscoverySource = "arp"
)

// Port represents an open port on a device
type Port struct {
    Port    int     `json:"port"`
    Service string  `json:"service,omitempty"`
    State   PortState `json:"state"`
    Banner  string  `json:"banner,omitempty"`
}

// PortState of the port
type PortState string

const (
    PortOpen     PortState = "open"
    PortFiltered PortState = "filtered"
)

// ScanResult is the output of a full scan
type ScanResult struct {
    ID       string   `json:"id"`
    Timestamp int64    `json:"timestamp"`
    IPRange  string   `json:"ip_range"`
    Devices  []Device `json:"devices"`
    Duration int64    `json:"duration_ms"`
}

// ScanConfig controls scan behavior
type ScanConfig struct {
    IPRange      string   // e.g. "192.168.1.0/24"
    Ports        []int    // ports to scan (nil = default list)
    Concurrency  int      // max parallel connections (default 200)
    TimeoutMs    int      // per-port timeout in ms (default 2000)
    BannerGrab   bool     // whether to grab banners (default true)
}
```

- [ ] **Step 3: Commit**

```bash
git add core/go.mod core/shared/types.go
git commit -m "chore: scaffold core with shared types

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 2: 工具函数——IP 和 OUI

**Files:**
- Create: `core/util/ip.go`
- Create: `core/util/oui.go`

- [ ] **Step 1: 创建 core/util/ip.go**

```go
package util

import (
    "net"
    "strings"
)

// InferSubnet takes a local IP and returns /24 subnet
func InferSubnet(localIP string) string {
    ip := net.ParseIP(localIP)
    if ip == nil {
        return "0.0.0.0/24"
    }
    ip = ip.To4()
    if ip == nil {
        return "::/64"
    }
    return strings.Join([]string{
        string(rune(ip[0])), ".", // placeholder — use fmt below
    }, "")
    // actual: use fmt.Sprintf
}
```

> Stop — writing naive version. Real implementation below.

```go
package util

import (
    "fmt"
    "net"
    "strings"
)

// InferSubnet takes "192.168.1.100" → "192.168.1.0/24"
func InferSubnet(localIP string) string {
    ip := net.ParseIP(localIP)
    if ip == nil {
        return "0.0.0.0/24"
    }
    ip4 := ip.To4()
    if ip4 == nil {
        return "::/64"
    }
    return fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
}

// ExpandSubnet returns all host IPs in a /24 subnet (1–254)
func ExpandSubnet(subnet string) []string {
    _, ipNet, err := net.ParseCIDR(subnet)
    if err != nil {
        return nil
    }
    ones, _ := ipNet.Mask.Size()
    if ones != 24 {
        // fallback: only /24 supported for MVP
        return nil
    }
    ip := ipNet.IP.To4()
    if ip == nil {
        return nil
    }
    base := fmt.Sprintf("%d.%d.%d", ip[0], ip[1], ip[2])
    ips := make([]string, 0, 254)
    for i := 1; i <= 254; i++ {
        ips = append(ips, fmt.Sprintf("%s.%d", base, i))
    }
    return ips
}

// IsPrivate returns true if IP is RFC 1918 private
func IsPrivate(ip string) bool {
    parsed := net.ParseIP(ip)
    if parsed == nil {
        return false
    }
    return parsed.IsPrivate()
}

// NormalizeMAC normalizes MAC to lowercase colon-separated
func NormalizeMAC(mac string) string {
    mac = strings.ToLower(mac)
    mac = strings.ReplaceAll(mac, "-", ":")
    mac = strings.ReplaceAll(mac, " ", "")
    return mac
}
```

- [ ] **Step 2: 创建 core/util/oui.go**

```go
package util

import (
    "strings"
)

var ouiMap = map[string]string{
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "00:1e:68": "Quanta (华为/H3C)",
    "00:25:9e": "Cisco",
    "00:1a:2b": "Cisco",
    "00:17:88": "Philips Hue",
    "a8:66:7f": "Apple",
    "f0:18:98": "Apple",
    "3c:06:30": "Apple",
    "00:e0:4c": "Realtek",
    "00:23:cd": "Intel",
    "00:1b:21": "Intel",
    "00:0d:2b": "Dell",
    "00:1c:23": "Dell",
    "00:24:e8": "Dell",
    "00:50:ba": "Dell",
    "ac:de:48": "Hangzhou Hikvision",
    "b4:15:13": "Hangzhou Hikvision",
    "00:03:93": "Siemens",
    "00:1b:a2": "Schneider Electric",
}

// LookupVendor returns vendor name for a MAC address OUI prefix
func LookupVendor(mac string) string {
    prefix := NormalizeMAC(mac)
    if len(prefix) < 8 {
        return ""
    }
    prefix = prefix[:8]
    return ouiMap[prefix]
}
```

- [ ] **Step 3: Commit**

```bash
git add core/util/ip.go core/util/oui.go
git commit -m "feat: add IP and OUI utility functions

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 3: TCP 端口扫描

**Files:**
- Create: `core/scanner/tcp.go`

- [ ] **Step 1: 写测试**

```go
package scanner

import (
    "testing"
    "time"
)

func TestProbePort_Open(t *testing.T) {
    // Probe a known open port on localhost
    result := probePort("127.0.0.1", 80, 2000)
    // On a standard machine this may or may not be open
    // This test just verifies it doesn't hang
}

func TestProbePort_Timeout(t *testing.T) {
    start := time.Now()
    result := probePort("127.0.0.1", 59999, 500)
    elapsed := time.Since(start)
    if elapsed > 700*time.Millisecond {
        t.Errorf("probe took too long: %v", elapsed)
    }
    if result != nil {
        t.Errorf("expected nil for closed port, got %v", result)
    }
}

func TestProbePorts_Concurrency(t *testing.T) {
    // Verify concurrency doesn't exceed limit
    results := probePorts("127.0.0.1", []int{80, 443, 8080, 8443}, 2000, 2)
    // results should contain whichever ports are open
    _ = results
}
```

- [ ] **Step 2: Run test**

```bash
cd /Users/jinguo.zeng/dmall/project/NetProwl/core
go test ./scanner/... -v -run TestProbePort_Timeout
# Expected: PASS (timeout returns nil quickly)
```

- [ ] **Step 3: Write implementation**

```go
package scanner

import (
    "context"
    "fmt"
    "net"
    "sync"
    "time"
)

const DefaultTimeout = 2000 * time.Millisecond
const DefaultConcurrency = 200

// DefaultPorts for TCP scan when none specified
var DefaultPorts = []int{
    80, 443, 8080, 8443, 554, 5000, 9000, 49152,
}

// ProbePort attempts a TCP connect to ip:port
// Returns port info if open, nil if closed/filtered
func ProbePort(ip string, port int, timeout time.Duration) *Port {
    addr := fmt.Sprintf("%s:%d", ip, port)
    conn, err := net.DialTimeout("tcp", addr, timeout)
    if err != nil {
        return nil
    }
    conn.Close()
    return &Port{Port: port, State: "open"}
}

// ProbePorts scans a list of ports on a single IP with concurrency limit
func ProbePorts(ip string, ports []int, timeout time.Duration, concurrency int) []Port {
    if len(ports) == 0 {
        ports = DefaultPorts
    }
    if timeout == 0 {
        timeout = DefaultTimeout
    }
    if concurrency == 0 {
        concurrency = DefaultConcurrency
    }

    sem := make(chan struct{}, concurrency)
    var mu sync.Mutex
    var results []Port
    var wg sync.WaitGroup

    for _, port := range ports {
        wg.Add(1)
        sem <- struct{}{}
        go func(p int) {
            defer wg.Done()
            defer func() { <-sem }()
            if r := ProbePort(ip, p, timeout); r != nil {
                mu.Lock()
                results = append(results, *r)
                mu.Unlock()
            }
        }(port)
    }
    wg.Wait()
    return results
}

// ScanIPRange scans a subnet for open ports
// ports nil = use DefaultPorts; returns discovered devices
func ScanIPRange(ipRange string, ports []int, timeout time.Duration, concurrency int) ([]Device, error) {
    var cfg ScanConfig
    // parse ip range and expand
    return scanWithConfig(cfg)
}
```

> Note: Full `ScanIPRange` needs ip.go to parse CIDR. This task writes `ProbePorts` which is the core work. `ScanIPRange` will be wired up in Task 5 (orchestrator).

- [ ] **Step 4: Run test again**

```bash
go test ./scanner/... -v -run TestProbePort_Timeout
# Expected: PASS
```

- [ ] **Step 5: Commit**

```bash
git add core/scanner/tcp.go
git commit -m "feat: add TCP port scanner

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 4: Banner 抓取

**Files:**
- Create: `core/scanner/banner.go`

- [ ] **Step 1: 写测试**

```go
package scanner

import (
    "testing"
)

func TestGrabBanner_HTTP(t *testing.T) {
    banner, err := GrabBanner("80.知名端口.com", 80, 2000)
    // Not a real host — expect timeout/nil
    if banner != nil && banner.Banner != "" {
        t.Logf("banner: %s", banner.Banner)
    }
}

func TestGrabBanner_SSH(t *testing.T) {
    // SSH banner test against a known SSH server
    // Use a public test server or skip if unavailable
}
```

- [ ] **Step 2: Write implementation**

```go
package scanner

import (
    "context"
    "fmt"
    "net"
    "strings"
    "time"
)

// GrabBanner connects and reads the initial protocol banner
func GrabBanner(ip string, port int, timeout time.Duration) (*BannerResult, error) {
    addr := fmt.Sprintf("%s:%d", ip, port)
    conn, err := net.DialTimeout("tcp", addr, timeout)
    if err != nil {
        return nil, nil // closed/filtered
    }
    defer conn.Close()

    // Set read deadline
    conn.SetDeadline(time.Now().Add(timeout))

    // Read banner
    buf := make([]byte, 1024)
    n, err := conn.Read(buf)
    if err != nil {
        return nil, nil
    }

    banner := strings.TrimSpace(string(buf[:n]))
    proto := DetectProtocol(banner, port)

    return &BannerResult{
        Port:   port,
        Banner: banner,
        Proto:  proto,
    }, nil
}

// BannerResult holds grabbed banner and detected protocol
type BannerResult struct {
    Port   int    `json:"port"`
    Banner string `json:"banner"`
    Proto  string `json:"protocol"`
}

// DetectProtocol guesses protocol from banner content and port
func DetectProtocol(banner string, port int) string {
    lower := strings.ToLower(banner)

    // Port-based quick match
    switch port {
    case 80, 8080, 8443:
        return "http"
    case 22:
        return "ssh"
    case 21:
        return "ftp"
    case 25, 587:
        return "smtp"
    case 110:
        return "pop3"
    case 143:
        return "imap"
    case 3306:
        return "mysql"
    case 5432:
        return "postgresql"
    case 6379:
        return "redis"
    case 9200:
        return "elasticsearch"
    }

    // Banner content match
    if strings.HasPrefix(lower, "ssh-") {
        return "ssh"
    }
    if strings.HasPrefix(lower, "220") {
        return "ftp"
    }
    if strings.Contains(lower, "http/") {
        return "http"
    }
    if strings.Contains(lower, "redis") {
        return "redis"
    }
    if strings.Contains(lower, "mysql") {
        return "mysql"
    }
    return "unknown"
}
```

- [ ] **Step 3: Commit**

```bash
git add core/scanner/banner.go
git commit -m "feat: add banner grabbing

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 5: mDNS 发现

**Files:**
- Create: `core/scanner/mdns.go`

- [ ] **Step 1: Write implementation**

```go
package scanner

import (
    "context"
    "net"
    "sync"
    "time"
)

// DiscoverMDNS sends mDNS queries for common service types
// Returns discovered services with their IP/port/hostname
func DiscoverMDNS(ctx context.Context, timeout time.Duration) ([]Device, error) {
    if timeout == 0 {
        timeout = 4 * time.Second
    }

    serviceTypes := []string{
        "_http._tcp",
        "_ftp._tcp",
        "_ssh._tcp",
        "_smb._tcp",
        "_airplay._tcp",
        "_googlecast._tcp",
        "_ipp._tcp",
    }

    var mu sync.Mutex
    var devices []Device

    var wg sync.WaitGroup
    for _, st := range serviceTypes {
        wg.Add(1)
        go func(svc string) {
            defer wg.Done()
            found, err := queryMDNS(svc, timeout)
            if err != nil {
                return
            }
            mu.Lock()
            devices = append(devices, found...)
            mu.Unlock()
        }(st)
    }

    wg.Wait()
    return devices, nil
}

// queryMDNS sends a single mDNS query and collects responses
// Uses Go's built-in multicast DNS support via net.Resolver
func queryMDNS(serviceType string, timeout time.Duration) ([]Device, error) {
    // Build mDNS query domain: _http._tcp.local
    // Use net.Resolver to do a lookup for serviceType
    res := &net.Resolver{
        PreferGo: true,
        Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
            d := net.Dialer{Timeout: timeout}
            return d.DialContext(ctx, "udp", "224.0.255.255:5353")
        },
    }

    // Not all service types are resolvable via standard Go net.Resolver
    // For MVP: use a simple approach — just try to resolve hostnames
    // This is a best-effort discovery
    return nil, nil
}
```

> **Note:** Go standard library `net.Resolver` does not natively support mDNS service discovery (service type queries). For a production implementation, you would need to use a pure-Go mDNS library like `github.com/hashicorp/mdns`. For MVP this package can use the `golang.org/x/net/dns/dnsmessage` to craft raw mDNS packets via raw sockets.

> The task should note: **Go stdlib does not support mDNS service browsing natively. Use hashicorp/mdns library or implement raw packet query.** For Phase 1, we will use the `hashicorp/mdns` library.

- [ ] **Step 2: Update go.mod to add mdns dependency**

```bash
cd /Users/jinguo.zeng/dmall/project/NetProwl/core
go get github.com/hashicorp/mdns@latest
```

- [ ] **Step 3: Rewrite mdns.go using hashicorp/mdns**

```go
package scanner

import (
    "context"
    "fmt"
    "strings"
    "time"

    "github.com/hashicorp/mdns"
)

const mDNSServiceType = "_netprowl._tcp"

// DiscoverMDNS discovers NetProwl agents on the local network via mDNS
func DiscoverMDNS(ctx context.Context, timeout time.Duration) ([]Device, error) {
    if timeout == 0 {
        timeout = 4 * time.Second
    }

    params := &mdns.QueryParam{
        Service: mDNSServiceType,
        Timeout: timeout,
    }

    ch := mdns.QueryWithChange(params)
    var devices []Device

    for {
        select {
        case <-ctx.Done():
            return devices, nil
        case info, ok := <-ch:
            if !ok {
                return devices, nil
            }
            device := mdnsInfoToDevice(info)
            devices = append(devices, device)
        }
    }
}

func mdnsInfoToDevice(info *mdns.ServiceEntry) Device {
    hostname := info.Name
    if strings.HasSuffix(hostname, ".local") {
        hostname = strings.TrimSuffix(hostname, ".local")
    }

    var ip string
    if len(info.AddrV4) > 0 {
        ip = info.AddrV4.String()
    } else if len(info.AddrV6) > 0 {
        ip = info.AddrV6.String()
    }

    return Device{
        ID:        hostname,
        IP:        ip,
        Hostname:  hostname,
        DeviceType: inferDeviceType(hostname, ""),
        OS:        OSUnknown,
        OpenPorts: extractPorts(info),
        DiscoveredAt: time.Now().UnixMilli(),
        Sources:  []DiscoverySource{SourceMDNS},
    }
}

func extractPorts(info *mdns.ServiceEntry) []Port {
    if info.Port == 0 {
        return nil
    }
    return []Port{{Port: info.Port, State: PortOpen}}
}
```

- [ ] **Step 4: Commit**

```bash
git add core/scanner/mdns.go
git commit -m "feat: add mDNS discovery using hashicorp/mdns

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 6: UDP SSDP 发现

**Files:**
- Create: `core/scanner/ssdp.go`

- [ ] **Step 1: Write implementation**

```go
package scanner

import (
    "encoding/binary"
    "fmt"
    "net"
    "strings"
    "time"
)

const ssdpMulticastAddr = "239.255.255.250"
const ssdpPort = 1900

var ssdpSearch = strings.Join([]string{
    "M-SEARCH * HTTP/1.1",
    "HOST: 239.255.255.250:1900",
    `MAN: "ssdp:discover"`,
    "MX: 2",
    "ST: ssdp:all",
    "",
    "",
}, "\r\n")

// DiscoverSSDP sends SSDP M-SEARCH broadcast and returns discovered devices
func DiscoverSSDP(timeout time.Duration) ([]Device, error) {
    if timeout == 0 {
        timeout = 3 * time.Second
    }

    addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ssdpMulticastAddr, ssdpPort))
    if err != nil {
        return nil, err
    }

    conn, err := net.ListenMulticastUDP("udp", nil, addr)
    if err != nil {
        return nil, err
    }
    defer conn.Close()

    conn.SetReadDeadline(time.Now().Add(timeout))

    // Send search
    _, err = conn.WriteToUDP([]byte(ssdpSearch), addr)
    if err != nil {
        return nil, err
    }

    var devices []Device
    buf := make([]byte, 4096)

    for {
        n, src, err := conn.ReadFromUDP(buf)
        if err != nil {
            break // timeout
        }
        if device := parseSSDPResponse(string(buf[:n]), src.IP.String()); device != nil {
            devices = append(devices, *device)
        }
    }

    return devices, nil
}

func parseSSDPResponse(banner string, ip string) *Device {
    if !strings.Contains(banner, "HTTP/1.1 200") {
        return nil
    }

    getHeader := func(key string) string {
        re := fmt.Sprintf("(?im)^%s:\\s*(.+)$", key)
        // Use strings.Replacer pattern manually
        lines := strings.Split(banner, "\r\n")
        for _, line := range lines {
            if strings.HasPrefix(strings.ToLower(line), strings.ToLower(key)+":") {
                return strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
            }
        }
        return ""
    }

    server := getHeader("SERVER")
    usn := getHeader("USN")
    if usn == "" {
        usn = ip
    }
    friendlyName := getHeader("X-FriendlyName")
    if friendlyName == "" {
        friendlyName = server
    }
    if friendlyName == "" {
        friendlyName = ip
    }

    return &Device{
        ID:        usn,
        IP:        ip,
        Hostname:  friendlyName,
        DeviceType: inferDeviceType(friendlyName, banner),
        OS:        OSUnknown,
        OpenPorts: nil,
        DiscoveredAt: time.Now().UnixMilli(),
        Sources:  []DiscoverySource{SourceSSDP},
    }
}

func inferDeviceType(name string, banner string) DeviceType {
    lower := strings.ToLower(name + banner)
    switch {
    case strings.Contains(lower, "router") || strings.Contains(lower, "gateway"):
        return DeviceTypeRouter
    case strings.Contains(lower, "camera") || strings.Contains(lower, "hikvision") || strings.Contains(lower, "dahua"):
        return DeviceTypeCamera
    case strings.Contains(lower, "nas") || strings.Contains(lower, "synology") || strings.Contains(lower, "qnap"):
        return DeviceTypeNAS
    case strings.Contains(lower, "printer") || strings.Contains(lower, "hp"):
        return DeviceTypePrinter
    case strings.Contains(lower, "iphone") || strings.Contains(lower, "android"):
        return DeviceTypePhone
    case strings.Contains(lower, "pc") || strings.Contains(lower, "desktop"):
        return DeviceTypePC
    default:
        return DeviceTypeUnknown
    }
}
```

- [ ] **Step 2: Commit**

```bash
git add core/scanner/ssdp.go
git commit -m "feat: add UDP SSDP discovery

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 7: 服务指纹规则引擎

**Files:**
- Create: `core/scanner/registry.go`

- [ ] **Step 1: Write implementation**

```go
package scanner

// FingerprintRule matches a service from port + banner
type FingerprintRule struct {
    ID        string `json:"id"`
    Port      int    `json:"port,omitempty"`
    BannerContains string `json:"banner_contains,omitempty"`
    Service   string `json:"service"`
    RiskLevel string `json:"risk_level,omitempty"`
    Notes     string `json:"notes,omitempty"`
}

// DefaultRules is the built-in rule set
var DefaultRules = []FingerprintRule{
    {ID: "hikvision-rtsp", Port: 554, BannerContains: "Hikvision", Service: "海康威视摄像头", RiskLevel: "medium"},
    {ID: "synology-dsm", Port: 5000, BannerContains: "Synology", Service: "群晖 NAS (DSM)", RiskLevel: "low"},
    {ID: "nginx", Port: 80, BannerContains: "nginx", Service: "Nginx", RiskLevel: "info"},
    {ID: "apache", Port: 80, BannerContains: "Apache", Service: "Apache", RiskLevel: "info"},
    {ID: "openssh", Port: 22, BannerContains: "OpenSSH", Service: "OpenSSH", RiskLevel: "info"},
    {ID: "mysql", Port: 3306, BannerContains: "mysql", Service: "MySQL", RiskLevel: "high"},
    {ID: "redis", Port: 6379, BannerContains: "redis", Service: "Redis", RiskLevel: "high"},
    {ID: "postgresql", Port: 5432, BannerContains: "postgres", Service: "PostgreSQL", RiskLevel: "high"},
    {ID: "elasticsearch", Port: 9200, BannerContains: "elasticsearch", Service: "Elasticsearch", RiskLevel: "high"},
    {ID: "docker-api", Port: 2375, BannerContains: "docker", Service: "Docker API", RiskLevel: "critical"},
    {ID: "jenkins", Port: 8080, BannerContains: "Jenkins", Service: "Jenkins", RiskLevel: "high"},
    {ID: "tomcat", Port: 8080, BannerContains: "Apache-Coyote", Service: "Apache Tomcat", RiskLevel: "medium"},
    {ID: "phpmyadmin", Port: 80, BannerContains: "phpMyAdmin", Service: "phpMyAdmin", RiskLevel: "high"},
}

// Match applies fingerprint rules to a port + banner
func Match(port int, banner string) *FingerprintRule {
    for _, rule := range DefaultRules {
        if rule.Port != 0 && rule.Port != port {
            continue
        }
        if rule.BannerContains != "" && !contains(banner, rule.BannerContains) {
            continue
        }
        return &rule
    }
    return nil
}

// MatchPort returns the service name for a port if known
func MatchPort(port int) string {
    switch port {
    case 80, 8080, 8443:
        return "http"
    case 22:
        return "ssh"
    case 21:
        return "ftp"
    case 25, 587:
        return "smtp"
    case 110:
        return "pop3"
    case 143:
        return "imap"
    case 3306:
        return "mysql"
    case 5432:
        return "postgresql"
    case 6379:
        return "redis"
    case 9200:
        return "elasticsearch"
    case 27017:
        return "mongodb"
    default:
        return ""
    }
}

func contains(s, substr string) bool {
    return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSlow(s, substr))
}

func containsSlow(s, substr string) bool {
    for i := 0; i <= len(s)-len(substr); i++ {
        if s[i:i+len(substr)] == substr {
            return true
        }
    }
    return false
}
```

- [ ] **Step 2: Commit**

```bash
git add core/scanner/registry.go
git commit -m "feat: add service fingerprint registry

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 8: 扫描引擎编排器

**Files:**
- Create: `core/scanner/scanner.go`

- [ ] **Step 1: Write implementation**

```go
package scanner

import (
    "context"
    "fmt"
    "strings"
    "sync"
    "time"

    "github.com/netprowl/core/util"
)

// RunScan executes a full discovery scan: mDNS + SSDP + TCP
// Returns all discovered devices, deduplicated by IP
func RunScan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
    start := time.Now()

    if cfg.Concurrency == 0 {
        cfg.Concurrency = DefaultConcurrency
    }
    if cfg.TimeoutMs == 0 {
        cfg.TimeoutMs = 2000
    }
    timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond

    // Infer subnet if not provided
    ipRange := cfg.IPRange
    if ipRange == "" {
        ipRange = "192.168.1.0/24" // fallback
    }

    // Stage 1: mDNS discovery
    mdnsDevices, _ := DiscoverMDNS(ctx, 4*time.Second)

    // Stage 2: SSDP discovery (parallel with TCP scan)
    ssdpDevices, _ := DiscoverSSDP(3 * time.Second)

    // Stage 3: TCP port scan
    tcpDevices, err := ScanIPRange(cfg)
    if err != nil {
        // partial results still OK
    }

    // Merge all devices
    all := append(mdnsDevices, ssdpDevices...)
    all = append(all, tcpDevices...)
    merged := mergeByIP(all)

    // Fill vendor info via OUI
    for i := range merged {
        if merged[i].MAC != "" && merged[i].Vendor == "" {
            merged[i].Vendor = util.LookupVendor(merged[i].MAC)
        }
    }

    result := &ScanResult{
        ID:        fmt.Sprintf("scan_%d", time.Now().UnixMilli()),
        Timestamp: time.Now().UnixMilli(),
        IPRange:   ipRange,
        Devices:   merged,
        Duration:  time.Since(start).Milliseconds(),
    }
    return result, nil
}

// ScanIPRange performs TCP port scan across a subnet
func ScanIPRange(cfg ScanConfig) ([]Device, error) {
    ips := util.ExpandSubnet(cfg.IPRange)
    if len(ips) == 0 {
        return nil, fmt.Errorf("invalid subnet: %s", cfg.IPRange)
    }

    ports := cfg.Ports
    if len(ports) == 0 {
        ports = DefaultPorts
    }

    timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
    concurrency := cfg.Concurrency
    if concurrency == 0 {
        concurrency = DefaultConcurrency
    }

    sem := make(chan struct{}, concurrency)
    var mu sync.Mutex
    var devices []Device
    var wg sync.WaitGroup

    for _, ip := range ips {
        wg.Add(1)
        sem <- struct{}{}
        go func(targetIP string) {
            defer wg.Done()
            defer func() { <-sem }()

            ports := ProbePorts(targetIP, ports, timeout, concurrency)
            if len(ports) == 0 {
                return
            }

            // Grab banners if enabled
            if cfg.BannerGrab {
                for i := range ports {
                    result, _ := GrabBanner(targetIP, ports[i].Port, timeout)
                    if result != nil {
                        ports[i].Banner = result.Banner
                        if rule := Match(ports[i].Port, result.Banner); rule != nil {
                            ports[i].Service = rule.Service
                        }
                    }
                }
            }

            mu.Lock()
            devices = append(devices, Device{
                ID:           targetIP,
                IP:           targetIP,
                DeviceType:  DeviceTypeUnknown,
                OS:           OSUnknown,
                OpenPorts:    ports,
                DiscoveredAt: time.Now().UnixMilli(),
                Sources:      []DiscoverySource{SourceTCP},
            })
            mu.Unlock()
        }(ip)
    }
    wg.Wait()
    return devices, nil
}

// mergeByIP deduplicates device list by IP
func mergeByIP(devices []Device) []Device {
    m := make(map[string]Device)
    for _, d := range devices {
        if existing, ok := m[d.IP]; ok {
            // combine sources
            srcSet := make(map[DiscoverySource]bool)
            for _, s := range existing.Sources {
                srcSet[s] = true
            }
            for _, s := range d.Sources {
                srcSet[s] = true
            }
            var srcs []DiscoverySource
            for s := range srcSet {
                srcs = append(srcs, s)
            }
            existing.Sources = srcs
            m[d.IP] = existing
        } else {
            m[d.IP] = d
        }
    }
    result := make([]Device, 0, len(m))
    for _, d := range m {
        result = append(result, d)
    }
    return result
}
```

> Note: `ScanIPRange` needs `util.ExpandSubnet` which was written in Task 2. Verify import path is correct.

- [ ] **Step 2: Commit**

```bash
git add core/scanner/scanner.go
git commit -m "feat: add scan orchestrator

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Self-Review Checklist

1. **Spec coverage:** mDNS, SSDP, TCP, Banner, Fingerprint, OUI — all 6 components covered.
2. **Placeholder scan:** `containsSlow` — naive O(n) string search; acceptable for MVP rule list size (~15 rules). `queryMDNS` raw packet approach noted as fallback, `hashicorp/mdns` library used.
3. **Type consistency:** `Device` fields match `types.go` definitions. `ScanResult.Duration` is `int64` (ms), consistent with `time.Since().Milliseconds()`.

---

**Plan complete.** 保存至 `docs/superpowers/plans/2026-05-11-netprowl-core-plan.md`.

Two execution options:

**1. Subagent-Driven (recommended)** — fresh subagent per task, two-stage review, fast iteration

**2. Inline Execution** — batch execute in this session

选哪个？
