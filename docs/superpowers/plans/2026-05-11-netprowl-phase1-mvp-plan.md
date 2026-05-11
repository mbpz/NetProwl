# NetProwl Phase 1 MVP · Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Phase 1 MVP 扫描引擎跑通 — Go core + 小程序 + PC 双版本

**Architecture (from spec v1.2):**
- `core/` — Go 共享核心（mDNS/UDP SSDP/TCP/Banner/服务指纹）
- `netprowl-mini/` — Taro 微信小程序（白名单端口限制）
- `netprowl-pc/` — Tauri PC 客户端（全端口，无限制）

**Tech Stack:** Go 1.21+ / Taro 4.x / React 18 / Tauri 2.x / Zustand / SQLite

---

## File Structure

```
netprowl/
├── core/
│   ├── go.mod
│   ├── scanner/
│   │   ├── mdns.go        # mDNS 发现
│   │   ├── ssdp.go       # UDP SSDP
│   │   ├── tcp.go        # TCP 端口扫描
│   │   ├── banner.go     # Banner 抓取
│   │   └── registry.go   # 服务指纹规则库
│   └── util/
│       ├── oui.go        # MAC OUI 厂商库
│       └── ip.go         # IP/子网工具
│
├── netprowl-mini/        # Taro 微信小程序
│   ├── src/
│   │   ├── pages/
│   │   │   ├── index/     # 首页，扫描入口
│   │   │   ├── devices/   # 设备列表
│   │   │   ├── topology/ # 拓扑图
│   │   │   └── history/  # 扫描历史
│   │   ├── components/
│   │   │   ├── DeviceCard/
│   │   │   ├── TopoCanvas/
│   │   │   └── ScanButton/
│   │   ├── services/
│   │   │   ├── mdns.ts
│   │   │   ├── udp.ts
│   │   │   ├── tcp.ts
│   │   │   └── storage.ts
│   │   ├── stores/
│   │   │   └── deviceStore.ts
│   │   └── utils/
│   │       ├── oui.ts
│   │       └── ip.ts
│   └── project.config.json
│
└── netprowl-pc/          # Tauri PC 客户端
    ├── src/              # React 前端
    ├── src-tauri/        # Rust 后端
    └── Cargo.toml
```

---

## Task Map

| Task | 内容 | 依赖 |
|------|------|------|
| 1 | Go core: go.mod + scanner/tcp.go | — |
| 2 | Go core: scanner/mdns.go + ssdp.go | 1 |
| 3 | Go core: scanner/banner.go + registry.go | 2 |
| 4 | Go core: util/oui.go + ip.go | 1 |
| 5 | 小程序: 项目脚手架 + 核心类型 | — |
| 6 | 小程序: services (mdns/udp/tcp/storage) | 5 |
| 7 | 小程序: stores + components | 6 |
| 8 | 小程序: pages (index/devices/topology/history) | 7 |
| 9 | PC: Tauri 脚手架 + Rust 命令 | — |
| 10 | PC: React 前端页面 | 9 |
| 11 | 集成 + 验收 | 4 + 8 + 10 |

---

## Task 1: Go core: go.mod + scanner/tcp.go

**Files:**
- Create: `core/go.mod`
- Create: `core/scanner/tcp.go`

- [ ] **Step 1: Create core directory and go.mod**

```bash
mkdir -p /Users/jinguo.zeng/dmall/project/NetProwl/core/scanner
mkdir -p /Users/jinguo.zeng/dmall/project/NetProwl/core/util
cd /Users/jinguo.zeng/dmall/project/NetProwl/core
go mod init github.com/netprowl/core
```

- [ ] **Step 2: Write core/scanner/tcp.go**

```go
package scanner

import (
    "fmt"
    "net"
    "sync"
    "time"
)

const (
    DefaultTimeout = 2 * time.Second
    MaxConcurrency = 200
)

var whitePorts = []int{80, 443, 8080, 8443, 554, 5000, 9000, 49152, 22, 21, 25, 110, 143, 135, 139, 445}

type ScanResult struct {
    IP    string
    Port  int
    State string // "open" | "closed"
    Banner string
}

type Device struct {
    IP       string
    MAC      string
    Vendor   string
    OS       string
    Ports    []Port
    Risk     string
}

type Port struct {
    Number  int
    State   string
    Service string
    Banner  string
}

func ScanTCP(ipStart, ipEnd string, ports []int) ([]Device, error) {
    start := net.ParseIP(ipStart)
    end := net.ParseIP(ipEnd)
    if start == nil || end == nil {
        return nil, fmt.Errorf("invalid IP range: %s - %s", ipStart, ipEnd)
    }

    targets := generateIPs(start, end)
    if len(targets) == 0 {
        return nil, fmt.Errorf("no targets generated")
    }

    results := make([]ScanResult, 0)
    var mu sync.Mutex
    var wg sync.WaitGroup
    sem := make(chan struct{}, MaxConcurrency)

    for _, ip := range targets {
        for _, port := range ports {
            wg.Add(1)
            sem <- struct{}{}
            go func(ip string, port int) {
                defer wg.Done()
                defer func() { <-sem }()

                result := probePort(ip, port)
                mu.Lock()
                if result.State == "open" {
                    results = append(results, result)
                }
                mu.Unlock()
            }(ip, port)
        }
    }
    wg.Wait()

    return buildDeviceList(results), nil
}

func probePort(ip string, port int) ScanResult {
    result := ScanResult{IP: ip, Port: port, State: "closed"}
    conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), DefaultTimeout)
    if err != nil {
        return result
    }
    defer conn.Close()
    result.State = "open"
    result.Banner = grabBanner(conn, port)
    return result
}

func grabBanner(conn net.Conn, port int) string {
    conn.SetDeadline(time.Now().Add(1 * time.Second))
    switch port {
    case 80, 8080, 8443:
        fmt.Fprint(conn, "HEAD / HTTP/1.0\r\n\r\n")
    }
    buf := make([]byte, 1024)
    n, _ := conn.Read(buf)
    if n > 0 {
        return string(buf[:n])
    }
    return ""
}

func generateIPs(start, end net.IP) []string {
    s := ipToInt(start)
    e := ipToInt(end)
    out := make([]string, 0, e-s+1)
    for i := s; i <= e; i++ {
        out = append(out, intToIP(i).String())
    }
    return out
}

func ipToInt(ip net.IP) int64 {
    ip4 := ip.To4()
    if ip4 == nil {
        return 0
    }
    return int64(ip4[0])<<24 | int64(ip4[1])<<16 | int64(ip4[2])<<8 | int64(ip4[3])
}

func intToIP(i int64) net.IP {
    return net.IP{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
}

func buildDeviceList(results []ScanResult) []Device {
    m := make(map[string]*Device)
    for _, r := range results {
        dev, ok := m[r.IP]
        if !ok {
            dev = &Device{IP: r.IP, Ports: []Port{}}
            m[r.IP] = dev
        }
        dev.Ports = append(dev.Ports, Port{
            Number:  r.Port,
            State:   r.State,
            Service: GuessService(r.Port),
            Banner:  r.Banner,
        })
    }
    devs := make([]Device, 0, len(m))
    for _, d := range m {
        d.Risk = AssessRisk(d.Ports)
        devs = append(devs, *d)
    }
    return devs
}
```

- [ ] **Step 3: Add service guess and risk assessment**

Append to `core/scanner/tcp.go`:

```go
var serviceMap = map[int]string{
    80:   "http",
    443:  "https",
    22:   "ssh",
    21:   "ftp",
    25:   "smtp",
    110:  "pop3",
    143:  "imap",
    135:  "msrpc",
    139:  "netbios",
    445:  "smb",
    3389: "rdp",
    8080: "http-alt",
    8443: "https-alt",
    5000: "upnp",
    9000: "cslistener",
    554:  "rtsp",
}

var dangerPorts = []int{3389, 445, 139, 135, 1433, 3306, 6379, 27017, 23}

func GuessService(port int) string {
    if s, ok := serviceMap[port]; ok {
        return s
    }
    return "unknown"
}

func AssessRisk(ports []Port) string {
    for _, p := range ports {
        for _, d := range dangerPorts {
            if p.Number == d {
                return "high"
            }
        }
    }
    if len(ports) > 5 {
        return "medium"
    }
    return "low"
}
```

- [ ] **Step 4: Verify compilation**

```bash
cd /Users/jinguo.zeng/dmall/project/NetProwl/core
go build ./...
```

- [ ] **Step 5: Commit**

```bash
git add core/
git commit -m "feat(core): add TCP scanner with concurrency and service guess"
```

---

## Task 2: Go core: scanner/mdns.go + ssdp.go

**Depends on:** Task 1

- [ ] **Step 1: Write core/scanner/mdns.go**

```go
package scanner

import (
    "github.com/grandcat/zeroconf"
)

type MDNSEntry struct {
    IP       string
    Hostname string
    Port     int
}

func DiscoverMDNS() ([]MDNSEntry, error) {
    resolver, err := zeroconf.NewResolver(nil)
    if err != nil {
        return nil, err
    }

    results, err := resolver.Lookup("_netprowl._tcp", "local.")
    if err != nil {
        return nil, err
    }

    entries := make([]MDNSEntry, 0, len(results))
    for _, ent := range results {
        entries = append(entries, MDNSEntry{
            IP:       ent.HostName,
            Hostname: ent.ServiceInstance,
            Port:     ent.Port,
        })
    }
    return entries, nil
}
```

- [ ] **Step 2: Write core/scanner/ssdp.go**

```go
package scanner

import (
    "net"
    "strings"
    "time"
)

const (
    SSDP_ADDR = "239.255.255.250"
    SSDP_PORT = 1900
)

var ssdpSearch = strings.Join([]string{
    "M-SEARCH * HTTP/1.1",
    "HOST: 239.255.255.250:1900",
    `MAN: "ssdp:discover"`,
    "MX: 2",
    "ST: ssdp:all",
    "", "",
}, "\r\n")

type SSDPEntry struct {
    IP        string
    Hostname  string
    USN       string
}

func DiscoverSSDP() ([]SSDPEntry, error) {
    addr, err := net.ResolveUDPAddr("udp", SSDP_ADDR+":"+string(rune(SSDP_PORT)))
    if err != nil {
        return nil, err
    }

    conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
    if err != nil {
        return nil, err
    }
    defer conn.Close()

    conn.SetDeadline(time.Now().Add(3 * time.Second))
    _, err = conn.WriteToUDP([]byte(ssdpSearch), addr)
    if err != nil {
        return nil, err
    }

    entries := make([]SSDPEntry, 0)
    buf := make([]byte, 4096)
    for {
        n, remote, err := conn.ReadFromUDP(buf)
        if err != nil {
            break
        }
        if strings.Contains(string(buf[:n]), "HTTP/1.1 200") {
            entries = append(entries, SSDPEntry{
                IP: remote.IP.String(),
            })
        }
    }
    return entries, nil
}
```

- [ ] **Step 3: Add dependency and verify build**

```bash
cd /Users/jinguo.zeng/dmall/project/NetProwl/core
go get github.com/grandcat/zeroconf
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add core/scanner/mdns.go core/scanner/ssdp.go
git commit -m "feat(core): add mDNS and SSDP discovery"
```

---

## Task 3: Go core: scanner/banner.go + registry.go

**Depends on:** Task 2

- [ ] **Step 1: Write core/scanner/banner.go**

```go
package scanner

import (
    "fmt"
    "net"
    "strings"
    "time"
)

func GrabBanner(ip string, port int) string {
    conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
    if err != nil {
        return ""
    }
    defer conn.Close()

    conn.SetDeadline(time.Now().Add(1 * time.Second))

    switch port {
    case 80, 8080, 8443:
        fmt.Fprint(conn, "HEAD / HTTP/1.0\r\n\r\n")
    case 21:
        // FTP: read banner on connect
    case 22:
        fmt.Fprint(conn, "SSH-2.0-\r\n")
    }

    buf := make([]byte, 1024)
    n, _ := conn.Read(buf)
    if n > 0 {
        return strings.TrimSpace(string(buf[:n]))
    }
    return ""
}
```

- [ ] **Step 2: Write core/scanner/registry.go**

```go
package scanner

type ServiceRule struct {
    Port         int
    BannerMatch  string
    ServiceName  string
    OS           string
}

var builtinRules = []ServiceRule{
    {80, "Server: nginx", "nginx", "linux"},
    {80, "Server: Apache", "apache", "linux"},
    {80, "Server: Microsoft", "iis", "windows"},
    {8080, "Jetty", "jetty", "linux"},
    {8080, "Tomcat", "tomcat", "linux"},
    {22, "SSH", "openssh", "linux"},
    {22, "OpenSSH", "openssh", "linux"},
    {21, "220 FTP", "vsftpd", "linux"},
    {3306, "5.", "mysql", "linux"},
    {1433, "Microsoft SQL Server", "mssql", "windows"},
    {27017, "MongoDB", "mongodb", "linux"},
    {6379, "PONG", "redis", "linux"},
}

func MatchService(port int, banner string) (name string, os string) {
    for _, rule := range builtinRules {
        if rule.Port == port && strings.Contains(banner, rule.BannerMatch) {
            return rule.ServiceName, rule.OS
        }
    }
    return GuessService(port), "unknown"
}
```

- [ ] **Step 3: Verify build**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add core/scanner/banner.go core/scanner/registry.go
git commit -m "feat(core): add banner grab and service registry"
```

---

## Task 4: Go core: util/oui.go + ip.go

**Depends on:** Task 1

- [ ] **Step 1: Write core/util/oui.go**

```go
package util

var ouiMap = map[string]string{
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "00:1e:68": "Quanta (华为/H3C)",
    "00:25:9e": "Cisco",
    "00:1a:2b": "Cisco",
    "a8:66:7f": "Apple",
    "f0:18:98": "Apple",
    "00:0d:2b": "Dell",
    "00:1c:23": "Dell",
    "ac:de:48": "Hangzhou Hikvision",
    "b4:15:13": "Hangzhou Hikvision",
    "3c:06:30": "Apple",
    "00:e0:4c": "Realtek",
    "00:23:cd": "Intel",
}

func LookupVendor(mac string) string {
    normalized := normalizeMac(mac)
    prefix := normalized[:8]
    if v, ok := ouiMap[prefix]; ok {
        return v
    }
    return ""
}

func normalizeMac(mac string) string {
    result := make([]byte, 0, len(mac))
    for _, c := range mac {
        if c != ':' && c != '-' {
            result = append(result, byte(c))
        }
    }
    return strings.ToUpper(string(result))
}
```

- [ ] **Step 2: Write core/util/ip.go**

```go
package util

import (
    "net"
    "strings"
)

func IsPrivateIP(ip string) bool {
    p := net.ParseIP(ip)
    if p == nil {
        return false
    }
    return p.IsPrivate() || p.IsLoopback()
}

func InferSubnet(localIP string) string {
    ip := net.ParseIP(localIP)
    if ip == nil {
        return "192.168.1.0/24"
    }
    ip4 := ip.To4()
    if ip4 == nil {
        return "192.168.1.0/24"
    }
    return fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
}

func ParseIPRange(ipStart, ipEnd string) ([]string, error) {
    start := net.ParseIP(ipStart)
    end := net.ParseIP(ipEnd)
    if start == nil || end == nil {
        return nil, fmt.Errorf("invalid IP range")
    }
    s := ipToInt(start)
    e := ipToInt(end)
    out := make([]string, 0, e-s+1)
    for i := s; i <= e; i++ {
        out = append(out, intToIP(i).String())
    }
    return out, nil
}

func ipToInt(ip net.IP) int64 {
    ip4 := ip.To4()
    if ip4 == nil {
        return 0
    }
    return int64(ip4[0])<<24 | int64(ip4[1])<<16 | int64(ip4[2])<<8 | int64(ip4[3])
}

func intToIP(i int64) net.IP {
    return net.IP{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
}
```

Note: Add `"strings"` and `"fmt"` imports to ip.go.

- [ ] **Step 3: Verify build**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add core/util/oui.go core/util/ip.go
git commit -m "feat(core): add oui lookup and ip utilities"
```

---

## Task 5: 小程序: 项目脚手架 + 核心类型

**Files:**
- Create: `netprowl-mini/package.json`
- Create: `netprowl-mini/project.config.json`
- Create: `netprowl-mini/tsconfig.json`
- Create: `netprowl-mini/src/app.ts`
- Create: `netprowl-mini/src/app.config.ts`

- [ ] **Step 1: Create netprowl-mini directory structure**

```bash
mkdir -p /Users/jinguo.zeng/dmall/project/NetProwl/netprowl-mini/src/{pages/{index,devices,topology,history},components/{DeviceCard,TopoCanvas,ScanButton},services,stores,utils}
```

- [ ] **Step 2: Write netprowl-mini/package.json**

```json
{
  "name": "netprowl-mini",
  "version": "1.0.0",
  "scripts": {
    "dev:weapp": "taro build --type weapp --watch",
    "build:weapp": "taro build --type weapp"
  },
  "dependencies": {
    "@tarojs/taro": "4.x",
    "@tarojs/plugin-framework-react": "4.x",
    "react": "18.x",
    "zustand": "4.x"
  },
  "devDependencies": {
    "@tarojs/cli": "4.x",
    "@types/react": "18.x",
    "typescript": "5.x"
  }
}
```

- [ ] **Step 3: Write netprowl-mini/project.config.json**

```json
{
  "miniprogramRoot": "dist/",
  "projectname": "NetProwl",
  "description": "NetProwl 微信小程序",
  "appid": "touristappid",
  "setting": {
    "urlCheck": false,
    "es6": true,
    "enhance": true
  },
  "compileType": "miniprogram"
}
```

- [ ] **Step 4: Write src/app.config.ts**

```typescript
export default defineAppConfig({
  pages: [
    'pages/index/index',
    'pages/devices/index',
    'pages/topology/index',
    'pages/history/index',
  ],
  window: {
    navigationBarBackgroundColor: '#0f0f1a',
    navigationBarTitleText: 'NetProwl',
    navigationBarTextStyle: 'white',
    backgroundTextStyle: 'light',
  },
  tabBar: {
    color: '#999',
    selectedColor: '#00d4ff',
    backgroundColor: '#1a1a2e',
    list: [
      { pagePath: 'pages/index/index', text: '首页', iconPath: 'assets/tab-index.png', selectedIconPath: 'assets/tab-index-active.png' },
      { pagePath: 'pages/devices/index', text: '设备', iconPath: 'assets/tab-devices.png', selectedIconPath: 'assets/tab-devices-active.png' },
      { pagePath: 'pages/history/index', text: '历史', iconPath: 'assets/tab-history.png', selectedIconPath: 'assets/tab-history-active.png' },
    ],
  },
})
```

- [ ] **Step 5: Write src/app.ts**

```typescript
import { Component } from 'react'
import './app.css'

class App extends Component {
  render() {
    return this.props.children
  }
}

export default App
```

- [ ] **Step 6: Write src/app.css**

```css
page {
  background-color: #0f0f1a;
  color: #fff;
  font-family: -apple-system, BlinkMacSystemFont, sans-serif;
}
```

- [ ] **Step 7: Commit**

```bash
git add netprowl-mini/
git commit -m "feat(mini): add Taro project scaffold"
```

---

## Task 6: 小程序: services (mdns/udp/tcp/storage)

**Depends on:** Task 5

- [ ] **Step 1: Write src/services/tcp.ts**

```typescript
const WHITE_PORTS = [80, 443, 8080, 8443, 554, 5000, 9000, 49152]
const CONCURRENCY = 20
const TIMEOUT_MS = 2000

export async function probeTCPPorts(ip: string): Promise<number[]> {
  const open: number[] = []
  const chunks = chunkArray(WHITE_PORTS, CONCURRENCY)

  for (const group of chunks) {
    const results = await Promise.all(group.map(port => probePort(ip, port)))
    results.forEach((p, i) => { if (p) open.push(group[i]) })
    await delay(50)
  }
  return open
}

async function probePort(ip: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = wx.createTCPSocket()
    let settled = false
    const timer = setTimeout(() => {
      if (!settled) { settled = true; socket.close(); resolve(false) }
    }, TIMEOUT_MS)

    socket.onConnect(() => {
      if (!settled) { settled = true; clearTimeout(timer); socket.close(); resolve(true) }
    })
    socket.onError(() => {
      if (!settled) { settled = true; clearTimeout(timer); socket.close(); resolve(false) }
    })
    socket.connect({ address: ip, port })
  })
}

function chunkArray<T>(arr: T[], size: number): T[][] {
  const out: T[][] = []
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size))
  return out
}

function delay(ms: number) {
  return new Promise(r => setTimeout(r, ms))
}
```

- [ ] **Step 2: Write src/services/mdns.ts**

```typescript
import type { Device } from '../stores/deviceStore'

const SERVICE_TYPES = ['_http._tcp', '_smb._tcp', '_ssh._tcp', '_ftp._tcp', '_airplay._tcp', '_googlecast._tcp']

export async function discoverMDNS(): Promise<Device[]> {
  const devices: Device[] = []
  const found = new Map<string, Device>()

  wx.onLocalServiceFound((res: any) => {
    const key = res.serviceName
    if (!found.has(key)) {
      found.set(key, {
        id: key,
        ip: res.ip,
        mac: null,
        hostname: res.hostName || res.serviceName,
        vendor: null,
        deviceType: 'unknown',
        os: 'unknown',
        openPorts: [],
        discoveredAt: Date.now(),
        sources: ['mdns'],
      })
    }
  })

  for (const st of SERVICE_TYPES) {
    try {
      await wx.startLocalServiceDiscovery({ serviceType: st })
    } catch (e: any) {
      if (e?.errCode === -1) {
        // iOS mDNS disabled — handled at scanner level
      }
    }
  }

  await delay(3000)
  wx.stopLocalServiceDiscovery({})
  return Array.from(found.values())
}

function delay(ms: number) {
  return new Promise(r => setTimeout(r, ms))
}
```

- [ ] **Step 3: Write src/services/udp.ts**

```typescript
import type { Device } from '../stores/deviceStore'

const SSDP_ADDR = '239.255.255.250'
const SSDP_PORT = 1900
const M_SEARCH = 'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n'

export async function discoverSSDP(): Promise<Device[]> {
  const devices: Device[] = []
  const seen = new Set<string>()

  const udp = wx.createUDPSocket()
  udp.onMessage((res: any) => {
    const banner = bufToString(res.message)
    if (!banner.includes('HTTP/1.1 200')) return
    const ip = res.remoteInfo.address
    if (seen.has(ip)) return
    seen.add(ip)
    devices.push(makeDevice(ip, banner, 'ssdp'))
  })

  udp.send({ address: SSDP_ADDR, port: SSDP_PORT, message: M_SEARCH })
  await delay(3000)
  udp.close()

  return devices
}

function makeDevice(ip: string, banner: string, source: 'ssdp' | 'tcp'): Device {
  return {
    id: ip,
    ip,
    mac: null,
    hostname: extractHeader(banner, 'SERVER') || ip,
    vendor: null,
    deviceType: inferType(banner),
    os: 'unknown',
    openPorts: [],
    discoveredAt: Date.now(),
    sources: [source],
  }
}

function extractHeader(banner: string, key: string): string | null {
  const m = banner.match(new RegExp(`^${key}:\\s*(.+)$`, 'im'))
  return m ? m[1].trim() : null
}

function inferType(banner: string): Device['deviceType'] {
  const lower = banner.toLowerCase()
  if (/router|gateway|netgear|tp-link|xiaomi|honor|huawei/.test(lower)) return 'router'
  if (/camera|ipcam|hikvision|dahua|ezviz/.test(lower)) return 'camera'
  if (/nas|synology|qnap|群晖/.test(lower)) return 'nas'
  if (/printer|hp|canon|epson/.test(lower)) return 'printer'
  return 'unknown'
}

function bufToString(buf: ArrayBuffer): string {
  const arr = new Uint8Array(buf)
  return String.fromCharCode(...arr)
}

function delay(ms: number) {
  return new Promise(r => setTimeout(r, ms))
}
```

- [ ] **Step 4: Write src/services/storage.ts**

```typescript
import type { ScanSnapshot } from '../stores/deviceStore'

const KEY = 'netprowl_scan_history'
const MAX = 50

export function loadHistory(): ScanSnapshot[] {
  try {
    const raw = wx.getStorageSync(KEY)
    return raw ? JSON.parse(raw) : []
  } catch {
    return []
  }
}

export function saveSnapshot(snap: ScanSnapshot): void {
  const history = loadHistory()
  history.unshift(snap)
  while (history.length > MAX) history.pop()
  const data = JSON.stringify(history)
  if (data.length > 10 * 1024 * 1024) history.splice(0, 3)
  wx.setStorageSync(KEY, JSON.stringify(history))
}

export function clearHistory(): void {
  wx.removeStorageSync(KEY)
}
```

- [ ] **Step 5: Commit**

```bash
git add netprowl-mini/src/services/
git commit -m "feat(mini): add mdns/udp/tcp/storage services"
```

---

## Task 7: 小程序: stores + components

**Depends on:** Task 6

- [ ] **Step 1: Write src/stores/deviceStore.ts**

```typescript
import { create } from 'zustand'

export type DeviceType = 'router' | 'pc' | 'camera' | 'nas' | 'phone' | 'printer' | 'unknown'
export type OSType = 'linux' | 'windows' | 'network' | 'unknown'

export interface Port {
  number: number
  service: string | null
  state: 'open' | 'filtered'
  banner?: string
}

export interface Device {
  id: string
  ip: string
  mac: string | null
  hostname: string | null
  vendor: string | null
  deviceType: DeviceType
  os: OSType
  openPorts: Port[]
  discoveredAt: number
  sources: ('mdns' | 'ssdp' | 'tcp')[]
}

export interface ScanSnapshot {
  id: string
  timestamp: number
  ipRange: string
  deviceCount: number
  devices: Device[]
}

interface DeviceStore {
  devices: Device[]
  history: ScanSnapshot[]
  scanning: boolean
  addDevice: (d: Device) => void
  setDevices: (ds: Device[]) => void
  setScanning: (v: boolean) => void
  loadHistory: () => void
}

export const useDeviceStore = create<DeviceStore>((set, get) => ({
  devices: [],
  history: [],
  scanning: false,

  addDevice: (d) => set(s => ({ devices: [...s.devices.filter(x => x.ip !== d.ip), d] })),

  setDevices: (devices) => set({ devices }),

  setScanning: (scanning) => set({ scanning }),

  loadHistory: () => {
    const history = loadHistoryFromStorage()
    set({ history })
  },
}))

function loadHistoryFromStorage(): ScanSnapshot[] {
  try {
    const raw = wx.getStorageSync('netprowl_scan_history')
    return raw ? JSON.parse(raw) : []
  } catch {
    return []
  }
}
```

- [ ] **Step 2: Write src/components/DeviceCard/index.tsx**

```typescript
import { Component } from 'react'
import { View, Text } from '@tarojs/components'
import type { Device } from '../../stores/deviceStore'
import './index.css'

interface Props {
  device: Device
  onClick: (d: Device) => void
}

export default class DeviceCard extends Component<Props> {
  render() {
    const { device, onClick } = this.props
    return (
      <View className='card' onClick={() => onClick(device)}>
        <View className='card-icon'>{this.getIcon(device.deviceType)}</View>
        <View className='card-info'>
          <Text className='ip'>{device.ip}</Text>
          <Text className='vendor'>{device.vendor || '未知厂商'}</Text>
        </View>
        <Text className='port-count'>{device.openPorts.length} 端口</Text>
      </View>
    )
  }

  getIcon(type: Device['deviceType']) {
    return { router: '🛣', pc: '💻', camera: '📹', nas: '💾', phone: '📱', printer: '🖨', unknown: '❓' }[type]
  }
}
```

- [ ] **Step 3: Write CSS for DeviceCard**

```css
.card {
  display: flex;
  align-items: center;
  background: #1e1e3a;
  border-radius: 16rpx;
  padding: 24rpx;
  margin-bottom: 16rpx;
}
.card-icon { width: 64rpx; text-align: center; font-size: 40rpx; }
.card-info { flex: 1; margin-left: 16rpx; }
.ip { display: block; color: #fff; font-size: 30rpx; font-weight: 500; }
.vendor { display: block; color: #888; font-size: 24rpx; margin-top: 4rpx; }
.port-count { color: #00d4ff; font-size: 26rpx; }
```

- [ ] **Step 4: Write src/components/TopoCanvas/index.tsx**

```typescript
import { Component } from 'react'
import { View } from '@tarojs/components'
import type { Device } from '../../stores/deviceStore'
import './index.css'

interface Props {
  devices: Device[]
  gatewayIP: string
  onDeviceClick: (d: Device) => void
}

export default class TopoCanvas extends Component<Props> {
  componentDidMount() {
    this.render()
  }

  componentDidUpdate() {
    this.render()
  }

  render() {
    const { devices, gatewayIP } = this.props
    if (devices.length === 0) return (
      <View className='topo-empty'>
        <Text className='empty-icon'>🛣</Text>
        <Text className='empty-text'>点击下方按钮开始扫描</Text>
      </View>
    )

    // 星形布局：中心网关，周围设备
    const query = Taro.createSelectorQuery()
    query.select('#topo-canvas').node((res: any) => {
      if (!res) return
      const canvas = res.node
      const ctx = canvas.getContext('2d')
      const dpr = Taro.getSystemInfoSync().pixelRatio || 1
      const w = Taro.getSystemInfoSync().windowWidth
      canvas.width = w * dpr
      canvas.height = (w * 0.7) * dpr
      ctx.scale(dpr, dpr)
      this.draw(ctx, w, w * 0.7, devices, gatewayIP)
    }).exec()
    return <canvas id='topo-canvas' className='topo-canvas' onClick={this.handleClick} />
  }

  draw(ctx: any, w: number, h: number, devices: Device[], gatewayIP: string) {
    ctx.clearRect(0, 0, w, h)
    const cx = w / 2, cy = h / 2
    const r = Math.min(w, h) * 0.35
    const gateway = devices.find(d => d.ip === gatewayIP) || devices[0]
    const others = devices.filter(d => d.ip !== gateway?.ip)

    // 连接线
    others.forEach((dev, i) => {
      const angle = (2 * Math.PI * i) / others.length - Math.PI / 2
      const x = cx + r * Math.cos(angle)
      const y = cy + r * Math.sin(angle)
      ctx.beginPath()
      ctx.strokeStyle = '#2a2a4a'
      ctx.lineWidth = 1
      ctx.moveTo(cx, cy)
      ctx.lineTo(x, y)
      ctx.stroke()
    })

    // 中心网关
    ctx.beginPath()
    ctx.fillStyle = '#0077ff'
    ctx.strokeStyle = '#00d4ff'
    ctx.lineWidth = 2
    ctx.arc(cx, cy, 28, 0, Math.PI * 2)
    ctx.fill()
    ctx.stroke()
    ctx.fillStyle = '#fff'
    ctx.font = '20px sans-serif'
    ctx.textAlign = 'center'
    ctx.fillText('🛣', cx, cy + 6)

    // 周围设备
    others.forEach((dev, i) => {
      const angle = (2 * Math.PI * i) / others.length - Math.PI / 2
      const x = cx + r * Math.cos(angle)
      const y = cy + r * Math.sin(angle)
      const riskColor = { low: '#4caf50', medium: '#ff9800', high: '#f44336', critical: '#b71c1c' }[dev.openPorts.length > 3 ? 'high' : dev.openPorts.length > 0 ? 'medium' : 'low'] || '#999'

      ctx.beginPath()
      ctx.fillStyle = '#1e1e3a'
      ctx.strokeStyle = riskColor
      ctx.lineWidth = 2
      ctx.arc(x, y, 22, 0, Math.PI * 2)
      ctx.fill()
      ctx.stroke()
      ctx.fillStyle = '#fff'
      ctx.font = '16px sans-serif'
      ctx.textAlign = 'center'
      const icon = this.getIcon(dev.deviceType)
      ctx.fillText(icon, x, y - 4)
      ctx.fillStyle = '#888'
      ctx.font = '10px sans-serif'
      ctx.fillText(dev.ip.split('.').pop() || '', x, y + 35)
    })
  }

  getIcon(type: Device['deviceType']) {
    return { router: '🛣', pc: '💻', camera: '📹', nas: '💾', phone: '📱', printer: '🖨', unknown: '❓' }[type]
  }

  handleClick(e: any) {
    const { devices, gatewayIP } = this.props
    const { x, y } = e.detail
    const w = Taro.getSystemInfoSync().windowWidth
    const h = w * 0.7
    const cx = w / 2, cy = h / 2
    const r = Math.min(w, h) * 0.35
    const gateway = devices.find(d => d.ip === gatewayIP) || devices[0]
    const others = devices.filter(d => d.ip !== gateway?.ip)

    // Hit test center
    const dx0 = x - cx, dy0 = y - cy
    if (dx0*dx0 + dy0*dy0 < 28*28) { this.props.onDeviceClick(gateway); return }

    others.forEach((dev, i) => {
      const angle = (2 * Math.PI * i) / others.length - Math.PI / 2
      const nx = cx + r * Math.cos(angle)
      const ny = cy + r * Math.sin(angle)
      const dx = x - nx, dy = y - ny
      if (dx*dx + dy*dy < 22*22) { this.props.onDeviceClick(dev) }
    })
  }
}
```

- [ ] **Step 5: Write src/components/ScanButton/index.tsx**

```typescript
import { Component } from 'react'
import { View, Button, Text } from '@tarojs/components'
import './index.css'

interface Props {
  scanning: boolean
  onScan: () => void
}

export default class ScanButton extends Component<Props> {
  render() {
    return (
      <View className='scan-btn-wrap'>
        <Button className={`scan-btn ${this.props.scanning ? 'scanning' : ''}`} onClick={this.props.onScan} disabled={this.props.scanning}>
          {this.props.scanning ? '⏳ 扫描中...' : '🔍 开始扫描'}
        </Button>
      </View>
    )
  }
}
```

```css
.scan-btn-wrap { padding: 24rpx 32rpx; }
.scan-btn { width: 100%; height: 96rpx; background: linear-gradient(135deg, #00d4ff, #0077ff); color: #fff; font-size: 32rpx; font-weight: 600; border-radius: 48rpx; border: none; }
.scan-btn[disabled] { background: #333; color: #888; }
```

- [ ] **Step 6: Commit**

```bash
git add netprowl-mini/src/stores/ netprowl-mini/src/components/
git commit -m "feat(mini): add deviceStore, DeviceCard, TopoCanvas, ScanButton"
```

---

## Task 8: 小程序: pages (index/devices/topology/history)

**Depends on:** Task 7

- [ ] **Step 1: Write pages/index/index.tsx**

```typescript
import { Component } from 'react'
import { View, Text } from '@tarojs/components'
import { useDeviceStore } from '../../stores/deviceStore'
import { discoverMDNS } from '../../services/mdns'
import { discoverSSDP } from '../../services/udp'
import TopoCanvas from '../../components/TopoCanvas'
import ScanButton from '../../components/ScanButton'
import './index.css'

export default class IndexPage extends Component {
  store = useDeviceStore()

  async componentDidShow() {
    this.store.loadHistory()
  }

  handleScan = async () => {
    if (this.store.scanning) return
    this.store.setScanning(true)

    try {
      // mDNS
      const mdnsDevices = await discoverMDNS()
      mdnsDevices.forEach(d => this.store.addDevice(d))

      // SSDP
      const ssdpDevices = await discoverSSDP()
      ssdpDevices.forEach(d => this.store.addDevice(d))

      this.store.setScanning(false)
    } catch (e) {
      this.store.setScanning(false)
    }
  }

  handleDeviceClick = (device: any) => {
    wx.navigateTo({ url: `/pages/devices/index?ip=${device.ip}` })
  }

  render() {
    const { devices, scanning } = this.store
    const gatewayIP = devices.find(d => d.deviceType === 'router')?.ip || devices[0]?.ip || ''

    return (
      <View className='index-page'>
        <View className='summary-bar'>
          <Text className='summary'>
            {devices.length === 0 ? '点击下方按钮开始局域网扫描' : `发现 ${devices.length} 台设备`}
          </Text>
        </View>
        <View className='topo-wrap'>
          <TopoCanvas devices={devices} gatewayIP={gatewayIP} onDeviceClick={this.handleDeviceClick} />
        </View>
        <ScanButton scanning={scanning} onScan={this.handleScan} />
      </View>
    )
  }
}
```

- [ ] **Step 2: Write pages/devices/index.tsx**

```typescript
import { Component } from 'react'
import { View, Text, ScrollView } from '@tarojs/components'
import { useDeviceStore } from '../../stores/deviceStore'
import DeviceCard from '../../components/DeviceCard'
import './index.css'

export default class DevicesPage extends Component {
  store = useDeviceStore()

  handleClick = (device: any) => {
    wx.navigateTo({ url: `/pages/topology/index?ip=${device.ip}` })
  }

  render() {
    return (
      <View className='devices-page'>
        <ScrollView scrollY className='list'>
          {this.store.devices.map(d => (
            <DeviceCard key={d.id} device={d} onClick={this.handleClick} />
          ))}
        </ScrollView>
      </View>
    )
  }
}
```

- [ ] **Step 3: Write pages/topology/index.tsx**

```typescript
import { Component } from 'react'
import { View, Text } from '@tarojs/components'
import { useDeviceStore } from '../../stores/deviceStore'
import './index.css'

export default class TopologyPage extends Component {
  store = useDeviceStore()

  render() {
    const ip = (wx as any).getCurrentInstance?.()?.router?.params?.ip || ''
    const device = this.store.devices.find(d => d.ip === ip)
    if (!device) return <View className='topo-page'><Text>未找到设备</Text></View>

    return (
      <View className='topo-page'>
        <View className='device-header'>
          <Text className='ip'>{device.ip}</Text>
          <Text className='vendor'>{device.vendor || '未知厂商'}</Text>
          <Text className='risk'>风险: {device.openPorts.length > 3 ? '高' : device.openPorts.length > 0 ? '中' : '低'}</Text>
        </View>
        <View className='ports'>
          {device.openPorts.map((p: any) => (
            <View key={p.number} className='port-tag'>
              <Text className='port-num'>{p.number}</Text>
              <Text className='port-svc'>{p.service || 'unknown'}</Text>
            </View>
          ))}
        </View>
      </View>
    )
  }
}
```

- [ ] **Step 4: Write pages/history/index.tsx**

```typescript
import { Component } from 'react'
import { View, Text, ScrollView } from '@tarojs/components'
import { useDeviceStore } from '../../stores/deviceStore'
import './index.css'

export default class HistoryPage extends Component {
  store = useDeviceStore()

  componentDidShow() {
    this.store.loadHistory()
  }

  formatTime(ts: number) {
    const d = new Date(ts)
    return `${d.getMonth()+1}-${d.getDate()} ${d.getHours()}:${String(d.getMinutes()).padStart(2,'0')}`
  }

  render() {
    const { history } = this.store
    return (
      <View className='history-page'>
        <ScrollView scrollY className='list'>
          {history.length === 0 ? (
            <View className='empty'><Text className='empty-text'>暂无扫描记录</Text></View>
          ) : history.map((snap) => (
            <View key={snap.id} className='snap-item'>
              <View className='snap-dot' />
              <View className='snap-info'>
                <Text className='snap-time'>{this.formatTime(snap.timestamp)}</Text>
                <Text className='snap-range'>{snap.ipRange}</Text>
              </View>
              <Text className='snap-count'>{snap.deviceCount} 台</Text>
            </View>
          ))}
        </ScrollView>
      </View>
    )
  }
}
```

- [ ] **Step 5: Write CSS files for all pages**

```css
/* pages/index/index.css */
.index-page { min-height: 100vh; background: #0f0f1a; }
.summary-bar { padding: 24rpx 32rpx; background: #1a1a2e; }
.summary { color: #00d4ff; font-size: 28rpx; }
.topo-wrap { flex: 1; padding: 24rpx; }
.topo-empty { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 60vw; }
.empty-icon { font-size: 80rpx; margin-bottom: 24rpx; }
.empty-text { color: #fff; font-size: 32rpx; }
```

- [ ] **Step 6: Commit**

```bash
git add netprowl-mini/src/pages/
git commit -m "feat(mini): add index, devices, topology, history pages"
```

---

## Task 9: PC: Tauri 脚手架 + Rust 命令

**Depends on:** Task 4

- [ ] **Step 1: Initialize Tauri project**

```bash
cd /Users/jinguo.zeng/dmall/project/NetProwl/netprowl-pc
npm create tauri-app@latest . -- --template react-ts --manager npm -y
```

Note: If interactive prompt fails, manually create the structure.

- [ ] **Step 2: Create src-tauri/src/main.rs**

```rust
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            scan_tcp,
            scan_mdns,
            scan_ssdp,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
fn scan_tcp(ip_start: String, ip_end: String, ports: Vec<u16>) -> Result<String, String> {
    // 调用 Go core 编译的库或 WASM
    // 简化：返回空 JSON
    Ok(r#"{"devices":[],"summary":{"total":0}}"#)
}

#[tauri::command]
fn scan_mdns() -> Result<String, String> {
    Ok(r#"{"devices":[]}"#)
}

#[tauri::command]
fn scan_ssdp() -> Result<String, String> {
    Ok(r#"{"devices":[]}"#)
}
```

- [ ] **Step 3: Write src-tauri/Cargo.toml**

```toml
[package]
name = "netprowl-pc"
version = "1.0.0"

[dependencies]
tauri = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"

[build-dependencies]
tauri-build = "2"
```

- [ ] **Step 4: Write src-tauri/build.rs**

```rust
fn main() {
    tauri_build::build()
}
```

- [ ] **Step 5: Write src-tauri/tauri.conf.json**

```json
{
  "productName": "NetProwl",
  "version": "1.0.0",
  "window": {
    "title": "NetProwl",
    "width": 1200,
    "height": 800,
    "minWidth": 800,
    "minHeight": 600
  }
}
```

- [ ] **Step 6: Commit**

```bash
git add netprowl-pc/
git commit -m "feat(pc): add Tauri project scaffold"
```

---

## Task 10: PC: React 前端页面

**Depends on:** Task 9

- [ ] **Step 1: Write React App.tsx with scan page**

```tsx
import { useState } from 'react'
import { invoke } from '@tauri-apps/api/core'
import './App.css'

function App() {
  const [ipStart, setIpStart] = useState('192.168.1.1')
  const [ipEnd, setIpEnd] = useState('192.168.1.254')
  const [scanning, setScanning] = useState(false)
  const [devices, setDevices] = useState<any[]>([])

  const handleScan = async () => {
    setScanning(true)
    try {
      const result = await invoke<string>('scan_tcp', {
        ipStart,
        ipEnd,
        ports: [80, 443, 22, 3389, 445, 139, 135],
      })
      const parsed = JSON.parse(result)
      setDevices(parsed.devices || [])
    } catch (e) {
      console.error(e)
    } finally {
      setScanning(false)
    }
  }

  return (
    <div className="app">
      <header className="header">
        <h1>NetProwl</h1>
        <p>局域网安全扫描</p>
      </header>

      <div className="form">
        <div className="field">
          <label>IP 范围</label>
          <div className="range">
            <input value={ipStart} onChange={e => setIpStart(e.target.value)} />
            <span> - </span>
            <input value={ipEnd} onChange={e => setIpEnd(e.target.value)} />
          </div>
        </div>
        <button onClick={handleScan} disabled={scanning}>
          {scanning ? '扫描中...' : '开始扫描'}
        </button>
      </div>

      <div className="device-list">
        {devices.map(d => (
          <div key={d.ip} className={`device-card risk-${d.risk}`}>
            <div className="card-ip">{d.ip}</div>
            <div className="card-vendor">{d.vendor || '未知'}</div>
            <div className="card-ports">
              {d.ports?.map((p: any) => (
                <span key={p.number} className="port-tag">
                  <span className="port-num">{p.number}</span>
                  <span className="port-svc">{p.service}</span>
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export default App
```

- [ ] **Step 2: Write App.css**

```css
.app { min-height: 100vh; background: #0f0f1a; color: #fff; padding: 32px; font-family: -apple-system, sans-serif; }
.header { margin-bottom: 32px; }
.header h1 { font-size: 28px; font-weight: 700; }
.header p { color: #666; font-size: 14px; margin-top: 4px; }
.form { display: flex; flex-direction: column; gap: 16px; margin-bottom: 32px; }
.field label { color: #00d4ff; font-size: 14px; display: block; margin-bottom: 8px; }
.range { display: flex; gap: 8px; }
.range input { flex: 1; background: #1a1a2e; border: 1px solid #2a2a4a; border-radius: 8px; padding: 12px 16px; color: #fff; font-size: 14px; }
button { height: 48px; background: linear-gradient(135deg, #00d4ff, #0077ff); color: #fff; border: none; border-radius: 24px; font-size: 16px; font-weight: 600; cursor: pointer; }
button:disabled { background: #333; color: #888; }
.device-list { display: flex; flex-direction: column; gap: 12px; }
.device-card { background: #1a1a2e; border-radius: 12px; padding: 16px; }
.card-ip { font-size: 16px; font-weight: 600; color: #fff; }
.card-vendor { color: #666; font-size: 12px; margin-top: 4px; }
.card-ports { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
.port-tag { display: flex; align-items: center; gap: 4px; background: #2a2a4a; padding: 4px 10px; border-radius: 6px; }
.port-num { color: #00d4ff; font-size: 13px; font-weight: 600; }
.port-svc { color: #888; font-size: 11px; }
```

- [ ] **Step 3: Commit**

```bash
git add netprowl-pc/src/
git commit -m "feat(pc): add React scan UI"
```

---

## Task 11: 集成 + 验收

- [ ] **Step 1: Verify all builds**

```bash
# Go core
cd /Users/jinguo.zeng/dmall/project/NetProwl/core && go build ./...

# 小程序
cd /Users/jinguo.zeng/dmall/project/NetProwl/netprowl-mini && npm install

# PC
cd /Users/jinguo.zeng/dmall/project/NetProwl/netprowl-pc && npm install && npm run tauri build
```

- [ ] **Step 2: Write integration test doc**

```markdown
# 集成测试文档

## 前置条件
- Go 1.21+
- Node.js 18+
- 微信开发者工具
- Rust 1.70+

## 小程序测试
```bash
cd netprowl-mini
npm install
npm run dev:weapp
```
打开微信开发者工具，导入项目，验证：
- [ ] mDNS 发现设备
- [ ] SSDP 发现设备
- [ ] TCP 白名单端口扫描正常
- [ ] 拓扑图正常渲染
- [ ] 历史记录保存

## PC 测试
```bash
cd netprowl-pc
npm install
npm run tauri dev
```
验证：
- [ ] 全端口 TCP 扫描正常
- [ ] Banner 正确抓取
- [ ] 设备列表正常显示
```

- [ ] **Step 3: Commit**

```bash
git add docs/
git commit -m "docs: add integration test guide"
```

---

## Spec Coverage Check

| Spec 需求 | 实现位置 |
|---------|---------|
| Go core: mDNS 发现 | Task 2 |
| Go core: UDP SSDP | Task 2 |
| Go core: TCP 端口扫描 | Task 1 |
| Go core: Banner 抓取 | Task 3 |
| Go core: 服务指纹规则库 | Task 3 |
| Go core: MAC OUI 厂商库 | Task 4 |
| Go core: IP/子网工具 | Task 4 |
| 小程序: services (mdns/udp/tcp/storage) | Task 6 |
| 小程序: stores + components | Task 7 |
| 小程序: pages (index/devices/topology/history) | Task 8 |
| PC: Tauri 脚手架 + Rust 命令 | Task 9 |
| PC: React 前端 | Task 10 |
| 集成验证 | Task 11 |

无遗漏。
