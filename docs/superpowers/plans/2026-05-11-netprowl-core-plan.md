# NetProwl Go Core 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 搭建 NetProwl Go 扫描核心骨架，6 个模块接口定义 + stub 实现，供小程序版和 PC 版调用。

**Architecture:** Go 1.21+，纯共享库（importable package）。goroutine + channel 并发，模块按职责分离。不绑定网络框架，不做二进制入口。

**Tech Stack:** Go 1.21+

---

## 文件结构

```
core/
├── go.mod
├── types.go                  # 共享类型定义
├── scanner/
│   ├── scanner.go           # Scanner 接口 + 主入口
│   ├── mdns.go              # mDNS 发现
│   ├── ssdp.go              # UDP SSDP
│   ├── tcp.go                # TCP 端口扫描
│   ├── banner.go             # Banner 抓取
│   └── registry.go           # 服务指纹规则库
└── util/
    ├── oui.go               # MAC OUI 厂商库
    └── ip.go                # IP/子网工具
```

---

## 任务列表

### Task 1: 项目骨架 + 类型定义

**Files:**
- Create: `core/go.mod`
- Create: `core/types.go`

- [ ] **Step 1: 创建 core/go.mod**

```go
module github.com/netprowl/core

go 1.21
```

- [ ] **Step 2: 创建 core/types.go**

```go
package core

import "time"

// DeviceType 设备类型
type DeviceType string

const (
	DeviceTypeRouter  DeviceType = "router"
	DeviceTypePC      DeviceType = "pc"
	DeviceTypeCamera  DeviceType = "camera"
	DeviceTypeNAS     DeviceType = "nas"
	DeviceTypePhone   DeviceType = "phone"
	DeviceTypePrinter DeviceType = "printer"
	DeviceTypeUnknown DeviceType = "unknown"
)

// OSType 操作系统类型
type OSType string

const (
	OSTypeLinux   OSType = "linux"
	OSTypeWindows OSType = "windows"
	OSTypeNetwork OSType = "network"
	OSTypeUnknown OSType = "unknown"
)

// DiscoverySource 发现来源
type DiscoverySource string

const (
	DiscoverySourceMDNS DiscoverySource = "mdns"
	DiscoverySourceSSDP DiscoverySource = "ssdp"
	DiscoverySourceTCP  DiscoverySource = "tcp"
)

// PortState 端口状态
type PortState string

const (
	PortStateOpen     PortState = "open"
	PortStateFiltered PortState = "filtered"
	PortStateClosed   PortState = "closed"
)

// Port 端口信息
type Port struct {
	Port    int       `json:"port"`
	Service string    `json:"service,omitempty"`
	State   PortState `json:"state"`
	Banner  string    `json:"banner,omitempty"`
}

// Device 设备信息
type Device struct {
	ID           string           `json:"id"`
	IP           string           `json:"ip"`
	MAC          string           `json:"mac,omitempty"`
	Hostname     string           `json:"hostname,omitempty"`
	Vendor       string           `json:"vendor,omitempty"`
	DeviceType   DeviceType       `json:"deviceType"`
	OS           OSType          `json:"os"`
	OpenPorts    []Port           `json:"openPorts"`
	DiscoveredAt time.Time        `json:"discoveredAt"`
	Sources      []DiscoverySource `json:"sources"`
	TTL          int              `json:"ttl,omitempty"`
}

// ScanResult 扫描结果
type ScanResult struct {
	Devices         []Device `json:"devices"`
	DurationMs     int64    `json:"durationMs"`
	MDNSUnavailable bool     `json:"mdnsUnavailable"`
}
```

- [ ] **Step 3: 提交**

```bash
git add core/go.mod core/types.go
git commit -m "feat(core): add project scaffold and shared types

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 2: Scanner 接口

**Files:**
- Create: `core/scanner/scanner.go`

- [ ] **Step 1: 创建 core/scanner/scanner.go**

```go
package scanner

import (
	"context"
	"github.com/netprowl/core"
)

// Config 扫描配置
type Config struct {
	Subnet         string // 目标子网，如 "192.168.1.0/24"
	TargetIPs      []string // 目标 IP 列表（优先于 Subnet）
	Concurrency    int      // 并发数，默认 100
	TimeoutMs      int      // 单端口超时，默认 2000ms
	WhitePortsOnly bool     // 仅使用白名单端口（小程序用）
}

// Scanner 扫描器接口
type Scanner interface {
	Run(ctx context.Context, cfg Config) (*core.ScanResult, error)
}

// Registry 服务指纹注册表接口
type Registry interface {
	Match(port int, banner string) (service string, deviceType core.DeviceType)
}

// NewScanner 创建默认扫描器
func NewScanner() Scanner {
	return &defaultScanner{}
}

type defaultScanner struct{}

func (s *defaultScanner) Run(ctx context.Context, cfg Config) (*core.ScanResult, error) {
	return &core.ScanResult{
		Devices:    []core.Device{},
		DurationMs: 0,
	}, nil
}
```

- [ ] **Step 2: 提交**

```bash
git add core/scanner/scanner.go
git commit -m "feat(core): add Scanner interface and stub

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 3: 工具函数

**Files:**
- Create: `core/util/oui.go`
- Create: `core/util/ip.go`

- [ ] **Step 1: 创建 core/util/oui.go**

```go
package util

import "strings"

// OUI_MAP MAC 前缀 → 厂商名（精简版，覆盖主流设备）
var OUI_MAP = map[string]string{
	"00:50:56": "VMware",
	"00:0c:29": "VMware",
	"b8:27:eb": "Raspberry Pi",
	"dc:a6:32": "Raspberry Pi",
	"e4:5f:01": "Raspberry Pi",
	"00:1e:68": "Huawei/H3C",
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
	"ac:de:48": "Hikvision",
	"b4:15:13": "Hikvision",
	"00:03:93": "Siemens",
	"00:1b:a2": "Schneider Electric",
}

// LookupVendor 根据 MAC 地址查询厂商
func LookupVendor(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	prefix := strings.ToLower(strings.ReplaceAll(mac[:8], "-", ":"))
	return OUI_MAP[prefix]
}
```

- [ ] **Step 2: 创建 core/util/ip.go**

```go
package util

import (
	"net"
	"strings"
)

// InferSubnet 从本机 IP 推断 /24 子网
func InferSubnet(localIP string) string {
	parts := strings.Split(localIP, ".")
	if len(parts) != 4 {
		return ""
	}
	return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
}

// ExpandSubnet 将子网展开为 IP 列表
func ExpandSubnet(subnet string) []string {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil
	}

	var ips []string
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	return ips
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// IsPrivateIP 判断是否为私有 IP
func IsPrivateIP(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	return p.IsPrivate()
}

// InferOS 根据 TTL 推断操作系统
func InferOS(ttl int) string {
	switch {
	case ttl <= 64:
		return "linux"
	case ttl <= 128:
		return "windows"
	case ttl >= 255:
		return "network"
	default:
		return "unknown"
	}
}
```

- [ ] **Step 3: 提交**

```bash
git add core/util/oui.go core/util/ip.go
git commit -m "feat(core): add util/ip and util/oui

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 4: mDNS 发现模块

**Files:**
- Create: `core/scanner/mdns.go`

- [ ] **Step 1: 创建 core/scanner/mdns.go**

```go
package scanner

import (
	"context"
	"time"

	"github.com/netprowl/core"
)

// MDNSConfig mDNS 扫描配置
type MDNSConfig struct {
	ServiceTypes []string
	Timeout      time.Duration
}

// DefaultMDNSConfig 默认配置
var DefaultMDNSConfig = MDNSConfig{
	ServiceTypes: []string{
		"_http._tcp",
		"_ftp._tcp",
		"_ssh._tcp",
		"_smb._tcp",
		"_airplay._tcp",
		"_googlecast._tcp",
		"_ipp._tcp",
	},
	Timeout: 5 * time.Second,
}

// DiscoverMDNS 发现 mDNS 服务
// 返回发现的设备列表
func DiscoverMDNS(ctx context.Context, cfg MDNSConfig) ([]core.Device, error) {
	// Stub: 暂不实现真实 mDNS 扫描
	// 后续通过 Go mDNS 库实现
	return nil, nil
}
```

- [ ] **Step 2: 提交**

```bash
git add core/scanner/mdns.go
git commit -m "feat(core): add mDNS discovery stub

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 5: UDP SSDP 发现模块

**Files:**
- Create: `core/scanner/ssdp.go`

- [ ] **Step 1: 创建 core/scanner/ssdp.go**

```go
package scanner

import (
	"context"
	"net"
	"time"

	"github.com/netprowl/core"
)

const (
	SSDP_ADDR = "239.255.255.250"
	SSDP_PORT = 1900
	M_SEARCH  = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
)

// SSDPConfig SSDP 扫描配置
type SSDPConfig struct {
	Timeout time.Duration
}

// DefaultSSDPConfig 默认配置
var DefaultSSDPConfig = SSDPConfig{
	Timeout: 5 * time.Second,
}

// DiscoverSSDP 发现 SSDP/UPnP 设备
func DiscoverSSDP(ctx context.Context, cfg SSDPConfig) ([]core.Device, error) {
	// Stub: 暂不实现真实 SSDP 扫描
	// 后续通过 UDP socket 实现
	return nil, nil
}

// parseSSDPResponse 解析 SSDP 响应
func parseSSDPResponse(banner string, ip string) *core.Device {
	// TODO: 实现解析逻辑
	return nil
}
```

- [ ] **Step 2: 提交**

```bash
git add core/scanner/ssdp.go
git commit -m "feat(core): add SSDP discovery stub

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 6: TCP 端口扫描模块

**Files:**
- Create: `core/scanner/tcp.go`

- [ ] **Step 1: 创建 core/scanner/tcp.go**

```go
package scanner

import (
	"context"
	"net"
	"time"

	"github.com/netprowl/core"
)

// WHITE_PORTS 白名单端口（微信小程序允许）
var WHITE_PORTS = []int{80, 443, 8080, 8443, 554, 5000, 9000, 49152}

// TCPConfig TCP 扫描配置
type TCPConfig struct {
	Ports       []int // 目标端口，为空则使用 WHITE_PORTS
	Concurrency int   // 并发连接数，默认 100
	TimeoutMs   int   // 单端口超时(ms)，默认 2000
}

// DefaultTCPConfig 默认配置（白名单端口）
var DefaultTCPConfig = TCPConfig{
	Ports:       WHITE_PORTS,
	Concurrency: 100,
	TimeoutMs:   2000,
}

// ProbeTCPPorts 扫描单个 IP 的端口
func ProbeTCPPorts(ctx context.Context, ip string, cfg TCPConfig) ([]core.Port, error) {
	if len(cfg.Ports) == 0 {
		cfg.Ports = WHITE_PORTS
	}
	// Stub: 暂不实现真实 TCP 扫描
	// 后续通过 net.DialTimeout 实现
	return nil, nil
}

// ProbeTCPPort 探测单个端口
func ProbeTCPPort(ctx context.Context, ip string, port int, timeout time.Duration) (core.Port, error) {
	// Stub
	return core.Port{}, nil
}
```

- [ ] **Step 2: 提交**

```bash
git add core/scanner/tcp.go
git commit -m "feat(core): add TCP port scanner stub

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 7: Banner 抓取模块

**Files:**
- Create: `core/scanner/banner.go`

- [ ] **Step 1: 创建 core/scanner/banner.go**

```go
package scanner

import (
	"context"
	"net"
	"time"

	"github.com/netprowl/core"
)

// BannerConfig Banner 抓取配置
type BannerConfig struct {
	TimeoutMs int
}

// DefaultBannerConfig 默认配置
var DefaultBannerConfig = BannerConfig{
	TimeoutMs: 3000,
}

// GrabBanner 抓取服务 banner
// 支持 HTTP、SSH、FTP、SMTP 等协议的 banner 提取
func GrabBanner(ctx context.Context, ip string, port int, cfg BannerConfig) (string, error) {
	if cfg.TimeoutMs <= 0 {
		cfg.TimeoutMs = 3000
	}
	// Stub: 暂不实现
	// 后续按协议类型发送探针并读取响应
	return "", nil
}

// grabHTTPBanner HTTP banner 抓取
func grabHTTPBanner(ctx context.Context, ip string, port int, timeout time.Duration) (string, error) {
	return "", nil
}

// grabSSHBanner SSH banner 抓取
func grabSSHBanner(ctx context.Context, ip string, port int, timeout time.Duration) (string, error) {
	return "", nil
}
```

- [ ] **Step 2: 提交**

```bash
git add core/scanner/banner.go
git commit -m "feat(core): add banner grabbing stub

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 8: 服务指纹规则库

**Files:**
- Create: `core/scanner/registry.go`

- [ ] **Step 1: 创建 core/scanner/registry.go**

```go
package scanner

import (
	"strings"

	"github.com/netprowl/core"
)

// ServiceRule 单条服务指纹规则
type ServiceRule struct {
	ID             string          `json:"id"`
	Port           int             `json:"port"`
	BannerContains string          `json:"bannerContains,omitempty"`
	Service        string          `json:"service"`
	DeviceType     core.DeviceType `json:"deviceType"`
}

// DefaultRegistry 默认服务指纹注册表
var DefaultRegistry = []ServiceRule{
	{ID: "http", Port: 80, BannerContains: "", Service: "HTTP", DeviceType: core.DeviceTypeUnknown},
	{ID: "https", Port: 443, BannerContains: "", Service: "HTTPS", DeviceType: core.DeviceTypeUnknown},
	{ID: "ssh", Port: 22, BannerContains: "SSH", Service: "SSH", DeviceType: core.DeviceTypeUnknown},
	{ID: "ftp", Port: 21, BannerContains: "FTP", Service: "FTP", DeviceType: core.DeviceTypeUnknown},
	{ID: "hikvision-camera", Port: 554, BannerContains: "Hikvision", Service: "Hikvision Camera", DeviceType: core.DeviceTypeCamera},
	{ID: "synology-nas", Port: 5000, BannerContains: "Synology", Service: "Synology NAS", DeviceType: core.DeviceTypeNAS},
	{ID: "rtsp", Port: 554, BannerContains: "RTSP", Service: "RTSP Stream", DeviceType: core.DeviceTypeCamera},
	{ID: "http-proxy", Port: 8080, BannerContains: "", Service: "HTTP Proxy", DeviceType: core.DeviceTypeUnknown},
	{ID: "upnp", Port: 1900, BannerContains: "UPnP", Service: "UPnP", DeviceType: core.DeviceTypeUnknown},
}

// Match 根据端口 + banner 匹配服务
func Match(port int, banner string) (service string, deviceType core.DeviceType) {
	for _, rule := range DefaultRegistry {
		if rule.Port != port {
			continue
		}
		if rule.BannerContains != "" && strings.Contains(banner, rule.BannerContains) {
			return rule.Service, rule.DeviceType
		}
		if rule.BannerContains == "" {
			return rule.Service, rule.DeviceType
		}
	}
	return "unknown", core.DeviceTypeUnknown
}
```

- [ ] **Step 2: 提交**

```bash
git add core/scanner/registry.go
git commit -m "feat(core): add service fingerprint registry

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Self-Review Checklist

1. **Spec coverage:**
   - [x] C1 mDNS → Task 4
   - [x] C2 UDP SSDP → Task 5
   - [x] C3 TCP 端口扫描 → Task 6
   - [x] C4 Banner 抓取 → Task 7
   - [x] C5 服务指纹 → Task 8
   - [x] C6 MAC OUI → Task 3 (util/oui.go)
   - [x] 文件结构符合规格书 3.3

2. **Placeholder scan:** 所有 stub 标注 "Stub: 暂不实现"，"TODO:" 标注后续实现点。

3. **Type consistency:** `core.Device`、`core.Port`、`core.ScanResult` 在 types.go 统一管理，所有模块引用一致。

---

**Plan complete.** 保存至 `docs/superpowers/plans/2026-05-11-netprowl-core-plan.md`

**两个执行选项：**

**1. Subagent-Driven (推荐)** — 每 task 派遣独立 subagent，完成后 review，循环迭代

**2. Inline Execution** — 本 session 内批量执行，checkpoint review

选哪个？