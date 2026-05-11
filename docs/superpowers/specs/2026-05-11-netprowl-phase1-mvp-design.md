# NetProwl Phase 1 MVP · 扫描引擎 spec

> 状态：已批准
> 日期：2026-05-11
> 目标：扫描引擎跑通，Phase 2 再接 AI

---

## 1. 目标

Phase 1 只做一件事：**扫描引擎跑通**。不接 AI，不做报告生成，先让扫描→结果展示全流程跑起来。

---

## 2. 技术架构

```
┌─────────────────────────┐     ┌─────────────────────────┐
│  netprowl-pc (Taro)    │     │  netprowl-mini (Taro)   │
│  PC 客户端              │     │  微信小程序              │
└───────────┬─────────────┘     └───────────┬─────────────┘
            │ WebSocket                       │ WebSocket
┌───────────▼─────────────┐     ┌───────────▼─────────────┐
│      netprowl-core      │◄───►│      netprowl-core      │
│   (Go, 共享核心库)       │     │   (probe-agent 同进程)  │
│  - mDNS 发现            │     │  - mDNS 发现            │
│  - TCP 扫描             │     │  - TCP 扫描             │
│  - WebSocket 服务端     │     │  - WebSocket 服务端     │
└────────────────────────┘     └─────────────────────────┘
```

**核心决策：**
- Go core 共享给 PC 和小程序两套前端
- Taro 多端，一套代码
- 小程序通过 WebSocket 连接 core（probe-agent 模式）

---

## 3. 项目结构

```
netprowl/
├── core/                    # Go 核心库
│   ├── go.mod
│   ├── scanner.go          # TCP 扫描引擎 + Banner Grabbing
│   ├── mdns.go            # mDNS 服务发现
│   ├── ws/
│   │   ├── server.go      # WebSocket 服务端
│   │   └── types.go       # 共享消息类型
│   ├── types/
│   │   └── types.go       # Device, Port, ScanRequest, ScanResponse
│   └── cmd/
│       └── agent/
│           └── main.go     # probe-agent 可执行文件入口
│
├── netprowl-pc/           # Taro PC 客户端
│   └── src/
│       ├── pages/scan/
│       └── pages/result/
│
├── netprowl-mini/          # Taro 微信小程序
│   └── src/
│       ├── pages/scan/
│       └── pages/result/
│
└── docs/
```

---

## 4. 共享类型 (core/types/types.go)

```go
package types

type Device struct {
    IP       string   `json:"ip"`
    MAC      string   `json:"mac"`
    Vendor   string   `json:"vendor"`
    Hostname string   `json:"hostname"`
    OS       string   `json:"os"`       // "linux" | "windows" | "router" | "unknown"
    Ports    []Port   `json:"ports"`
    Risk     string   `json:"risk"`     // "low" | "medium" | "high" | "critical"
}

type Port struct {
    Number  int    `json:"number"`
    State   string `json:"state"`    // "open" | "closed"
    Service string `json:"service"`  // "http" | "ssh" | "ftp" | "rdp" | ...
    Banner  string `json:"banner"`
}

type ScanRequest struct {
    IPStart string `json:"ip_start"`  // e.g. "192.168.1.1"
    IPEnd   string `json:"ip_end"`    // e.g. "192.168.1.254"
    Ports   []int  `json:"ports"`     // []int{80, 443, 22, 3389}
}

type ScanResponse struct {
    Type    string   `json:"type"`    // "scan_result"
    Devices []Device `json:"devices"`
    Summary Summary  `json:"summary"`
}

type Summary struct {
    TotalDevices int `json:"total_devices"`
    OpenPorts    int `json:"open_ports"`
    HighRisk     int `json:"high_risk"`
}

type WSMessage struct {
    Type    string          `json:"type"`
    Payload json.RawMessage `json:"payload"`
}
```

---

## 5. 核心模块

### 5.1 Scanner (core/scanner.go)

```go
func Scan(ipStart, ipEnd string, ports []int) ([]Device, error)
```

- 并发控制：200 并发（semaphore pattern）
- TCP Connect 扫描，2s 超时
- Banner Grabbing：HTTP/SSH/FTP/RTSP
- 风险评估：基于开放端口数量和危险端口 presence

### 5.2 mDNS (core/mdns.go)

```go
func Discover() ([]Device, error)   // 发现局域网设备
func Broadcast(port int) error      // 广播自身存在（供小程序发现）
```

- 使用 `github.com/grandcat/zeroconf`
- 服务类型：`_netprowl._tcp`

### 5.3 WebSocket 服务端 (core/ws/server.go)

```go
func Serve(port int) error
```

- 处理消息类型：`scan` | `ping`
- 广播扫描进度，流式返回结果

---

## 6. PC 客户端 UI (netprowl-pc)

### 扫描页 (pages/scan/index.tsx)

```
┌────────────────────────────────────────┐
│ NetProwl                    [设置]      │
├────────────────────────────────────────┤
│ IP 范围: [192.168.1.1] - [192.168.1.254]│
│ 端口:   [80,443,22,3389] [+自定义]      │
│                                        │
│         [ 开始扫描 ]                     │
│                                        │
│ 状态: 正在扫描 192.168.1.37 ...         │
│ 进度: ████████░░░░ 45%                 │
└────────────────────────────────────────┘
```

### 结果页 (pages/result/index.tsx)

```
┌────────────────────────────────────────┐
│ ← 返回         扫描结果                 │
├────────────────────────────────────────┤
│ 设备: 12 台  |  开放端口: 28  |  高风险: 2 │
├────────────────────────────────────────┤
│ ● 192.168.1.1  (路由器)                 │
│   厂商: TP-Link  |  风险: 中            │
│   开放端口: 80, 443, 8080              │
│   ──────────────────────────────────── │
│ ● 192.168.1.37  (PC)                   │
│   厂商: Dell  |  风险: 高              │
│   开放端口: 22(ssh), 3389(rdp)         │
└────────────────────────────────────────┘
```

---

## 7. 小程序 UI (netprowl-mini)

同 PC 布局，适配小程序屏幕。用 Taro 共享代码。

---

## 8. 消息协议

### 请求
```json
{ "type": "scan", "payload": { "ip_start": "192.168.1.1", "ip_end": "192.168.1.254", "ports": [80, 443, 22] } }
{ "type": "ping" }
```

### 响应
```json
{ "type": "scan_result", "devices": [...], "summary": {...} }
{ "type": "pong" }
```

---

## 9. 验收标准

- [ ] PC 客户端能发起扫描请求
- [ ] 扫描结果正确显示设备列表
- [ ] Banner 正确抓取（HTTP Server header 等）
- [ ] 小程序能复用同一套核心代码
- [ ] 无 AI，无报告生成（Phase 2）

---

## 10. 下一步

使用 `writing-plans` 拆解实现计划，从 probe-agent 核心开始。
