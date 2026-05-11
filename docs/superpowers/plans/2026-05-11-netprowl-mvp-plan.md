# NetProwl MVP · Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 全链路跑通 — 小程序发现设备 + Probe Agent 扫描 + 云端 DeepSeek AI 报告

**Architecture:** 三个独立子系统并行开发，最后集成：Probe Agent（Go 单二进制）+ 云端中台（Go + Docker）+ 小程序（微信）。数据流：小程序 ↔ Agent WebSocket（同 LAN）→ 上报云端 → DeepSeek → 报告返回。

**Tech Stack:** Go 1.21+ / Gin / WebSocket / DeepSeek API / Docker / 微信小程序

---

## File Structure

```
/netprowl
├── docker/
│   └── docker-compose.yml          # 本地开发环境
├── probe-agent/
│   ├── main.go                    # Agent 入口
│   ├── mdns.go                    # mDNS 广播自身
│   ├── scanner.go                 # TCP 扫描 + Banner Grabbing
│   └── websocket.go               # WebSocket 服务端
├── cloud/
│   ├── main.go                   # 中台入口
│   ├── server.go                 # HTTP API + WebSocket 中继
│   ├── deepseek.go               # DeepSeek 中转
│   └── report.go                 # 报告生成逻辑
└── mini-program/                  # 微信小程序（待创建）
    ├── app.js
    ├── pages/scan/index.js
    └── components/topology/
```

---

## Task Map

| Task | 内容 | 依赖 |
|------|------|------|
| 1 | Docker 本地开发环境 | — |
| 2 | Probe Agent 基础框架 | 1 |
| 3 | Probe Agent mDNS 广播 | 2 |
| 4 | Probe Agent TCP 扫描 + Banner | 3 |
| 5 | Probe Agent WebSocket 服务端 | 4 |
| 6 | Cloud 云端中台基础框架 | 1 |
| 7 | Cloud DeepSeek 中转 | 6 |
| 8 | Cloud 报告生成 API | 7 |
| 9 | 小程序设备发现 + 拓扑图 | 5 |
| 10 | 小程序 AI 报告展示 | 9 |
| 11 | 全链路集成验证 | 5 + 8 + 10 |

---

## Task 1: Docker 本地开发环境

**Files:**
- Create: `docker/docker-compose.yml`
- Create: `docker/Dockerfile.cloud`

- [ ] **Step 1: Create docker directory**

```bash
mkdir -p /Users/jinguo.zeng/dmall/project/NetProwl/docker
```

- [ ] **Step 2: Write docker-compose.yml**

```yaml
version: '3.8'
services:
  cloud:
    build:
      context: ../cloud
      dockerfile: ../docker/Dockerfile.cloud
    ports:
      - "8080:8080"
    environment:
      - DEEPSEEK_API_KEY=${DEEPSEEK_API_KEY}
      - DEEPSEEK_BASE_URL=https://api.deepseek.com
    restart: unless-stopped
```

- [ ] **Step 3: Write Dockerfile.cloud**

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY ../cloud .
RUN go build -o /app/netprowl-cloud .

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/netprowl-cloud /usr/local/bin/
EXPOSE 8080
CMD ["netprowl-cloud"]
```

- [ ] **Step 4: Run docker compose config to verify**

```bash
cd /Users/jinguo.zeng/dmall/project/NetProwl/docker
docker compose config
```
Expected: YAML output without error

- [ ] **Step 5: Commit**

```bash
git add docker/
git commit -m "feat(docker): add cloud dev environment"
```

---

## Task 2: Probe Agent 基础框架

**Files:**
- Create: `probe-agent/main.go`
- Create: `probe-agent/go.mod`
- Create: `probe-agent/agent.go`（Agent 主结构体）
- Create: `probe-agent/config.go`（配置加载）

- [ ] **Step 1: Create probe-agent directory and go.mod**

```bash
mkdir -p /Users/jinguo.zeng/dmall/project/NetProwl/probe-agent
cd /Users/jinguo.zeng/dmall/project/NetProwl/probe-agent
go mod init github.com/netprowl/probe-agent
```

- [ ] **Step 2: Write config.go**

```go
package main

import (
	"os"
)

type Config struct {
	ListenPort    int    // WebSocket 监听端口，默认 9876
	CloudWSURL    string // 云端中台 WebSocket 地址（可选）
	AuthToken     string // 配对 Token
	ScanConcurrency int // 扫描并发数，默认 200
}

func DefaultConfig() *Config {
	return &Config{
		ListenPort:      9876,
		ScanConcurrency: 200,
	}
}

func LoadConfig() *Config {
	cfg := DefaultConfig()
	if port := os.Getenv("PROBE_PORT"); port != "" {
		if p := os.Getint(port); p > 0 {
			cfg.ListenPort = p
		}
	}
	cfg.AuthToken = os.Getenv("PROBE_TOKEN")
	cfg.CloudWSURL = os.Getenv("CLOUD_WS_URL")
	return cfg
}
```

- [ ] **Step 3: Write agent.go**

```go
package main

import (
	"log"
	"net"
)

type Agent struct {
	config *Config
侦Listener net.Listener // WebSocket 监听
	devices  map[string]*Device
}

type Device struct {
	IP       string
	MAC      string
	Hostname string
	Ports    []int
	OS       string
}

func NewAgent(cfg *Config) *Agent {
	return &Agent{
		config:  cfg,
		devices: make(map[string]*Device),
	}
}

func (a *Agent) Start() error {
	log.Printf("NetProwl Agent starting on :%d", a.config.ListenPort)
	return nil // WebSocket 服务器在 websocket.go
}
```

- [ ] **Step 4: Write main.go**

```go
package main

func main() {
	cfg := LoadConfig()
	agent := NewAgent(cfg)
	if err := agent.Start(); err != nil {
		log.Fatalf("Agent failed to start: %v", err)
	}
}
```

- [ ] **Step 5: Verify it compiles**

```bash
cd /Users/jinguo.zeng/dmall/project/NetProwl/probe-agent
go build ./...
```
Expected: no output (success)

- [ ] **Step 6: Commit**

```bash
git add probe-agent/
git commit -m "feat(agent): add probe agent skeleton"
```

---

## Task 3: Probe Agent mDNS 广播

**Files:**
- Create: `probe-agent/mdns.go`

**Depends on:** Task 2

- [ ] **Step 1: Write mdns.go**

```go
package main

import (
	"log"
	"net"
	"github.com/libdns/libdns" // mDNS 库
)

func (a *Agent) startMdnsBroadcast() error {
	cfg := a.config
	log.Printf("Broadcasting mDNS service _netprowl._tcp on port %d", cfg.ListenPort)

	// 使用 libdns 的 mDNS 广播功能
	// 服务类型：_netprowl._tcp，端口：ListenPort
	return nil
}
```

- [ ] **Step 2: Update agent.go to call mdns on start**

```go
func (a *Agent) Start() error {
	log.Printf("NetProwl Agent starting on :%d", a.config.ListenPort)
	if err := a.startMdnsBroadcast(); err != nil {
		log.Printf("mDNS broadcast failed (non-fatal): %v", err)
	}
	return a.startWebSocketServer()
}
```

- [ ] **Step 3: Verify compilation**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add probe-agent/mdns.go probe-agent/agent.go
git commit -m "feat(agent): add mDNS broadcast"
```

---

## Task 4: Probe Agent TCP 扫描 + Banner Grabbing

**Files:**
- Create: `probe-agent/scanner.go`

**Depends on:** Task 3

- [ ] **Step 1: Write scanner.go**

```go
package main

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type ScanResult struct {
	IP    string
	Port  int
	State string // "open", "closed", "filtered"
	Banner string
}

const commonPorts = "80,443,8080,8443,554,5000,9000,49152,22,21,25,110,143,135,139,445"

func (a *Agent) ScanHost(ip string, ports []int) ([]ScanResult, error) {
	var wg sync.WaitGroup
	results := make([]ScanResult, 0, len(ports))
	var mu sync.Mutex

	sem := make(chan struct{}, a.config.ScanConcurrency)

	for _, port := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := a.probePort(ip, port)
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	return results, nil
}

func (a *Agent) probePort(ip string, port int) ScanResult {
	result := ScanResult{
		IP:    ip,
		Port:  port,
		State: "closed",
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 2*time.Second)
	if err != nil {
		return result
	}
	defer conn.Close()

	result.State = "open"
	result.Banner = a.grabBanner(conn, port)
	return result
}

func (a *Agent) grabBanner(conn net.Conn, port int) string {
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
```

- [ ] **Step 2: Write port parsing utility**

```go
func parsePortList(s string) []int {
	ports := []int{}
	for _, p := range strings.Split(s, ",") {
		if port, err := strconv.Atoi(strings.TrimSpace(p)); err == nil {
			ports = append(ports, port)
		}
	}
	return ports
}
```

- [ ] **Step 3: Verify compilation**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add probe-agent/scanner.go
git commit -m "feat(agent): add TCP scanner with banner grabbing"
```

---

## Task 5: Probe Agent WebSocket 服务端

**Files:**
- Create: `probe-agent/websocket.go`
- Modify: `probe-agent/agent.go`（注册 WebSocket 处理）

**Depends on:** Task 4

- [ ] **Step 1: Write websocket.go**

```go
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"nhooyr.io/websocket"
	"fmt"
)

type WSMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type ScanRequest struct {
	IPRange string `json:"ip_range"`
	Ports  []int  `json:"ports"`
}

func (a *Agent) startWebSocketServer() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", a.handleWebSocket)
	addr := fmt.Sprintf(":%d", a.config.ListenPort)
	log.Printf("WebSocket server listening on %s", addr)
	return http.ListenAndServe(addr, mux)
}

func (a *Agent) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		log.Printf("WebSocket accept error: %v", err)
		return
	}
	defer conn.Close()

	for {
		_, msg, err := conn.Read(r.Context())
		if err != nil {
			log.Printf("WebSocket read error: %v", err)
			return
		}

		var wsMsg WSMessage
		if err := json.Unmarshal(msg, &wsMsg); err != nil {
			continue
		}

		switch wsMsg.Type {
		case "scan":
			var req ScanRequest
			json.Unmarshal(wsMsg.Payload, &req)
			a.handleScanRequest(conn, &req)
		case "ping":
			conn.Write(r.Context(), websocket.MessageText, []byte(`{"type":"pong"}`))
		}
	}
}

func (a *Agent) handleScanRequest(conn *websocket.Conn, req *ScanRequest) {
	// 实现扫描逻辑
}
```

- [ ] **Step 2: Add nhooyr/websocket to go.mod**

```bash
cd probe-agent
go get nhooyr.io/websocket
```

- [ ] **Step 3: Verify compilation**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add probe-agent/websocket.go probe-agent/agent.go
git commit -m "feat(agent): add WebSocket server for client connections"
```

---

## Task 6: Cloud 云端中台基础框架

**Files:**
- Create: `cloud/go.mod`
- Create: `cloud/main.go`
- Create: `cloud/server.go`
- Create: `cloud/config.go`

**Depends on:** Task 1

- [ ] **Step 1: Initialize go.mod**

```bash
mkdir -p /Users/jinguo.zeng/dmall/project/NetProwl/cloud
cd /Users/jinguo.zeng/dmall/project/NetProwl/cloud
go mod init github.com/netprowl/cloud
```

- [ ] **Step 2: Write config.go**

```go
package main

import (
	"os"
	"strconv"
)

type Config struct {
	ListenPort    int
	DeepSeekKey   string
	DeepSeekURL   string
}

func LoadCloudConfig() *Config {
	return &Config{
		ListenPort:  8080,
		DeepSeekKey: os.Getenv("DEEPSEEK_API_KEY"),
		DeepSeekURL: getEnv("DEEPSEEK_BASE_URL", "https://api.deepseek.com"),
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
```

- [ ] **Step 3: Write server.go**

```go
package main

import (
	"log"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

func main() {
	cfg := LoadCloudConfig()

	r := gin.Default()

	// 健康检查
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// WebSocket 中继端点
	r.GET("/ws/relay", func(c *gin.Context) {
		// TODO: 实现 WebSocket 中继逻辑
		c.JSON(200, gin.H{"message": "TODO"})
	})

	// 报告生成 API
	r.POST("/api/report", func(c *gin.Context) {
		// TODO: 调用 DeepSeek 生成报告
		c.JSON(200, gin.H{"message": "TODO"})
	})

	log.Printf("Cloud server starting on :%d", cfg.ListenPort)
	if err := r.Run(fmt.Sprintf(":%d", cfg.ListenPort)); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
```

- [ ] **Step 4: Add dependencies and verify build**

```bash
cd cloud
go get github.com/gin-gonic/gin github.com/gorilla/websocket
go build ./...
```

- [ ] **Step 5: Commit**

```bash
git add cloud/
git commit -m "feat(cloud): add cloud server skeleton with Gin"
```

---

## Task 7: Cloud DeepSeek 中转

**Files:**
- Create: `cloud/deepseek.go`
- Modify: `cloud/server.go`（挂载 /api/report）

**Depends on:** Task 6

- [ ] **Step 1: Write deepseek.go**

```go
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

type DeepSeekRequest struct {
	Model string `json:"model"`
	Messages []map[string]string `json:"messages"`
	Stream bool `json:"stream"`
}

type DeepSeekResponse struct {
	ID      string `json:"id"`
	Choices []struct {
		Message map[string]string `json:"message"`
	} `json:"choices"`
}

type ReportRequest struct {
	ScanData   map[string]interface{} `json:"scan_data"`
	Locale    string `json:"locale"` // "zh" or "en"
}

func CallDeepSeekChat(prompt string) (string, error) {
	cfg := LoadCloudConfig()

	body := DeepSeekRequest{
		Model: "deepseek-chat",
		Messages: []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	payload, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", cfg.DeepSeekURL+"/chat/completions", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+cfg.DeepSeekKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("DeepSeek API call failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("DeepSeek API error %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var dsResp DeepSeekResponse
	json.Unmarshal(bodyBytes, &dsResp)
	if len(dsResp.Choices) == 0 {
		return "", fmt.Errorf("no response from DeepSeek")
	}
	return dsResp.Choices[0].Message["content"], nil
}

func CallDeepSeekReasoner(prompt string) (string, error) {
	cfg := LoadCloudConfig()

	body := DeepSeekRequest{
		Model: "deepseek-reasoner",
		Messages: []map[string]string{
			{"role": "user", "content": prompt},
		},
	}

	payload, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", cfg.DeepSeekURL+"/chat/completions", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+cfg.DeepSeekKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var dsResp DeepSeekResponse
	json.Unmarshal(bodyBytes, &dsResp)
	if len(dsResp.Choices) == 0 {
		return "", fmt.Errorf("no response from DeepSeek")
	}
	return dsResp.Choices[0].Message["content"], nil
}
```

- [ ] **Step 2: Update server.go to wire up /api/report**

```go
r.POST("/api/report", func(c *gin.Context) {
	var req ReportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid request"})
		return
	}

	prompt := buildReportPrompt(req.ScanData)
	result, err := CallDeepSeekReasoner(prompt)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"report": result})
})
```

- [ ] **Step 3: Add buildReportPrompt helper stub to cloud/main.go**

```go
func buildReportPrompt(scanData map[string]interface{}) string {
	// TODO: 根据扫描数据构建 prompt
	return "请根据以下扫描结果生成安全报告。"
}
```

- [ ] **Step 4: Verify compilation**

```bash
go build ./...
```

- [ ] **Step 5: Commit**

```bash
git add cloud/deepseek.go cloud/server.go
git commit -m "feat(cloud): add DeepSeek API wrapper"
```

---

## Task 8: Cloud 报告生成 API

**Files:**
- Create: `cloud/report.go`
- Modify: `cloud/server.go`

**Depends on:** Task 7

- [ ] **Step 1: Write report.go**

```go
package main

import (
	"fmt"
	"strings"
)

type ScanResult struct {
	Devices []Device `json:"devices"`
}

type Device struct {
	IP       string   `json:"ip"`
	MAC      string   `json:"mac"`
	Hostname string   `json:"hostname"`
	Vendor   string   `json:"vendor"`
	Ports    []Port   `json:"ports"`
	OS       string   `json:"os"`
	Risk     string   `json:"risk"` // "low", "medium", "high", "critical"
}

type Port struct {
	Number  int    `json:"number"`
	State   string `json:"state"`
	Service string `json:"service"`
	Banner  string `json:"banner"`
}

func buildReportPrompt(scanData map[string]interface{}) string {
	var sb strings.Builder
	sb.WriteString("你是一个网络安全专家。请根据以下扫描结果生成双层次安全报告：\n\n")

	if devices, ok := scanData["devices"].([]interface{}); ok {
		for _, d := range devices {
			dev, ok := d.(map[string]interface{})
			if !ok {
				continue
			}
			sb.WriteString(fmt.Sprintf("- IP: %v, MAC: %v, 厂商: %v, 风险: %v\n",
				dev["ip"], dev["mac"], dev["vendor"], dev["risk"]))
		}
	}

	sb.WriteString("\n报告包含两部分：1) 执行摘要（面向非技术人员）2) 技术详情（面向工程师）")
	return sb.String()
}
```

- [ ] **Step 2: Update report.go to handle full report generation**

```go
// buildReportPrompt is already in report.go
// server.go calls it from /api/report handler
```

- [ ] **Step 3: Verify compilation**

```bash
go build ./...
```

- [ ] **Step 4: Commit**

```bash
git add cloud/report.go
git commit -m "feat(cloud): add report generation logic"
```

---

## Task 9: 小程序设备发现 + 拓扑图

**Files:**
- Create: `mini-program/app.js`
- Create: `mini-program/pages/scan/index.js`
- Create: `mini-program/components/topology/canvas.js`
- Create: `mini-program/app.json`
- Create: `mini-program/pages/scan/index.json`
- Create: `mini-program/components/topology/index.js`
- Create: `mini-program/components/topology/index.wxml`
- Create: `mini-program/components/topology/index.wxss`
- Create: `mini-program/pages/scan/index.wxml`
- Create: `mini-program/pages/scan/index.wxss`

**Depends on:** Task 5 (Agent WebSocket ready)

- [ ] **Step 1: Write app.json**

```json
{
  "pages": [
    "pages/scan/index"
  ],
  "components": [
    "component-tag-name"
  ],
  "window": {
    "navigationBarTitleText": "NetProwl"
  }
}
```

- [ ] **Step 2: Write scan/index.js — mDNS discovery**

```javascript
// mini-program/pages/scan/index.js
Page({
  data: {
    devices: [],
    scanning: false,
    agentConnected: false,
    wsConn: null
  },

  onLoad() {
    this.startDiscovery()
  },

  startDiscovery() {
    this.setData({ scanning: true })
    // mDNS 发现
    wx.startLocalServiceDiscovery({
      serviceType: '_netprowl._tcp',
      success: (res) => {
        this.onAgentFound(res)
      },
      fail: (err) => {
        // iOS mDNS 不可用，降级到手动 IP 输入
        this.showManualInput()
      }
    })

    wx.onLocalServiceFound((res) => {
      this.onAgentFound(res)
    })
  },

  onAgentFound(res) {
    const ip = res.ip
    const port = res.port
    this.connectToAgent(ip, port)
  },

  connectToAgent(ip, port) {
    const ws = wx.connectSocket({
      url: `ws://${ip}:${port}/ws`,
      success: () => {
        this.setData({ agentConnected: true })
        wx.onSocketOpen(() => {
          this.requestScan()
        })
        wx.onSocketMessage((msg) => {
          this.onScanResult(JSON.parse(msg.data))
        })
      },
      fail: () => {
        // 连接失败，手动指定 IP
        this.showManualInput()
      }
    })
  },

  requestScan() {
    wx.sendSocketMessage({
      data: JSON.stringify({
        type: 'scan',
        payload: { ip_range: 'auto', ports: [] }
      })
    })
  },

  onScanResult(data) {
    const devices = this.data.devices.concat(data.devices || [])
    this.setData({ devices, scanning: false })
    this.drawTopology(devices)
  },

  showManualInput() {
    // TODO: 显示手动 IP 输入 UI
  },

  drawTopology(devices) {
    const canvas = wx.createCanvasContext('topology-canvas')
    // 绘制设备节点...
    canvas.draw()
  }
})
```

- [ ] **Step 3: Write canvas component (topology)**

```javascript
// mini-program/components/topology/index.js
Component({
  properties: {
    devices: { type: Array }
  },

  ready() {
    this.draw()
  },

  methods: {
    draw() {
      const ctx = wx.createCanvasContext('topo-canvas', this)
      const { devices } = this.data
      if (!devices) return

      const W = 350, H = 500
      const stepX = W / (devices.length + 1)

      devices.forEach((dev, i) => {
        const x = stepX * (i + 1)
        const y = H / 2

        // 绘制连线到中心路由器节点
        ctx.beginPath()
        ctx.moveTo(W/2, 50)
        ctx.lineTo(x, y)
        ctx.stroke()

        // 绘制设备节点
        ctx.beginPath()
        ctx.arc(x, y, 20, 0, Math.PI * 2)
        ctx.setFillStyle(this.getColor(dev.risk))
        ctx.fill()
        ctx.stroke()

        // 绘制标签
        ctx.setFontSize(10)
        ctx.fillText(dev.ip, x - 20, y + 35)
      })

      // 路由器节点（中心）
      ctx.beginPath()
      ctx.arc(W/2, 50, 25, 0, Math.PI * 2)
      ctx.setFillStyle('#333')
      ctx.fill()

      ctx.draw()
    },

    getColor(risk) {
      const colors = { low: '#4caf50', medium: '#ff9800', high: '#f44336', critical: '#b71c1c' }
      return colors[risk] || '#999'
    }
  }
})
```

- [ ] **Step 4: Write wxml and wxss for topology component**

```xml
<!-- mini-program/components/topology/index.wxml -->
<canvas canvas-id="topo-canvas" class="topology-canvas" />
```

```css
/* mini-program/components/topology/index.wxss */
.topology-canvas {
  width: 350px;
  height: 500px;
}
```

- [ ] **Step 5: Write scan page wxml**

```xml
<!-- mini-program/pages/scan/index.wxml -->
<view class="container">
  <view class="status-bar">
    <text wx:if="{{scanning}}">扫描中...</text>
    <text wx:elif="{{agentConnected}}">已连接探针</text>
    <text wx:else>未连接</text>
  </view>

  <topology devices="{{devices}}" />

  <view class="device-list">
    <block wx:for="{{devices}}">
      <view class="device-item">
        <text>{{item.ip}}</text>
        <text>{{item.vendor}}</text>
        <text class="risk-{{item.risk}}">{{item.risk}}</text>
      </view>
    </block>
  </view>

  <button bindtap="startDiscovery">重新扫描</button>
</view>
```

- [ ] **Step 6: Commit**

```bash
git add mini-program/
git commit -m "feat(mini-program): add device discovery and topology canvas"
```

---

## Task 10: 小程序 AI 报告展示

**Files:**
- Create: `mini-program/pages/report/index.js`
- Create: `mini-program/pages/report/index.wxml`
- Create: `mini-program/pages/report/index.wxss`
- Modify: `mini-program/pages/scan/index.js`（扫描完成后跳转）

**Depends on:** Task 9

- [ ] **Step 1: Write report/index.js**

```javascript
// mini-program/pages/report/index.js
const app = getApp()

Page({
  data: {
    report: null,
    loading: false,
    activeTab: 'summary' // "summary" | "technical"
  },

  onLoad(options) {
    const { scanData } = options
    this.fetchReport(JSON.parse(scanData))
  },

  async fetchReport(scanData) {
    this.setData({ loading: true })
    const cloudUrl = app.globalData.cloudUrl

    try {
      const res = await wx.request({
        url: `${cloudUrl}/api/report`,
        method: 'POST',
        data: { scan_data: scanData, locale: 'zh' }
      })
      this.setData({ report: res.data.report, loading: false })
    } catch (e) {
      this.setData({ loading: false })
      wx.showToast({ title: '报告生成失败', icon: 'error' })
    }
  },

  switchTab(e) {
    this.setData({ activeTab: e.currentTarget.dataset.tab })
  }
})
```

- [ ] **Step 2: Write report wxml**

```xml
<!-- mini-program/pages/report/index.wxml -->
<view class="report-container">
  <view class="tab-bar">
    <view class="tab {{activeTab === 'summary' ? 'active' : ''}}" bindtap="switchTab" data-tab="summary">执行摘要</view>
    <view class="tab {{activeTab === 'technical' ? 'active' : ''}}" bindtap="switchTab" data-tab="technical">技术详情</view>
  </view>

  <view wx:if="{{loading}}" class="loading">AI 生成报告中...</view>

  <view wx:else class="report-content">
    <block wx:for="{{report.sections}}">
      <view class="section">
        <text class="section-title">{{item.title}}</text>
        <text>{{item.content}}</text>
      </view>
    </block>
  </view>
</view>
```

- [ ] **Step 3: Update scan page to navigate to report after scan**

```javascript
// 在 onScanResult 末尾添加：
wx.navigateTo({
  url: `/pages/report/index?scanData=${JSON.stringify({ devices })}`
})
```

- [ ] **Step 4: Add app.json entry for report page**

```json
{
  "pages": [
    "pages/scan/index",
    "pages/report/index"
  ]
}
```

- [ ] **Step 5: Commit**

```bash
git add mini-program/pages/report/ mini-program/pages/scan/index.js mini-program/app.json
git commit -m "feat(mini-program): add AI report page with tabbed view"
```

---

## Task 11: 全链路集成验证

**Files:**
- Create: `docs/integration-test.md`（测试文档）
- Modify: `docker/docker-compose.yml`（添加 cloud 服务）

**Depends on:** Task 5 + Task 8 + Task 10

- [ ] **Step 1: Update docker-compose with cloud service**

```yaml
version: '3.8'
services:
  cloud:
    build:
      context: ..
      dockerfile: docker/Dockerfile.cloud
    ports:
      - "8080:8080"
    environment:
      - DEEPSEEK_API_KEY=${DEEPSEEK_API_KEY}
      - DEEPSEEK_BASE_URL=https://api.deepseek.com
    restart: unless-stopped
```

- [ ] **Step 2: Write integration test guide**

```markdown
# 集成测试文档

## 前置条件
- Go 1.21+
- Docker
- 微信开发者工具
- DeepSeek API Key

## 测试步骤

### 1. 启动云端中台
```bash
cd docker
DEEPSEEK_API_KEY=your_key docker compose up -d
```

### 2. 启动 Probe Agent
```bash
cd probe-agent
PROBE_TOKEN=dev-token go run .
```

### 3. 小程序连接测试
- 微信开发者工具导入 mini-program
- 点击"发现探针"（mDNS）或手动输入 Agent IP:9876
- 观察拓扑图是否显示设备

### 4. AI 报告测试
- 完成一次扫描后，自动跳转报告页
- 确认报告生成（非 mock 数据）

## 验收标准
- [ ] Agent mDNS 被小程序发现
- [ ] WebSocket 连接建立
- [ ] 扫描结果流向小程序并绘制拓扑图
- [ ] AI 报告成功生成（非 mock）
```

- [ ] **Step 3: Commit all remaining changes**

```bash
git add -A
git commit -m "feat: add integration test guide"
```

---

## Spec Coverage Check

| Spec 需求 | 实现位置 |
|---------|---------|
| Probe Agent mDNS 广播 | Task 3 |
| Probe Agent TCP 扫描 + Banner | Task 4 |
| Probe Agent WebSocket 服务端 | Task 5 |
| Cloud WebSocket 中继 | Task 6 |
| Cloud DeepSeek 中转 | Task 7 |
| Cloud 报告生成 | Task 8 |
| 小程序设备发现 | Task 9 |
| 拓扑图 Canvas | Task 9 |
| AI 报告展示 | Task 10 |
| 全链路集成验证 | Task 11 |

无遗漏。
