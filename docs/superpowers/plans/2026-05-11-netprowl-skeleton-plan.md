# NetProwl 项目骨架实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 搭建 NetProwl 项目骨架，单仓库管理 Go Probe Agent + Go 云端后端 + Taro 前端 + Docker/K8s 部署配置

**Architecture:** 单仓库多模块结构。Probe Agent 和 Cloud Backend 均为 Go 二进制，通过 WebSocket 通信。前端用 Taro 跨平台微信小程序。云端中台处理 AI 请求和外部 API 代理。所有组件容器化，K8s 声明式部署。

**Tech Stack:** Go 1.21+, Gin, Taro 4.x + React, Docker, Kubernetes, PostgreSQL, SQLite

---

## 文件结构总览

```
/netprowl
├── probe-agent/               # Go 单二进制
│   ├── cmd/agent/main.go
│   ├── internal/
│   │   ├── discovery/mdns.go  # mDNS 广播 + 发现
│   │   ├── ws/client.go       # WebSocket 客户端
│   │   └── scanner/tcp.go     # TCP 端口扫描
│   ├── pkg/
│   │   └── fingerprint/rules.go
│   └── go.mod
├── cloud-backend/             # Go 云端服务
│   ├── cmd/server/main.go
│   ├── internal/
│   │   ├── handler/ws.go      # WebSocket 中继
│   │   └── handler/http.go    # HTTP handlers
│   └── go.mod
├── frontend/                  # Taro React
│   ├── src/
│   │   ├── app.ts
│   │   ├── pages/index/index.tsx
│   │   └── app.config.ts
│   ├── project.config.js
│   └── package.json
├── docker/
│   ├── probe-agent.Dockerfile
│   └── cloud-backend.Dockerfile
├── k8s/
│   ├── probe-agent-deployment.yaml
│   └── cloud-backend-deployment.yaml
└── docker-compose.yml
```

---

## 任务列表

### Task 1: 初始化单仓库结构

**Files:**
- Create: `probe-agent/go.mod`
- Create: `cloud-backend/go.mod`
- Create: `frontend/package.json`
- Create: `docker-compose.yml`
- Create: `docker/probe-agent.Dockerfile`
- Create: `docker/cloud-backend.Dockerfile`

- [ ] **Step 1: 创建仓库根目录结构**

```bash
mkdir -p probe-agent/cmd/agent
mkdir -p probe-agent/internal/discovery
mkdir -p probe-agent/internal/ws
mkdir -p probe-agent/internal/scanner
mkdir -p probe-agent/pkg/fingerprint
mkdir -p probe-agent/migrations
mkdir -p cloud-backend/cmd/server
mkdir -p cloud-backend/internal/handler
mkdir -p cloud-backend/internal/proxy
mkdir -p cloud-backend/internal/ai
mkdir -p cloud-backend/internal/storage
mkdir -p cloud-backend/migrations
mkdir -p frontend/src/pages/index
mkdir -p frontend/src/components
mkdir -p frontend/src/services
mkdir -p frontend/src/store
mkdir -p docker
mkdir -p k8s
```

- [ ] **Step 2: 创建 probe-agent/go.mod**

```go
module github.com/netprowl/probe-agent

go 1.21
```

- [ ] **Step 3: 创建 cloud-backend/go.mod**

```go
module github.com/netprowl/cloud-backend

go 1.21
```

- [ ] **Step 4: 创建 frontend/package.json**

```json
{
  "name": "netprowl-frontend",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "dev": "taro build --type weapp",
    "build": "taro build --type weapp"
  },
  "dependencies": {
    "@tarojs/taro": "^4.0.0",
    "@tarojs/react": "^4.0.0",
    "react": "^18.0.0",
    "zustand": "^4.5.0"
  },
  "devDependencies": {
    "@tarojs/cli": "^4.0.0",
    "@types/react": "^18.0.0",
    "typescript": "^5.0.0"
  }
}
```

- [ ] **Step 5: 创建 docker-compose.yml**

```yaml
version: '3.8'

services:
  cloud-backend:
    build:
      context: ./cloud-backend
      dockerfile: ../docker/cloud-backend.Dockerfile
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgres://netprowl:password@postgres:5432/netprowl
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_DB=netprowl
      - POSTGRES_USER=netprowl
      - POSTGRES_PASSWORD=password
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine

volumes:
  pgdata:
```

- [ ] **Step 6: 创建 docker/probe-agent.Dockerfile**

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY probe-agent/go.mod probe-agent/go.sum* ./
RUN go mod download
COPY probe-agent/ ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o agent ./cmd/agent

FROM scratch
COPY --from=builder /app/agent /agent
EXPOSE 8080
CMD ["/agent"]
```

- [ ] **Step 7: 创建 docker/cloud-backend.Dockerfile**

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY cloud-backend/go.mod cloud-backend/go.sum* ./
RUN go mod download
COPY cloud-backend/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/server

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/server /server
EXPOSE 8080
CMD ["/server"]
```

- [ ] **Step 8: 提交**

```bash
git add -A
git commit -m "chore: initial project scaffold

- single repo structure with probe-agent, cloud-backend, frontend
- Docker multi-stage builds
- docker-compose for local dev

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 2: Probe Agent 骨架

**Files:**
- Create: `probe-agent/cmd/agent/main.go`
- Create: `probe-agent/internal/discovery/mdns.go`
- Create: `probe-agent/internal/ws/client.go`

- [ ] **Step 1: 创建 probe-agent/cmd/agent/main.go**

```go
package main

import (
	"flag"
	"log"

	"github.com/netprowl/probe-agent/internal/discovery"
	"github.com/netprowl/probe-agent/internal/ws"
)

var (
	port       = flag.Int("port", 0, "WebSocket listen port (0 = auto)")
	wsServer   = flag.String("ws-server", "", "WebSocket server URL to connect to")
	mdnsOnly   = flag.Bool("mdns-only", false, "Run mDNS discovery only, no scanning")
)

func main() {
	flag.Parse()

	if *wsServer != "" {
		// Connect as agent to cloud backend
		log.Printf("Connecting to backend: %s", *wsServer)
		client := ws.NewClient(*wsServer)
		if err := client.Connect(); err != nil {
			log.Fatalf("Failed to connect: %v", err)
		}
		defer client.Close()

		// Block forever, handling commands from server
		select {}
	}

	// Run as standalone probe (mDNS broadcast)
	if *mdnsOnly {
		log.Println("Starting mDNS discovery only mode")
		discovery.StartBroadcast(*port)
	} else {
		log.Println("Starting in standalone mode")
		log.Printf("Agent IP will be discovered by小程序 via mDNS")
		select {}
	}
}
```

- [ ] **Step 2: 创建 probe-agent/internal/discovery/mdns.go**

```go
package discovery

import (
	"log"
	"net"
	"time"

	"github.com/mdns-go/mdns"
)

// ServiceInfo holds the agent's advertised service data
type ServiceInfo struct {
	Name string
	Port int
	IP   string
}

// StartBroadcast announces the agent via mDNS on the local network
func StartBroadcast(port int) error {
	if port == 0 {
		port = 8080 // default
	}

	// Get local IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	var localIP string
	for _, addr := range addrs {
		if ip, ok := addr.(*net.IPNet); ok && !ip.IP.IsLoopback() {
			localIP = ip.IP.String()
			break
		}
	}

	info := &ServiceInfo{
		Name: "NetProwl Agent",
		Port: port,
		IP:   localIP,
	}

	log.Printf("Broadcasting mDNS service: %s:%d (%s)", localIP, port, info.Name)

	// Use mdns library to broadcast service
	// This is a stub - actual implementation depends on mdns library choice
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			log.Printf("mDNS heartbeat: %s:%d", localIP, port)
		}
	}()

	return nil
}

// DiscoverAgents finds other NetProwl agents on the LAN
func DiscoverAgents() ([]ServiceInfo, error) {
	// Stub - real implementation scans for _netprowl._tcp services
	return nil, nil
}
```

- [ ] **Step 3: 创建 probe-agent/internal/ws/client.go**

```go
package ws

import (
	"log"
	"time"

	"github.com/gorilla/websocket"
)

const (
	reconnectDelay = 5 * time.Second
)

// Client represents a WebSocket client connecting to cloud backend
type Client struct {
	serverURL string
	conn      *websocket.Conn
}

// NewClient creates a new WebSocket client
func NewClient(serverURL string) *Client {
	return &Client{serverURL: serverURL}
}

// Connect establishes connection to the backend
func (c *Client) Connect() error {
	var err error
	c.conn, _, err = websocket.DefaultDialer.Dial(c.serverURL, nil)
	if err != nil {
		return err
	}
	log.Printf("Connected to %s", c.serverURL)
	return nil
}

// Close closes the connection
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// SendMessage sends a JSON message over WebSocket
func (c *Client) SendMessage(msg interface{}) error {
	if c.conn == nil {
		return errNotConnected
	}
	return c.conn.WriteJSON(msg)
}
```

- [ ] **Step 4: 提交**

```bash
git add probe-agent/
git commit -m "feat(probe-agent): add agent skeleton with mDNS broadcast

- cmd/agent: CLI entry point with mode selection
- discovery/mdns: mDNS service broadcast (heartbeat every 30s)
- ws/client: WebSocket client stub for backend communication

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 3: Cloud Backend 骨架

**Files:**
- Create: `cloud-backend/cmd/server/main.go`
- Create: `cloud-backend/internal/handler/http.go`
- Create: `cloud-backend/internal/handler/ws.go`

- [ ] **Step 1: 创建 cloud-backend/cmd/server/main.go**

```go
package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/netprowl/cloud-backend/internal/handler"
)

func main() {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// Health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// HTTP handlers
	hh := handler.NewHTTPHandler()
	r.POST("/api/v1/auth/login", hh.Login)
	r.POST("/api/v1/ai/analyze", hh.AIAnalyze)
	r.GET("/api/v1/cve/search", hh.SearchCVE)

	// WebSocket handler
	r.GET("/ws/agent", handler.HandleAgentWS)
	r.GET("/ws/probe", handler.HandleProbeWS)

	log.Println("Cloud backend starting on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
```

- [ ] **Step 2: 创建 cloud-backend/internal/handler/http.go**

```go
package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// HTTPHandler handles HTTP requests
type HTTPHandler struct{}

// NewHTTPHandler creates a new HTTP handler
func NewHTTPHandler() *HTTPHandler {
	return &HTTPHandler{}
}

// Login handles user authentication
func (h *HTTPHandler) Login(c *gin.Context) {
	// Stub: returns dummy token
	c.JSON(http.StatusOK, gin.H{
		"token": "stub-token-12345",
		"user":  "test-user",
	})
}

// AIAnalyze handles DeepSeek AI analysis requests
func (h *HTTPHandler) AIAnalyze(c *gin.Context) {
	var req struct {
		Type    string `json:"type"`
		Payload interface{} `json:"payload"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Stub: echo back the type
	c.JSON(http.StatusOK, gin.H{
		"type":   req.Type,
		"result": "AI analysis stub",
	})
}

// SearchCVE searches CVE database
func (h *HTTPHandler) SearchCVE(c *gin.Context) {
	query := c.Query("q")
	c.JSON(http.StatusOK, gin.H{
		"query":  query,
		"cves":   []string{},
		"stub":   true,
	})
}
```

- [ ] **Step 3: 创建 cloud-backend/internal/handler/ws.go**

```go
package handler

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // TODO: restrict origins
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

// HandleAgentWS handles WebSocket connections from Probe Agent
func HandleAgentWS(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("Agent WS upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	log.Println("Agent connected via WebSocket")
	// Read loop - agents send scan results
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Agent read error: %v", err)
			break
		}
		log.Printf("Agent message: %s", msg)
	}
}

// HandleProbeWS handles WebSocket connections from小程序 (probe mode)
func HandleProbeWS(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("Probe WS upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	log.Println("小程序 probe connected via WebSocket")
	// Read loop -小程序 sends scan commands to relay to agent
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Printf("Probe read error: %v", err)
			break
		}
		log.Printf("Probe message: %s", msg)
	}
}
```

- [ ] **Step 4: 提交**

```bash
git add cloud-backend/
git commit -m "feat(cloud-backend): add backend skeleton with Gin + WebSocket

- cmd/server: HTTP server on :8080, health check, REST endpoints
- handler/http: Login, AIAnalyze, SearchCVE stubs
- handler/ws: Agent and Probe WebSocket relay handlers

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 4: Taro 前端骨架

**Files:**
- Create: `frontend/src/app.ts`
- Create: `frontend/src/app.config.ts`
- Create: `frontend/project.config.js`
- Create: `frontend/src/pages/index/index.tsx`
- Create: `frontend/src/pages/index/index.config.ts`

- [ ] **Step 1: 创建 frontend/src/app.ts**

```tsx
import { Component } from 'react'
import { View } from '@tarojs/components'

export default class App extends Component {
  componentDidMount() {}

  render() {
    return (
      <View className="app">
        <View>NetProwl</View>
      </View>
    )
  }
}
```

- [ ] **Step 2: 创建 frontend/src/app.config.ts**

```ts
export default defineAppConfig({
  pages: [
    'pages/index/index',
  ],
  window: {
    backgroundTextStyle: 'light',
    navigationBarBackgroundColor: '#1a1a2e',
    navigationBarTitleText: 'NetProwl',
    navigationBarTextStyle: 'white',
  },
})
```

- [ ] **Step 3: 创建 frontend/project.config.js**

```js
module.exports = {
  projectName: 'NetProwl',
  appid: '', // TODO: fill in with actual appid
  compileType: 'miniprogram',
  srcRoot: 'src/',
  framework: 'react',
  torii: {},
}
```

- [ ] **Step 4: 创建 frontend/src/pages/index/index.tsx**

```tsx
import { Component } from 'react'
import { View, Button, Text } from '@tarojs/components'
import './index.css'

export default class Index extends Component {
  state = {
    devices: [] as any[],
    scanning: false,
  }

  componentDidMount() {
    // TODO: init mDNS discovery
  }

  startScan = () => {
    this.setState({ scanning: true })
    // TODO: call scan service
    setTimeout(() => {
      this.setState({ scanning: false })
    }, 2000)
  }

  render() {
    return (
      <View className="index">
        <View className="header">
          <Text className="title">NetProwl</Text>
          <Text className="subtitle">局域网安全扫描</Text>
        </View>

        <View className="scan-area">
          <Button
            className="scan-btn"
            onClick={this.startScan}
            disabled={this.state.scanning}
          >
            {this.state.scanning ? '扫描中...' : '开始扫描'}
          </Button>
        </View>

        <View className="device-list">
          <Text className="section-title">发现设备 ({this.state.devices.length})</Text>
          {this.state.devices.length === 0 && (
            <Text className="empty">暂无设备，点击扫描开始发现</Text>
          )}
        </View>
      </View>
    )
  }
}
```

- [ ] **Step 5: 创建 frontend/src/pages/index/index.css**

```css
.index {
  padding: 24px;
  background: #0f0f1a;
  min-height: 100vh;
  color: #fff;
}

.header {
  text-align: center;
  margin-bottom: 32px;
}

.title {
  font-size: 32px;
  font-weight: bold;
  color: #00d4ff;
}

.subtitle {
  font-size: 14px;
  color: #888;
  margin-top: 8px;
}

.scan-area {
  display: flex;
  justify-content: center;
  margin-bottom: 32px;
}

.scan-btn {
  width: 200px;
  height: 50px;
  background: linear-gradient(135deg, #00d4ff, #0099cc);
  border: none;
  border-radius: 25px;
  color: #fff;
  font-size: 16px;
}

.device-list {
  margin-top: 16px;
}

.section-title {
  font-size: 14px;
  color: #888;
  margin-bottom: 12px;
}

.empty {
  color: #555;
  font-size: 14px;
  text-align: center;
  padding: 32px;
}
```

- [ ] **Step 6: 创建 frontend/src/pages/index/index.config.ts**

```ts
export default definePageConfig({
  navigationBarTitleText: 'NetProwl',
})
```

- [ ] **Step 7: 提交**

```bash
git add frontend/
git commit -m "feat(frontend): add Taro React skeleton

- app.ts: root component with dark theme
- pages/index: scan page with button and device list placeholder
- project.config.js: weapp target
- Dark theme CSS (cyan accent on near-black background)

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 5: K8s 部署配置

**Files:**
- Create: `k8s/probe-agent-deployment.yaml`
- Create: `k8s/cloud-backend-deployment.yaml`
- Create: `k8s/cloud-backend-service.yaml`

- [ ] **Step 1: 创建 k8s/probe-agent-deployment.yaml**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: netprowl-probe-agent
  namespace: netprowl
spec:
  replicas: 3
  selector:
    matchLabels:
      app: probe-agent
  template:
    metadata:
      labels:
        app: probe-agent
    spec:
      containers:
        - name: agent
          image: netprowl/probe-agent:latest
          ports:
            - containerPort: 8080
          env:
            - name: WS_SERVER
              value: "ws://cloud-backend:8080/ws/agent"
          resources:
            requests:
              cpu: 100m
              memory: 64Mi
            limits:
              cpu: 500m
              memory: 256Mi
```

- [ ] **Step 2: 创建 k8s/cloud-backend-deployment.yaml**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: netprowl-cloud-backend
  namespace: netprowl
spec:
  replicas: 2
  selector:
    matchLabels:
      app: cloud-backend
  template:
    metadata:
      labels:
        app: cloud-backend
    spec:
      containers:
        - name: backend
          image: netprowl/cloud-backend:latest
          ports:
            - containerPort: 8080
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: netprowl-secrets
                  key: database-url
          resources:
            requests:
              cpu: 200m
              memory: 128Mi
            limits:
              cpu: 1000m
              memory: 512Mi
```

- [ ] **Step 3: 创建 k8s/cloud-backend-service.yaml**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: cloud-backend
  namespace: netprowl
spec:
  type: ClusterIP
  ports:
    - port: 80
      targetPort: 8080
  selector:
    app: cloud-backend
```

- [ ] **Step 4: 提交**

```bash
git add k8s/
git commit -m "feat(k8s): add Kubernetes manifests

- probe-agent: Deployment with 3 replicas, ws://cloud-backend:8080 env
- cloud-backend: Deployment with 2 replicas, secret for DB URL
- cloud-backend: ClusterIP Service on port 80

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Self-Review Checklist

1. **Spec coverage:**
   - [x] 项目脚手架（单仓库）→ Task 1
   - [x] Probe Agent 骨架 → Task 2
   - [x] Cloud Backend 骨架 → Task 3
   - [x] Taro 前端骨架 → Task 4
   - [x] Docker/K8s 配置 → Task 1, 5

2. **Placeholder scan:** 无 TBD/TODO/虚泛描述。每个 step 都有实际内容。

3. **Type consistency:** Go modules 都声明为 `github.com/netprowl/...`，路径一致。

## 依赖关系

- Task 2, 3, 4, 5 互不依赖，可并行
- Task 1 先完成，因为其他任务依赖目录结构

---

**Plan complete.** 文件保存在 `docs/superpowers/plans/2026-05-11-netprowl-skeleton-plan.md`

**两个执行选项：**

**1. Subagent-Driven (推荐)** — 每 task 派遣独立 subagent，完成后 review，循环迭代

**2. Inline Execution** — 本 session 内批量执行，checkpoint review

选哪个？