# NetProwl 项目骨架设计

**日期**：2026-05-11
**范围**：Phase 0（骨架）+ Phase 1（MVP）

---

## 技术栈

| 组件 | 技术 | 说明 |
|------|------|------|
| Probe Agent | Go 1.21+ | 单二进制，全平台（linux/darwin/windows/arm） |
| 云端中台 | Go + Gin | WebSocket中继、DeepSeek代理、Shodan/FOFA转发 |
| 前端 | Taro + React | 跨平台（微信/H5），未来可扩其他小程序 |
| 部署 | Docker + Kubernetes | 容器化，K8s声明式部署 |
| 数据库 | PostgreSQL（云端）+ SQLite（Agent本地） | CVE库、用户数据云端，扫描历史本地 |

---

## 项目结构（单仓库）

```
/netprowl
├── probe-agent/           # Go 单二进制，跨平台编译
│   ├── cmd/agent/          # 入口点
│   ├── internal/
│   │   ├── scanner/        # 端口扫描、Banner抓取
│   │   ├── discovery/      # mDNS服务发现
│   │   ├── security/       # 弱密码检测、TLS审计
│   │   └── ws/             # WebSocket客户端
│   ├── pkg/
│   │   └── fingerprint/    # 服务指纹规则库
│   └── migrations/         # SQLite schema
├── cloud-backend/          # Go 云端服务
│   ├── cmd/server/         # 入口点
│   ├── internal/
│   │   ├── handler/        # HTTP/WebSocket handlers
│   │   ├── proxy/          # DeepSeek、Shodan/FOFA代理
│   │   ├── ai/             # AI层（banner解析、攻击链、报告生成）
│   │   ├── user/           # 用户管理、订阅
│   │   └── storage/        # PostgreSQL + Redis
│   └── migrations/
├── frontend/               # Taro React
│   ├── src/
│   │   ├── pages/          # 页面
│   │   ├── components/     # 组件（拓扑图、设备卡片）
│   │   ├── services/       # API调用、WebSocket连接
│   │   └── store/          # 状态管理
│   └── taro-app.config.ts
├── shared/                 # 共享类型/proto
│   └── proto/
├── docker/                 # Dockerfile + docker-compose
│   └── k8s/                # K8s manifests
└── docs/superpowers/specs/ # 设计文档
```

---

## 核心接口设计

### Probe Agent ↔ 小程序（WebSocket）

```
ws://<agent-ip>:<port>/connect?token=<pairing-token>
```

消息格式（JSON）：
- `{ "type": "scan_start", "target": "192.168.1.0/24", "ports": [...] }`
- `{ "type": "device_found", "ip": "...", "mac": "...", "ports": [...] }`
- `{ "type": "scan_complete", "devices": [...] }`

### 小程序 ↔ 云端中台（HTTPS）

- `POST /api/v1/auth/login` — 用户登录
- `POST /api/v1/ai/analyze` — DeepSeek AI分析请求
- `GET /api/v1/cve/search` — CVE查询

---

## 关键架构决策

1. **mDNS服务发现** — Agent 启动后广播 `_netprowl._tcp`，小程序在同一局域网内自动发现并配对
2. **配对Token** — 一次性Token + PIN码防止同局域网劫持
3. **AI双轨** — 规则引擎精确匹配优先，AI处理模糊情况，降低DeepSeek调用频次
4. **Banner哈希缓存** — 7天内相同Banner文本复用AI结果，预计>80%命中率

---

## Phase 1 工作项（MVP）

```
1. 项目脚手架（单仓库，Go + Taro + Docker）
2. Probe Agent 基础骨架（mDNS广播、WebSocket服务器）
3. 小程序端mDNS/UDP发现（验证微信API能力边界）
4. TCP端口探测（白名单端口，≤20并发）
5. 设备拓扑图Canvas实现
6. 扫描历史存储（wx.setStorage）
```

---

## 里程碑

- Week 1-2: 脚手架 + 验证微信API边界（真机mDNS + TCP测试）
- Week 3-4: 核心扫描功能实现
- Week 5: UI/拓扑图实现
- Week 6: 内测 + Bug修复 + 提交审核