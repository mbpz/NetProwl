# NetProwl MVP · 最小闭环设计

> 状态：已批准
> 日期：2026-05-11
> 目标：Phase 1 MVP 全链路跑通

---

## 1. 目标与范围

**成功标准**：用户完成一次完整扫描，看见 AI 生成的双层次安全报告。

**裁剪原则**：Phase 1 只做局域网 MVP，云端中台必须完整接入 DeepSeek，不做 mock。

| 功能 | MVP 行为 |
|------|---------|
| 设备发现 | mDNS + TCP 兜底 |
| 端口扫描 | Probe Agent 全端口，小程序仅白名单端口 |
| 拓扑图 | Canvas，设备节点 + 端口列表 |
| AI 报告 | DeepSeek 生成双层次报告（执行摘要 + 技术详情） |
| 云端中台 | WebSocket 中继 + DeepSeek 中转 + 报告生成 |

---

## 2. 子系统边界

```
┌──────────────────┐     WebSocket（同LAN）      ┌─────────────────┐
│  微信小程序前端   │◄──────────────────────────►│   Probe Agent   │
│  - mDNS/UDP/TCP  │                            │   (Go 二进制)   │
│  - 拓扑图 Canvas │                            │   - 全端口扫描  │
│  - AI 报告展示   │                            │   - Banner 抓取 │
└────────┬─────────┘                            └────────┬────────┘
         │ HTTPS                                      │
         │                                             │ HTTPS
         ▼                                             ▼
┌──────────────────────────────────────────────────────────────┐
│                      云端中台（Go + Docker）                    │
│  - WebSocket 中继（小程序 ↔ Agent 跨网络透传）                   │
│  - DeepSeek API 中转                                           │
│  - 报告生成 + 用户管理                                          │
└──────────────────────────────────────────────────────────────┘
```

---

## 3. 数据流

1. 小程序发现 Probe Agent（mDNS 广播或手动指定 IP:Port）
2. 小程序 ↔ Agent 建立 WebSocket 直连（同 LAN）
3. Agent 执行扫描（TCP Connect 扫描 + Banner Grabbing），结果流式推送小程序
4. 小程序上报扫描数据 → 云端中台 HTTPS API
5. 云端调用 DeepSeek 生成双层次报告 → 返回小程序展示

---

## 4. 技术架构

```
/netprowl
├── probe-agent/          # Go 二进制（NAS/树莓派/PC 运行）
│   └── main.go
├── cloud/               # Go 云端中台
│   ├── server.go       # WebSocket 中继 + HTTP API
│   └── deepseek.go     # DeepSeek API 中转
├── mini-program/       # 微信小程序（待创建）
│   ├── pages/scan/
│   └── components/topology/
└── docker/            # Docker 本地开发
    └── docker-compose.yml
```

### 4.1 Probe Agent

- Go 1.21+ 单二进制，`go build`
- mDNS 广播自身（`_netprowl._tcp`），供小程序自动发现
- WebSocket 服务端（固定端口或随机端口通过 mDNS 广告）
- TCP Connect 扫描：全端口，支持黑名单端口（解锁后才需要）
- Banner Grabbing：HTTP/SSH/FTP/RTSP 等协议探针
- 认证：Token 配对机制

### 4.2 云端中台

- Go + Gin 框架
- WebSocket 中继：小程序和 Agent 可能不在同一网络，Agent 连接中台 WebSocket 作为反向通道
- HTTP API：接收扫描结果 → 调用 DeepSeek → 返回报告
- DeepSeek：deepseek-chat（Banner 解析）+ deepseek-reasoner（报告生成）
- 部署：Docker，本地 docker-compose 开发验证

### 4.3 小程序前端

- Taro 或原生微信小程序
- mDNS 发现（`wx.startLocalServiceDiscovery`）+ mDNS 失败时 TCP 扫描兜底
- Canvas 拓扑图（设备节点 + 端口列表 + 厂商图标）
- AI 报告页（执行摘要 + 技术详情双 tab）

---

## 5. 技术约束

- 微信小程序 TCPSocket：每 5 分钟最多 20 个并发，白名单端口优先
- Probe Agent：绕过小程序网络限制，解锁全端口扫描
- 云端中台：必须可公网访问（用于 AI 报告生成链路）
- DeepSeek API Key：用户侧配置或系统默认

---

## 6. 交付物清单

- [ ] `probe-agent/main.go` — Agent 二进制代码
- [ ] `cloud/server.go` + `cloud/deepseek.go` — 云端中台代码
- [ ] `docker/docker-compose.yml` — 本地开发环境
- [ ] `mini-program/` — 小程序代码（待创建）
- [ ] 端到端跑通截图

---

## 7. 下一步

使用 `writing-plans` 技能拆解实现计划。
