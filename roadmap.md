# NetProwl · 微信小程序网络安全工具 · 完整 Roadmap

> **定位**：面向个人和中小企业的移动端网络安全工具，运行于微信小程序，无需安装 App，扫码即用。核心能力覆盖局域网服务发现、服务指纹识别、安全弱点检测、公网资产侦察，并以 DeepSeek 大模型驱动 AI 增值功能层。

---

## 目录

1. [竞品分析与差异化定位](#1-竞品分析与差异化定位)
2. [核心技术约束与架构决策](#2-核心技术约束与架构决策)
3. [Phase 1 · 局域网服务发现（MVP）](#3-phase-1--局域网服务发现mvp)
4. [Phase 2 · 服务指纹与协议识别](#4-phase-2--服务指纹与协议识别)
5. [Phase 3 · 安全弱点检测 · 内网](#5-phase-3--安全弱点检测--内网)
6. [Phase 4 · 公网侦察 · 外网资产](#6-phase-4--公网侦察--外网资产)
7. [AI 增值层 · DeepSeek 集成](#7-ai-增值层--deepseek-集成)
8. [整体架构设计](#8-整体架构设计)
9. [商业化模型](#9-商业化模型)
10. [合规与审核策略](#10-合规与审核策略)
11. [里程碑总览](#11-里程碑总览)

---

## 1. 竞品分析与差异化定位

### 1.1 主要竞品对比

| 项目 | 平台 | 核心能力 | 缺失能力 | 最近活跃 |
|------|------|----------|----------|----------|
| **PortAuthority** | Android 原生 | 极快端口扫描，多线程 TCP，LAN/WAN | 无服务指纹，无安全检测，无 AI | 持续维护 |
| **Network Scanner** (usamaiqb) | Android 原生 | mDNS + ARP + SSDP + NetBIOS + OS 指纹 | 无安全弱点检测，无 AI | 3 周前更新 |
| **Ning** | Android / F-Droid | 轻量设备发现 | 功能极简，无指纹，无安全检测 | 一般 |
| **GoScan** | CLI (Go) | nmap 集成，SQLite 状态持久化，服务枚举 | 无移动端，无 AI | 稳定 |
| **各类 nmap 封装** | CLI | 服务枚举完善 | 无移动端，无 AI | 多样 |
| **微信官方漏洞扫描** | 微信开发者工具 | 小程序自身后端接口漏洞扫描 | 非通用 LAN/WAN 工具 | 官方维护 |

### 1.2 市场空白

**微信小程序生态内做通用网络安全工具几乎是空白**。现有工具要么是 Android/iOS 原生 App（需要安装），要么是 CLI 工具（需要技术背景）。NetProwl 的差异化价值：

- **零安装门槛**：微信生态，扫码即用，覆盖 13 亿微信用户
- **内外网统一**：同一工具处理局域网探测和公网资产侦察
- **AI 语义层**：DeepSeek 驱动，非技术用户也能读懂安全报告
- **中国市场适配**：DeepSeek 私有化可选，无数据出境顾虑

---

## 2. 核心技术约束与架构决策

### 2.1 微信小程序网络 API 能力边界

微信小程序的网络能力远比 Android 原生受限，这决定了整个架构。

#### 可用 API

| API | 说明 | 限制 |
|-----|------|------|
| `wx.createTCPSocket` | TCP 连接（基础库 2.18.0+） | 仅允许同局域网非本机 IP；禁止大量高危端口 |
| `wx.createUDPSocket` | UDP 通信（基础库 2.7.0+） | 同局域网规则相同 |
| `wx.startLocalServiceDiscovery` | mDNS 服务发现 | **iOS 微信 7.0.18+ 已禁用**；Android 正常 |
| `wx.request` | HTTP/HTTPS 请求 | 公网须走已备案域名白名单；局域网 IP 豁免 |
| `wx.connectSocket` | WebSocket | 同上 |

#### TCP 黑名单端口（禁止连接）

```
< 1024, 1099, 1433, 1521, 1719, 1720, 1723, 2049, 2375,
3128, 3306, 3389, 3659, 4045, 5060, 5061, 5432, 5984,
6379, 6000, 6566, 7001, 7002, 8000-8100, 8443, 8888,
9200, 9300, 10051, 10080, 11211, 27017, 27018, 27019
```

> 这张黑名单几乎覆盖了所有主流服务的默认端口（SSH/MySQL/Redis/MongoDB/ES），是 **引入 Probe Agent 的核心原因**。

#### TCPSocket 频率限制

每 5 分钟最多建立 20 个 TCPSocket 实例，纯前端并发扫描不可行。

### 2.2 架构决策：三层模型

```
┌─────────────────────────────────────────────────┐
│              微信小程序（前端）                    │
│  UI · 结果可视化 · mDNS · UDP SSDP · 少量 TCP    │
└────────────────────┬────────────────────────────┘
                     │ WebSocket / HTTP
┌────────────────────▼────────────────────────────┐
│           Probe Agent（局域网探针）               │
│  Go 单二进制 · 部署于局域网设备（NAS/树莓派/PC）  │
│  完整端口扫描 · 弱密码检测 · TLS 审计 · Banner 抓取│
└────────────────────┬────────────────────────────┘
                     │ HTTPS / WebSocket
┌────────────────────▼────────────────────────────┐
│           云端服务（中台）                        │
│  DeepSeek API 中转 · CVE 库 · Shodan 代理        │
│  用户数据 · 订阅管理 · Prompt 缓存               │
└─────────────────────────────────────────────────┘
```

### 2.3 Probe Agent 技术选型

**选 Go 的理由**：

- 单二进制，无需运行时，用户解压即用
- 跨平台 ARM 编译（树莓派 / NAS / 旧 Mac / Linux Server）
- 并发模型天然适合大量 TCP 连接
- 可参考 GoScan 项目的 SQLite 状态持久化设计

**Probe Agent 发现机制**：首次使用时，用户在同一局域网的任意设备（PC / NAS / 树莓派）上运行探针，探针通过 mDNS 广播自身，小程序自动发现并配对，体验类似 HomeKit 配件配对。

---

## 3. Phase 1 · 局域网服务发现（MVP）

**周期**：约 6 周  
**目标**：可用的局域网探测工具，覆盖主流设备发现场景

### 3.1 功能列表

#### F1-1 · mDNS 服务扫描

- 调用 `wx.startLocalServiceDiscovery` 发现局域网内广播 mDNS 服务的设备
- 支持常见 serviceType：`_http._tcp`、`_ftp._tcp`、`_ssh._tcp`、`_smb._tcp`、`_airplay._tcp`、`_googlecast._tcp`、`_ipp._tcp`（打印机）
- iOS 7.0.18+ 降级策略：mDNS 不可用时自动切换至 TCP 端口探测兜底
- Android 通过系统 mDNS 接口实现，无限制

#### F1-2 · TCP 端口探测

- 通过 `wx.createTCPSocket` 探测非黑名单端口的服务
- 白名单端口优先探测：`80`、`443`、`8080`、`8443`、`554`（RTSP）、`5000`、`9000` 等
- Probe Agent 模式：解锁全端口扫描（包括黑名单端口）
- 并发控制：小程序端 ≤20 个并发，探针端可配置（默认 200）

#### F1-3 · UDP 广播探测

- 调用 `wx.createUDPSocket` 发送 SSDP/UPnP M-SEARCH 广播
- 解析 UPnP 设备描述 XML，提取友好名称、厂商、型号
- 覆盖设备类型：智能电视、网络摄像头、NAS、智能音箱、打印机

#### F1-4 · 设备拓扑视图

- Canvas 绘制局域网设备拓扑图
- 设备图标按类型区分（路由器 / PC / 摄像头 / 手机 / 未知）
- MAC 地址 OUI 前缀查库识别厂商（离线库，约 800 KB）
- 点击设备节点展开详情：IP、MAC、厂商、开放端口、发现时间

#### F1-5 · 本地 IP 感知与子网推断

- `wx.getNetworkType` + `wx.getLocalIPAddress`（基础库 2.21.0+）
- 推断 /24 子网范围，生成扫描目标 IP 列表
- 支持手动指定 IP 段（高级用户）

#### F1-6 · 扫描历史记录

- `wx.setStorage` 持久化，上限 10 MB
- 按时间排序的扫描历史，支持对比查看（设备增减、端口变化）
- 单次扫描快照压缩存储（JSON gzip）

### 3.2 技术实现要点

```javascript
// mDNS 发现示例
wx.startLocalServiceDiscovery({
  serviceType: '_http._tcp',
  success: () => {},
  fail: (err) => {
    // iOS 7.0.18+ 降级至 TCP 扫描
    if (err.errCode === -1) fallbackToTCPScan()
  }
})

wx.onLocalServiceFound((res) => {
  // res: { serviceType, serviceName, ip, port, hostName }
  addDevice(res)
})
```

```javascript
// TCP 端口探测（非黑名单端口）
const WHITE_PORTS = [80, 443, 8080, 554, 5000, 9000, 49152]

async function probePorts(ip, ports) {
  const results = []
  for (const port of ports) {
    const socket = wx.createTCPSocket()
    await new Promise((resolve) => {
      socket.connect({ address: ip, port, timeout: 2000 })
      socket.onConnect(() => { results.push(port); socket.close(); resolve() })
      socket.onError(() => { resolve() })
    })
  }
  return results
}
```

### 3.3 MVP 验收标准

- [ ] 在 iOS / Android 真机上均能正常发现局域网设备
- [ ] 设备拓扑图在 10+ 设备时不卡顿
- [ ] 扫描全程不触发微信安全拦截
- [ ] 历史记录可正常读写，不超存储上限

---

## 4. Phase 2 · 服务指纹与协议识别

**周期**：约 4 周（Phase 1 完成后开始）  
**目标**：从"知道有什么设备"升级到"知道设备上跑了什么服务、什么版本"

### 4.1 功能列表

#### F2-1 · Banner Grabbing

- Probe Agent 在 TCP 连接建立后发送协议探针，读取首包响应
- 支持协议：HTTP（Server header）、SSH（version string）、FTP（banner）、SMTP、POP3、IMAP、Telnet、MySQL（greeting packet）
- 原始 Banner 存储，供 AI 层语义解析

#### F2-2 · 服务类型识别规则库

内置规则库（JSON 格式，可云端热更新）：

```json
{
  "rules": [
    {
      "id": "hikvision-rtsp",
      "match": { "port": 554, "banner_contains": "Hikvision" },
      "service": "海康威视摄像头",
      "risk_level": "medium",
      "notes": "检查是否使用默认密码 admin/12345"
    },
    {
      "id": "synology-dsm",
      "match": { "port": 5000, "http_title_contains": "Synology" },
      "service": "群晖 NAS (DSM)",
      "risk_level": "low"
    }
  ]
}
```

覆盖设备类型：海康/大华/萤石摄像头、群晖/威联通 NAS、华为/TP-Link/小米路由器、树莓派、各类 Docker 服务。

#### F2-3 · OS 指纹推断

基于 TTL 值 + 开放端口组合进行 OS 推断：

| TTL 范围 | 推断 OS |
|---------|---------|
| 64 | Linux / macOS / Android / iOS |
| 128 | Windows |
| 255 | 网络设备（路由器/交换机）|

结合开放端口进一步细化（如 5985 = Windows WinRM，9090 = Cockpit Linux 管理界面）。

#### F2-4 · HTTP 服务深度探测

对识别到 HTTP 服务的目标：

- 提取 Server、X-Powered-By、X-Generator 等 Header
- 探测常见路径：`/robots.txt`、`/wp-login.php`、`/phpmyadmin/`、`/admin/`
- 识别 CMS/框架：WordPress、phpMyAdmin、Nginx、Apache、Tomcat

#### F2-5 · RTSP 摄像头流探测

- 探针尝试 `DESCRIBE rtsp://ip:554/` 获取流信息
- 识别摄像头品牌和流路径格式
- 返回预览截图（需用户授权）和流地址（用于安全验证）

#### F2-6 · 版本 → CVE 映射

- 离线 CVE 规则库（SQLite，压缩后约 30 MB，含主流设备和服务的高危 CVE）
- 格式：`软件名 + 版本范围 → CVE 列表 + CVSS 评分`
- 云端增量更新，每周同步最新高危 CVE

### 4.2 与 AI 层协同

Banner Grabbing 的结果直接进入 DeepSeek 语义解析管道（见第 7 章），规则引擎和 AI 双轨并行，规则库精准匹配，AI 处理规则库覆盖不到的模糊情况。

---

## 5. Phase 3 · 安全弱点检测 · 内网

**周期**：约 6 周  
**目标**：从"知道有什么"升级到"知道哪里有安全问题"  
**前置条件**：用户完成设备授权声明（合规要求）

### 5.1 合规前置流程

所有 Phase 3 功能在首次使用前触发授权声明弹窗：

```
【安全声明】
以下检测功能将对您的设备进行主动探测。
请确认您拥有以下设备的管理权限，
或已获得设备所有者的明确授权。

[我确认拥有或已获授权] [取消]
```

该声明记录时间戳、用户 openid、扫描目标 IP 段，云端留存日志供合规审计。

### 5.2 功能列表

#### F3-1 · 默认凭据检测

针对识别出的设备类型，尝试已知默认账号密码：

| 设备类型 | 默认凭据示例 |
|---------|------------|
| 海康威视摄像头 | admin / 12345, admin / admin |
| 大华摄像头 | admin / admin |
| TP-Link 路由器 | admin / admin, admin / (空) |
| 小米路由器 | admin / admin |
| 群晖 NAS | admin / (空) |
| phpMyAdmin | root / (空), root / root |

凭据库：约 2000 条，覆盖主流设备，持续更新。

#### F3-2 · HTTP 基础认证弱口令探测

对开放 HTTP Basic Auth 的服务进行受控探测：

- 并发限制：每目标最多 5 个并发请求，避免触发锁定
- 探测间隔：请求间隔 500ms，模拟人工操作
- 锁定检测：连续 3 次 401 后暂停，避免账号锁定
- 字典：精简版（Top 200 弱密码 + 设备品牌相关密码）

#### F3-3 · TLS/SSL 配置审计

- 检测证书是否过期（超过 30 天预警，已过期告警）
- 检测自签名证书
- 识别弱密码套件（RC4、DES、MD5）
- 检测 TLS 版本（TLS 1.0/1.1 标记为需升级）
- 结合 DeepSeek 生成针对性修复建议

#### F3-4 · 未授权访问检测

针对常见服务检测无认证暴露：

| 服务 | 检测方式 |
|------|---------|
| Redis | 发送 `PING` 命令，响应 `+PONG` = 无认证 |
| Elasticsearch | `GET /` 返回集群信息 = 无认证 |
| MongoDB | 尝试 `listDatabases` 无认证连接 |
| Memcached | 发送 `stats` 命令 |
| Docker API | `GET /v1.41/containers/json` |
| Kubernetes API | `GET /api/v1/nodes` |
| RTSP 摄像头 | 无认证 DESCRIBE 请求 |

#### F3-5 · 固件版本风险评估

- 基于 Phase 2 识别的设备型号和固件版本
- 查询厂商 EOS（End of Support）数据库，标记停止维护的固件
- 比对最新固件版本，提示是否有安全更新
- 高危设备优先标记（如超过 2 年未更新固件的摄像头）

#### F3-6 · 风险报告生成（规则版）

- CVSS 2.0/3.1 评分汇总
- 风险等级分布饼图（严重/高危/中危/低危/信息）
- 按优先级排序的修复清单
- 导出 JSON，供 AI 层生成自然语言报告（见第 7 章）

---

## 6. Phase 4 · 公网侦察 · 外网资产

**周期**：约 8 周  
**目标**：从局域网扩展到公网资产管理，帮助用户了解自身的互联网暴露面

### 6.1 功能列表

#### F4-1 · Shodan / FOFA 集成

由于小程序不能直接调用外部 API，通过云端中转服务代理请求：

- **Shodan**：查询 IP 地址关联的历史扫描数据、开放端口、CVE
- **FOFA**：查询国内资产，覆盖更多中国 IP 段
- **ZoomEye**：补充查询，三源数据聚合去重
- 用户输入：域名 / IP / IP 段，支持 CIDR
- 结果包含：开放端口、运行服务、地理位置、ASN、历史快照

#### F4-2 · 子域名与 DNS 侦察

- **证书透明日志**（crt.sh）：枚举域名的所有 TLS 证书记录中的子域名
- **被动 DNS 查询**：多源历史 DNS 记录（无主动扫描，合规友好）
- DNS 记录类型：A、AAAA、CNAME、MX、TXT（SPF/DKIM 配置审计）、NS
- 识别云服务商（AWS/阿里云/腾讯云）和 CDN（Cloudflare/阿里 CDN）

#### F4-3 · HTTP 安全头审计

对用户指定的 URL 进行安全头检测：

| Header | 满分条件 |
|--------|---------|
| Strict-Transport-Security | 存在，max-age ≥ 31536000 |
| Content-Security-Policy | 存在，无 unsafe-inline |
| X-Frame-Options | DENY 或 SAMEORIGIN |
| X-Content-Type-Options | nosniff |
| Referrer-Policy | strict-origin-when-cross-origin |
| Permissions-Policy | 存在 |

综合评分 A–F，DeepSeek 生成优化建议。

#### F4-4 · WAF / CDN 识别

通过响应头特征识别：

- Cloudflare（`CF-Ray` header）
- 阿里云 WAF（`X-Powered-By-Alibaba` / 特定错误页）
- 腾讯云 WAF（特征响应码和页面）
- 宝塔面板（特征页面结构）
- 识别结果用于攻击面评估

#### F4-5 · Web 漏洞被动检测

**被动检测**（不主动攻击）：

- SQL 注入特征：响应中包含数据库错误信息（MySQL error、ORA-）
- XSS 反射：echo 用户输入到响应体（无实际执行）
- 敏感路径暴露：`.env`、`/backup/`、`/.git/`、`/api/swagger`
- 敏感信息泄露：响应体中包含 API Key 格式字符串、内网 IP

#### F4-6 · 社区情报共享

- 用户可匿名上报发现的高危资产（摄像头无认证等）
- 公共黑名单：已知恶意 IP / 已被攻击的开放 Redis 等
- 社区规则库：用户贡献的设备指纹规则（审核后合并）

---

## 7. AI 增值层 · DeepSeek 集成

这一章是 NetProwl 与所有现有竞品的本质区别。DeepSeek 不是"加了个问答框"，而是处理传统规则引擎结构性做不到的五类任务。

### 7.1 为什么 LLM 在这个场景能创造真实价值

| 传统规则引擎能做 | DeepSeek 解锁的新能力 |
|----------------|---------------------|
| 正则匹配 Banner 版本号 | 语义理解任意格式的模糊 Banner |
| CVE ID 精确查表 | 自然语言描述 → 漏洞语义推断 |
| 固定端口 → 固定服务名 | 多漏洞跨资产攻击链推理 |
| 预设字典弱密码爆破 | 业务场景感知的上下文修复建议 |
| 导出 CSV/JSON 数据 | 双层次自然语言安全报告 |

### 7.2 AI 功能 #1 · 智能 Banner 语义解析

**集成阶段**：Phase 2  
**解决的问题**：厂商定制 Banner、乱序格式、版本号混淆导致规则引擎失效

**工作流**：

```
Probe Agent 抓取 Banner
       ↓
规则引擎优先匹配（精确、快速）
       ↓ 未命中
DeepSeek 语义解析
       ↓
结构化 JSON 输出
```

**Prompt 设计**：

```
System:
你是一个网络安全专家，专门分析网络服务的 Banner 信息。
请将以下 Banner 解析为结构化 JSON，字段包括：
- software: 软件名称（如 OpenSSH、Nginx、Apache）
- version: 版本号（如能提取）
- os: 运行系统（如能推断）
- known_cves: 该版本已知的 CVE（仅列出 CVSS ≥ 7.0 的）
- confidence: 置信度 0-1
只输出 JSON，不要任何其他文字。

User:
Banner: "SSH-2.0-OpenSSH_for_Windows_8.1"
```

**输出示例**：

```json
{
  "software": "OpenSSH",
  "version": "8.1",
  "os": "Windows",
  "known_cves": ["CVE-2023-38408"],
  "confidence": 0.92
}
```

### 7.3 AI 功能 #2 · 多漏洞攻击链推理

**集成阶段**：Phase 3  
**解决的问题**：传统扫描器输出独立告警，无法理解漏洞之间的利用关系

**示例对比**：

```
传统输出（3 条独立告警）：
- [高危] Redis 6379 无认证
- [中危] SSH 弱密码 admin/123456  
- [低危] HTTP 目录遍历 /backup/

DeepSeek 推理输出：
攻击链分析：
1. 通过 HTTP 目录遍历（/backup/db.conf）获取 Redis 密码
   → 实际上 Redis 无密码，目录遍历可能暴露更多配置
2. Redis SLAVEOF 命令写入 SSH authorized_keys
   → 利用 Redis 无认证获得 SSH 访问权限
3. SSH 弱密码作为备用横移路径
   → 即使修复 Redis 也存在直接 SSH 入侵风险

综合评级：严重（单一漏洞中危，组合利用为 RCE）
修复优先级：先修 Redis 无认证 → 再改 SSH 密码 → 最后关目录遍历
```

**Prompt 设计**：

```
System:
你是一名渗透测试专家。请分析以下漏洞列表，找出可以串联利用的攻击路径，
以 JSON 格式输出攻击链（nodes 和 edges），并给出综合风险评级和修复优先级。

User:
目标网络 192.168.1.0/24，发现如下漏洞：
[漏洞列表 JSON]
```

前端基于返回的 DAG（有向无环图）数据渲染攻击链可视化。

### 7.4 AI 功能 #3 · 自然语言网络问诊

**集成阶段**：Phase 1 即可接入，贯穿全程  
**解决的问题**：非技术用户无法理解扫描结果

**Function Calling 设计**：

```javascript
const tools = [
  {
    name: "scan_lan",
    description: "扫描局域网，发现设备和开放服务",
    parameters: { type: "object", properties: {
      ip_range: { type: "string", description: "IP 段，如 192.168.1.0/24" }
    }}
  },
  {
    name: "check_device_security",
    description: "检查特定设备的安全状态",
    parameters: { type: "object", properties: {
      ip: { type: "string" }
    }}
  },
  {
    name: "get_scan_history",
    description: "获取历史扫描记录进行对比"
  }
]
```

**对话示例**：

```
用户：我家摄像头安全吗？

DeepSeek（内部调用 scan_lan + check_device_security）：

我扫描了你家局域网，发现 2 台摄像头：

- 192.168.1.105 海康威视 DS-2CD2043G0-I
  ⚠️ 问题：使用默认密码 admin/12345（就像你家大门用了出厂密码）
  修复：登录 http://192.168.1.105 更改密码

- 192.168.1.112 小米摄像头 2K
  ✓ 安全：已设置自定义密码，固件版本为最新

建议先处理第一台，默认密码的摄像头任何人连上你家 WiFi 都能看直播。
```

### 7.5 AI 功能 #4 · 上下文感知修复建议

**集成阶段**：Phase 3  
**解决的问题**：通用 CVE 修复建议无法对应到用户的具体设备型号

**Prompt 包含的上下文**：

```
设备信息：群晖 NAS DS220+ DSM 7.1.1-42962
漏洞：CVE-2022-27624（Synology DSM 任意文件读取）
用户技术水平：初级（从问诊对话推断）

请提供：
1. 风险通俗解释（1 句话）
2. 是否需要立即处理（是/否 + 理由）
3. 具体操作步骤（针对群晖 DSM 界面，带截图路径描述）
4. 验证修复成功的方法
```

### 7.6 AI 功能 #5 · 双层次安全报告生成

**集成阶段**：Phase 3–4  
**解决的问题**：技术报告非技术人员读不懂，两类受众需要不同版本

**报告结构**：

```markdown
# 网络安全评估报告
**评估时间**：2025-xx-xx  **目标网络**：192.168.1.0/24

## 执行摘要（管理层版本）
您的家庭/企业网络整体风险等级为 **高危**。
主要问题是 2 台安防摄像头使用出厂默认密码，这意味着
任何连接您 WiFi 的人都可以查看摄像头画面。建议在本周内修复。

## 风险统计
- 严重：0 项 | 高危：2 项 | 中危：3 项 | 低危：5 项

## 技术详情（工程师版本）
### [高危] CVE-2024-xxxx · 海康威视摄像头默认凭据
- 影响资产：192.168.1.105
- CVSS 3.1 评分：8.8
- 复现步骤：...
- 修复方案：...
```

### 7.7 AI 功能 #6 · 网络行为异常分析

**集成阶段**：Phase 4  
**解决的问题**：单次扫描是静态快照，无法理解"这次扫描结果和上次有什么变化"

**工作流**：

1. 每次扫描结果存储为带时间戳的快照
2. 用户触发"变化分析"或定时自动分析
3. DeepSeek 接收两次快照 diff，解释变化含义

**示例**：

```
本次扫描比 3 天前新增了 1 台设备：
- 192.168.1.201 未知设备，MAC: xx:xx:xx（小米/华为）
  开放端口：80、8080
  可能是：新连接的智能家居设备或访客设备
  建议：如果您没有添加新设备，考虑检查 WiFi 密码
```

### 7.8 DeepSeek 模型选择策略

| 任务 | 模型 | 原因 |
|------|------|------|
| Banner 语义解析 | `deepseek-chat` | 高频、低延迟、成本低 |
| 自然语言问诊 | `deepseek-chat` | 流式输出，实时响应感 |
| 攻击链推理 | `deepseek-reasoner` (R1) | 需要多步逻辑推理 |
| 报告生成 | `deepseek-reasoner` (R1) | 长文本、结构化、质量优先 |
| 异常行为分析 | `deepseek-reasoner` (R1) | 需要对比推断能力 |

### 7.9 成本控制策略

```
Banner 哈希缓存
  相同 Banner 文本 hash → 7 天内复用结果
  预计命中率 > 80%（相同设备型号重复出现）

用户分层限额
  免费层：每日 3 次 AI 调用（问诊 + 报告）
  Pro 层：无限制

Prompt 压缩
  扫描结果传入前去冗余，只保留 AI 需要的字段
  平均每次调用 token 数控制在 2000 以内

私有化选项（Enterprise）
  DeepSeek 系列模型开源，可本地部署
  M4 Mac Mini 可运行 DeepSeek-R1 7B
  完全消除 API 调用费用和数据出境顾虑
```

---

## 8. 整体架构设计

### 8.1 技术栈

| 层次 | 技术选型 | 说明 |
|------|---------|------|
| 小程序前端 | 原生微信小程序 / Taro | Canvas 可视化、WebSocket 长连 |
| Probe Agent | Go 1.21+ | 单二进制，跨平台编译，goroutine 并发 |
| 云端中台 | Node.js / Go + Nginx | WebSocket 中继、DeepSeek 代理、用户管理 |
| 数据库 | SQLite（Agent 本地）+ PostgreSQL（云端）| CVE 库离线，用户数据云端 |
| AI | DeepSeek API / 私有化部署 | function calling + streaming |
| 缓存 | Redis（云端）| Prompt 结果缓存、限流计数 |

### 8.2 数据流图

```
用户操作小程序
    │
    ├─── mDNS/UDP（小程序直连，同局域网）
    │         └── 设备列表
    │
    ├─── WebSocket → Probe Agent（同局域网）
    │         ├── 完整端口扫描
    │         ├── Banner 抓取
    │         ├── 弱密码检测
    │         └── 扫描结果流式推送 → 小程序
    │
    └─── HTTPS → 云端中台
              ├── DeepSeek API 调用
              │       └── AI 分析结果 → 小程序（SSE 流式）
              ├── CVE 库查询
              ├── Shodan/FOFA 代理
              └── 用户数据 / 历史记录
```

### 8.3 Probe Agent 安装流程

```
1. 用户在小程序内扫描 QR Code
   → 跳转到探针下载页（已备案域名）

2. 用户在局域网内的 PC/NAS/树莓派下载并运行探针
   ./netprowl-agent  （单二进制，无需安装）

3. 探针通过 mDNS 广播自身
   serviceType: _netprowl._tcp
   port: 随机（避免固定端口被防火墙拦截）

4. 小程序自动发现探针，用户确认配对
   （显示探针机器名，类似 AirDrop 配对确认）

5. 配对成功，探针 WebSocket 连接建立
   小程序解锁全功能（完整端口扫描、弱密码检测等）
```

### 8.4 安全设计

- 探针与小程序通信使用 TLS（自签名证书 + PIN）
- 探针生成一次性配对 Token，防止同局域网其他设备劫持
- 所有扫描结果端到端加密存储
- 云端不存储扫描目标的原始 IP（只存储哈希，用于去重）
- DeepSeek 调用的 Prompt 不包含用户个人信息

---

## 9. 商业化模型

### 9.1 功能分层

| 功能 | 免费层 | Pro（个人）| Enterprise |
|------|--------|-----------|------------|
| 局域网设备发现 | ✓ | ✓ | ✓ |
| mDNS / UDP / TCP 探测 | ✓ | ✓ | ✓ |
| 设备拓扑图 | ✓ | ✓ | ✓ |
| 扫描历史记录（7 天） | ✓ | ✓（无限） | ✓（无限） |
| 服务指纹识别 | 基础规则 | 完整规则库 | 完整规则库 |
| CVE 版本映射 | ✓ | ✓ | ✓ |
| 默认凭据检测 | 前 5 台设备 | 无限制 | 无限制 |
| TLS 审计 | ✓ | ✓ | ✓ |
| 未授权访问检测 | ✓ | ✓ | ✓ |
| AI 问诊 | 每日 3 次 | 无限制 | 无限制 |
| 攻击链推理 | — | ✓ | ✓ |
| AI 修复建议 | — | ✓ | ✓ |
| AI 安全报告生成 | — | ✓ | ✓ |
| 公网侦察（Shodan/FOFA） | — | ✓ | ✓ |
| 异常行为定时分析 | — | ✓ | ✓ |
| 私有化 DeepSeek 部署 | — | — | ✓ |
| 自定义规则库 | — | — | ✓ |
| 多网段 · 团队协作 | — | — | ✓ |
| API 接入 | — | — | ✓ |

### 9.2 定价策略（参考）

- **免费层**：永久免费，核心发现功能无限制，AI 有限次
- **Pro 个人**：¥29/月 或 ¥199/年，面向个人 homelab、IT 运维人员
- **Enterprise**：定制报价，面向中小企业 IT 部门、安全团队

### 9.3 增长路径

```
Phase 1-2（免费，获取用户）
  → 微信生态裂变（扫描结果分享、邀请好友）
  → 目标：10 万 MAU

Phase 3（引入 Pro 订阅）
  → 核心安全检测功能付费解锁
  → 转化率目标：5%

Phase 4（Enterprise 销售）
  → 企业采购，私有化部署
  → 目标客户：中小企业 IT、安全服务商
```

---

## 10. 合规与审核策略

### 10.1 微信小程序审核风险点

| 风险点 | 应对策略 |
|--------|---------|
| 网络扫描被判定为"黑客工具" | 定位为"网络安全自检工具"，首页突出"仅限自有设备"声明 |
| 弱密码检测被判定为"暴力破解" | 功能描述为"默认凭据安全检查"，限速不超过人工操作速度 |
| Shodan/FOFA 集成被拦截 | 通过自有域名中转，不在小程序内直接显示第三方品牌 |
| 审核人员触发安全检测 | 添加"演示模式"，审核环境返回模拟数据 |

### 10.2 向腾讯申请安全工具白名单

参考微信官方"小程序漏洞扫描"的白名单路径：

1. 通过微信开放平台企业认证
2. 提交"安全工具类小程序"说明材料
3. 声明使用场景（仅限用户自有网络/设备）
4. 提供合规使用协议和用户授权声明流程

### 10.3 法律边界

- 用户使用协议明确声明：本工具仅限用于用户合法拥有或获得授权的网络和设备
- 禁止用于任何未经授权的网络探测和渗透测试
- Phase 3 的授权声明流程留存时间戳日志
- 违规使用的举报和封号机制

---

## 11. 里程碑总览

```
Week 1-6    Phase 1 · MVP
  - W1-2:   技术可行性验证（真机 mDNS + TCP 测试）
  - W3-4:   核心扫描功能实现
  - W5:     UI / 拓扑图实现
  - W6:     内测 + Bug 修复 + 提交审核

Week 7-10   Phase 2 · 服务指纹
  - W7-8:   Probe Agent 基础版（Banner Grabbing）
  - W9:     CVE 规则库 + 离线 SQLite
  - W10:    AI Banner 解析接入（DeepSeek #1）

Week 11-16  Phase 3 · 安全检测
  - W11-12: 默认凭据 + 未授权访问检测
  - W13-14: TLS 审计 + 固件风险评估
  - W15:    攻击链推理（DeepSeek #2）+ 修复建议（DeepSeek #4）
  - W16:    报告生成（DeepSeek #5）+ Pro 订阅上线

Week 17-24  Phase 4 · 公网侦察
  - W17-18: Shodan/FOFA 云端中转
  - W19-20: 子域名侦察 + HTTP 安全头审计
  - W21-22: Web 漏洞被动检测
  - W23:    异常行为分析（DeepSeek #6）
  - W24:    Enterprise 功能 + 私有化 DeepSeek 方案

持续进行
  - 每周 CVE 库更新
  - 设备指纹规则库社区贡献
  - DeepSeek Prompt 优化迭代
```

### 关键风险与缓解

| 风险 | 概率 | 影响 | 缓解方案 |
|------|------|------|---------|
| 微信审核拒绝安全工具 | 中 | 高 | 提前申请白名单，准备 H5 备用方案 |
| iOS mDNS 限制扩大 | 低 | 中 | TCP 兜底已覆盖，Probe Agent 不受影响 |
| DeepSeek API 不稳定 | 低 | 低 | 降级到规则引擎，AI 功能暂时不可用提示 |
| Probe Agent 安装率低 | 中 | 中 | 优化安装体验，提供 Docker 一键部署版 |
| 用户误用于非授权网络 | 低 | 高 | 授权声明 + 日志留存 + 举报机制 |

---

*文档版本：v1.2 · 含 DeepSeek AI 增值层*  
*最后更新：2025年*