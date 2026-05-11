# NetProwl · Phase 1 MVP · 小程序前端设计规格书

**版本**：v1.0
**日期**：2026-05-11
**范围**：Phase 1 · 局域网服务发现（MVP）

---

## 1. 概述

### 1.1 目标

在微信小程序内实现局域网设备发现功能，覆盖 mDNS / UDP SSDP / TCP 端口探测三种发现机制，渲染设备拓扑图，提供扫描历史记录。

### 1.2 技术栈

| 层次 | 技术选型 |
|------|---------|
| 框架 | 原生微信小程序 + Taro（多端适配）|
| UI 组件 | 自定义组件 |
| 探测能力 | 小程序直连（mDNS + UDP SSDP + TCP）|
| 状态管理 | Taro 内置 |
| 存储 | `wx.setStorage`（扫描历史，上限 10MB）|
| AI（后续） | 云端 DeepSeek 中转 |

---

## 2. 架构决策

### 2.1 三层模型（Phase 1 范围）

```
┌─────────────────────────────────┐
│        微信小程序（前端）          │
│  UI · 结果可视化 · 探测引擎       │
│  mDNS / UDP SSDP / TCP 白名单端口│
└─────────────────────────────────┘
         │ HTTPS（后续 AI + 云端）
         ▼
┌─────────────────────────────────┐
│         云端中台（Phase 2+）      │
│  DeepSeek API · 用户数据 · CVE   │
└─────────────────────────────────┘
         │ WebSocket（Phase 2+）
         ▼
┌─────────────────────────────────┐
│       Probe Agent（Phase 2+）     │
│  完整端口扫描 · Banner 抓取       │
└─────────────────────────────────┘
```

**Phase 1 仅实现第一层的小程序前端**。iOS mDNS 限制通过 TCP 兜底覆盖。

### 2.2 目录结构

```
netprowl/
├── src/
│   ├── pages/
│   │   ├── discovery/          # 发现页（拓扑图 + 扫描）
│   │   │   ├── index.tsx
│   │   │   └── index.config.ts
│   │   ├── history/            # 历史页
│   │   │   ├── index.tsx
│   │   │   └── index.config.ts
│   │   └── chat/               # AI 问诊（Phase 2 接入）
│   │       ├── index.tsx
│   │       └── index.config.ts
│   ├── components/
│   │   ├── TopologyCanvas/     # 拓扑图画布组件
│   │   ├── DeviceDrawer/       # 设备详情抽屉
│   │   ├── ScanButton/         # 扫描触发按钮
│   │   ├── DeviceCard/         # 设备卡片
│   │   ├── PortList/           # 端口列表
│   │   └── icons/              # 设备类型图标（线性风格）
│   ├── services/
│   │   ├── scanner.ts          # 扫描引擎入口
│   │   ├── mdns.ts             # mDNS 发现服务
│   │   ├── udp.ts              # UDP SSDP 发现服务
│   │   ├── tcp.ts              # TCP 端口探测服务
│   │   ├── network.ts          # 网络感知（本机 IP / 子网推断）
│   │   └── storage.ts          # 扫描历史存储服务
│   ├── utils/
│   │   ├── oui.ts              # MAC OUI 厂商查表
│   │   ├── ip.ts               # IP / 子网工具函数
│   │   └── gzip.ts             # 扫描快照压缩
│   ├── app.ts
│   ├── app.config.ts
│   └── app.css
├── package.json
├── project.config.json
└── tsconfig.json
```

---

## 3. 页面设计

### 3.1 导航

底部 Tab 栏，3 个 Tab：

| Tab | 页面 | 图标 |
|-----|------|------|
| 发现 | `pages/discovery/index` | 雷达/扫描图标 |
| 历史 | `pages/history/index` | 时钟图标 |
| 问诊 | `pages/chat/index` | 对话图标 |

### 3.2 发现页（discovery）

**布局**（从上到下）：

```
┌──────────────────────────────┐
│  NetProwl      [设置图标]    │  ← 导航栏
├──────────────────────────────┤
│                              │
│     [拓扑图画布 Canvas]       │  ← 星形布局，中心路由器
│     设备节点可点击            │
│                              │
├──────────────────────────────┤
│  设备: 8 台  开放端口: 23 个 │  ← 状态摘要条
├──────────────────────────────┤
│                              │
│      [ 🔍 开始扫描 ]         │  ← 手动扫描按钮
│                              │
└──────────────────────────────┘
```

**设备节点详情（抽屉面板）**：

点击设备节点 → 底部滑出抽屉面板，包含：
- 设备基本信息：IP、MAC、厂商（OUI 查询）、发现时间
- 开放端口列表
- 设备类型标签（路由器/摄像头/NAS/手机/未知）

**拓扑图规范**：

- 布局：**星形**（中心 = 网关路由节点，周围 = 其他设备）
- 图标风格：**线性图标**（线条勾勒，轻量感）
- 设备类型区分：路由器 / PC / 摄像头 / NAS / 手机 / 打印机 / 未知
- MAC OUI 查表：离线库（`oui.json`，约 800KB），识别设备厂商
- 节点交互：点击 → 抽屉面板展开详情

### 3.3 历史页（history）

**布局**：

```
┌──────────────────────────────┐
│  扫描历史                    │
├──────────────────────────────┤
│  ● 2026-05-11 14:23  8 台   │  ← 扫描记录列表
│    192.168.1.0/24            │     按时间倒序
│  ○ 2026-05-10 09:15  7 台   │
│    192.168.1.0/24            │
│  ○ 2026-05-09 18:44  9 台   │
└──────────────────────────────┘
```

**对比视图**：点击记录 → 展开扫描详情，支持与上次扫描对比（设备增减、端口变化）。

### 3.4 AI 问诊页（chat）

Phase 1 仅为入口占位，内容在 Phase 2 接入 DeepSeek 后实现。

---

## 4. 扫描引擎设计

### 4.1 三阶段扫描流程

```
阶段 1: mDNS 发现
  └─ wx.startLocalServiceDiscovery
       ├─ Android: 正常获取设备列表
       └─ iOS 7.0.18+: errCode=-1 → 降级至阶段 2

阶段 2: UDP SSDP 广播
  └─ wx.createUDPSocket → M-SEARCH 广播
       └─ 解析 UPnP 设备描述 XML

阶段 3: TCP 端口探测
  └─ 白名单端口探测（限 20 并发）
       └─ connect 超时 2s

合并去重 → 存入 storage → 渲染拓扑
```

### 4.2 白名单端口

```
80, 443, 8080, 8443, 554, 5000, 9000, 49152
```

### 4.3 并发控制

| 参数 | 值 |
|------|-----|
| TCP 并发数 | ≤20 |
| 请求间隔 | 50ms |
| 单端口超时 | 2000ms |
| 总扫描超时 | 60s |

### 4.4 降级策略

iOS `wx.startLocalServiceDiscovery` 失败（errCode -1）→ 自动切换至 TCP 端口探测，无需用户操作。

---

## 5. 数据模型

### 5.1 设备对象（Device）

```typescript
interface Device {
  id: string                    // 内部 UUID
  ip: string                     // IPv4
  mac: string | null             // MAC 地址（可为空）
  hostname: string | null        // 主机名（mDNS/UPnP 获取）
  vendor: string | null          // 厂商（OUI 查询）
  deviceType: DeviceType          // 设备类型枚举
  os: 'linux' | 'windows' | 'network' | 'unknown'  // OS 推断
  openPorts: Port[]              // 开放端口列表
  discoveredAt: number           // 发现时间戳
  sources: ('mdns' | 'ssdp' | 'tcp' | 'arp')[]  // 发现来源
}
```

### 5.2 端口对象（Port）

```typescript
interface Port {
  port: number
  service: string | null         // 服务名（规则库匹配）
  state: 'open' | 'filtered'
  banner?: string               // Banner（Phase 2）
}
```

### 5.3 扫描快照（ScanSnapshot）

```typescript
interface ScanSnapshot {
  id: string
  timestamp: number
  ipRange: string               // 如 192.168.1.0/24
  deviceCount: number
  devices: Device[]
  summary: {
    critical: number
    high: number
    medium: number
    low: number
  }
}
```

### 5.4 存储策略

- 单次扫描快照 gzip 压缩后存入 `wx.setStorage`
- 历史记录上限 10MB，超限清理最旧记录
- 最多保留 50 次扫描

---

## 6. 错误处理

| 场景 | 处理方式 |
|------|---------|
| iOS mDNS 禁用 | 自动切换 TCP 探测，toast 提示"iOS 环境，降级扫描" |
| 网络权限拒绝 | 引导开启："检测到网络权限未开启，是否去设置？" |
| Storage 满 | 清理最旧 3 条记录，toast 提示 |
| 扫描超时（60s）| 显示已发现设备 + "扫描超时，继续等待？" |
| 无局域网设备 | 空状态页 + "未发现设备，请确认在同一 WiFi 下" |

---

## 7. 验收标准

- [ ] Android / iOS 真机均能正常发现局域网设备
- [ ] 设备拓扑图在 10+ 设备时不卡顿（Canvas 优化）
- [ ] 扫描全程不触发微信安全拦截
- [ ] 历史记录正常读写，不超存储上限
- [ ] iOS mDNS 禁用自动降级至 TCP 探测
- [ ] 设备详情抽屉正常滑出，数据完整

---

## 8. 待定项（Phase 2+）

- Probe Agent 配对流程（WebSocket + mDNS 发现探针）
- Banner 抓取与服务指纹识别
- DeepSeek AI 问诊接入
- CVE 版本映射
