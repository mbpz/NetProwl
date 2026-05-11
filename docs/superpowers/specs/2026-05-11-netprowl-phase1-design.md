# NetProwl Phase 1 MVP 规格书

> **版本**：v1.0
> **更新**：2025-05-11
> **状态**：草稿

---

## 1. 项目概述

**项目名**：NetProwl
**类型**：网络安全工具
**定位**：面向个人和中小企业的网络安全工具

**Phase 1 双版本并行：**

| 版本 | 平台 | 说明 |
|------|------|------|
| 微信小程序版 | 微信小程序 | 扫码即用，API 限制多（Phase 2+ 解锁 Probe Agent）|
| PC 客户端版 | Tauri/Electron | 功能完整，无 API 限制 |

**两版本共享同一核心扫描能力（Go），仅前端不同。**

---

## 2. 技术栈

| 层 | 技术 | 说明 |
|----|------|------|
| 前端 | Taro + React | 微信小程序，Canvas 拓扑图 |
| 本地能力 | 微信小程序 API | mDNS + UDP SSDP + 白名单 TCP |

**架构图**：

```
                    ┌─────────────────────────────────┐
                    │         NetProwl Core (Go)       │
                    │  mDNS · UDP SSDP · TCP Scan     │
                    │  Banner Grabbing · 规则引擎      │
                    └──────────┬──────────────────────┘
                               │
              ┌────────────────┴────────────────┐
              ▼                                 ▼
┌─────────────────────────┐         ┌─────────────────────────┐
│     微信小程序版          │         │      PC 客户端版         │
│  Taro + React           │         │  Tauri/Electron         │
│  Canvas 拓扑图           │         │  完整功能无限制         │
│  Storage 历史           │         │  桌面 UI                │
└─────────────────────────┘         └─────────────────────────┘
```

**设计原则**：
- 核心能力（Go）共享，两版本前端独立
- 小程序版：轻量拉新，受微信 API 限制
- PC 版：功能完整，无限制

---

## 3. 前端（微信小程序 / Taro）

### 3.1 技术选型

- **框架**：Taro 4.x + React 18
- **编译目标**：微信小程序
- **状态管理**：Zustand（轻量）
- **Canvas**：原生 Canvas API（拓扑图绘制）

### 3.2 功能列表

| 功能 | 说明 |
|------|------|
| F1-1 · mDNS 服务扫描 | `wx.startLocalServiceDiscovery` 发现 `_http._tcp` 等 |
| F1-2 · UDP SSDP 探测 | `wx.createUDPSocket` 发送 M-SEARCH 广播 |
| F1-3 · TCP 端口探测 | `wx.createTCPSocket` 探测白名单端口（80/443/8080/554/5000/9000） |
| F1-4 · 设备拓扑图 | Canvas 绘制，设备图标区分类型，MAC OUI 识别厂商 |
| F1-5 · 本地 IP 感知 | `wx.getNetworkType` + `wx.getLocalIPAddress` 推断子网 |
| F1-6 · 扫描历史记录 | `wx.setStorage` 持久化，JSON gzip 压缩 |

### 3.3 文件结构

```
src/
├── pages/
│   ├── index/           # 首页，扫描入口
│   ├── devices/          # 设备列表
│   ├── topology/         # 拓扑图
│   └── history/          # 扫描历史
├── components/
│   ├── DeviceCard/       # 设备卡片
│   ├── TopoCanvas/      # 拓扑图 Canvas 组件
│   └── ScanButton/       # 扫描按钮
├── services/
│   ├── mdns.ts          # mDNS 发现
│   ├── udp.ts           # UDP SSDP
│   ├── tcp.ts           # TCP 端口探测
│   └── storage.ts       # 本地存储
├── stores/
│   └── deviceStore.ts   # 设备状态
└── utils/
    ├── oui.ts           # MAC OUI 厂商库
    └── ip.ts            # IP/子网工具
```

### 3.4 关键 API 设计

**mDNS 发现**：
```typescript
wx.startLocalServiceDiscovery({
  serviceType: '_http._tcp',
  success: () => {},
  fail: (err) => {
    if (err.errCode === -1) fallbackToTCPScan()
  }
})

wx.onLocalServiceFound((res) => {
  // res: { serviceType, serviceName, ip, port, hostName }
  addDevice(res)
})
```

**TCP 端口探测**：
```typescript
const WHITE_PORTS = [80, 443, 8080, 554, 5000, 9000, 49152]

async function probePorts(ip: string, ports: number[]): Promise<number[]> {
  const results: number[] = []
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

---

## 4. 数据流

```
用户操作小程序
    │
    ├─── mDNS（小程序直连，同局域网）
    │         └── 设备列表（mDNS 服务发现）
    │
    ├─── UDP SSDP（小程序直连）
    │         └── 智能设备列表（TV/摄像头/NAS）
    │
    ├─── TCP 端口探测（小程序直连，白名单端口）
    │         └── 开放端口列表
    │
    └─── 本地存储（wx.setStorage）
              └── 扫描历史记录
```

**Probe Agent 和云端中台移至 Phase 2+**。

---

## 5. MVP 验收标准

- [ ] iOS / Android 真机均能正常发现局域网设备
- [ ] 设备拓扑图在 10+ 设备时不卡顿
- [ ] 扫描全程不触发微信安全拦截
- [ ] 历史记录可正常读写，不超存储上限（10MB）

---

## 6. Phase 1 里程碑

| 周次 | 任务 |
|------|------|
| W1-2 | 技术可行性验证（真机 mDNS + TCP 测试） |
| W3-4 | 核心扫描功能实现（小程序端） |
| W5 | UI / 拓扑图实现 |
| W6 | 内测 + Bug 修复 + 提交审核 |

---

## 7. 未来扩展（Phase 2+）

| 组件 | 说明 |
|------|------|
| Probe Agent | 可选部署，解锁全端口扫描 |
| 云端中台 | DeepSeek AI / CVE 库 / 扫描历史云同步 |

---

*规格书版本：v1.1 · NetProwl Phase 1 MVP（简化版）*