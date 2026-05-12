# NetProwl Phase 1 MVP 规格书

> **版本**：v1.3
> **更新**：2026-05-12
> **状态**：待评审

---

## 1. 项目概述

**项目名**：NetProwl
**类型**：网络安全工具
**定位**：面向个人和中小企业的网络安全工具

**Phase 1 双版本并行：**

| 版本 | 平台 | 说明 |
|------|------|------|
| 微信小程序版 | 微信小程序 | 扫码即用，受微信 API 限制（白名单端口/mDNS）|
| PC 客户端版 | Tauri/Electron | 用户电脑安装，全部功能本地运行，无任何限制 |

**两者是完全独立的两个产品，共享部分代码但各自完整。**

---

## 2. 技术栈

| 层 | 技术 | 说明 |
|----|------|------|
| 核心扫描 | Rust | mDNS/UDP SSDP/TCP/厂商识别，统一语言 |
| 小程序前端 | Taro + React | 微信小程序（Rust 通过 WASM 调用） |
| PC 前端 | React + TypeScript | Tauri 桌面端（Rust 直接调用） |

**架构图**：

```
┌─────────────────────────────────────────────┐
│         NetProwl Core (Rust)                │
│  mDNS · UDP SSDP · TCP Scan · Banner       │
│  OUI 厂商库 · 服务指纹 · TLS 审计           │
└──────────┬──────────────────────┬───────────┘
           │                      │
┌──────────▼──────────┐  ┌───────▼─────────────┐
│   微信小程序版       │  │    PC 客户端版       │
│  Taro + React       │  │  Tauri + React      │
│  WASM (Rust Core)   │  │  Native (Rust Core) │
│  白名单端口（API 限）│  │  全端口（无限制）    │
│  Canvas 拓扑图      │  │  Canvas 拓扑图       │
│  Storage 历史       │  │  SQLite 历史         │
└─────────────────────┘  └─────────────────────┘
```

**语言统一调研结论**：

| 维度 | Go → Rust | 说明 |
|------|-----------|------|
| 并发模型 | goroutine → async/await | Rust tokio 成熟，能力对等 |
| 跨平台编译 | Go cross → cargo cross | Rust 更成熟，apple/android 均支持 |
| 小程序 WASM | Go WASM → Rust WASM | Rust WASM 生态更成熟，产物更小 |
| Tauri 集成 | FFI 桥接 → 直接调用 | Rust 是 Tauri 原生语言，无 FFI 开销 |
| 学习曲线 | Go 简单 | Rust 有借用检查器学习成本 |
| 扫描性能 | 相当 | 均为 C 级别性能 |
| 社区生态 | 网络库均成熟 | Rust 的 async-stdin/Tokio 更现代 |

**结论**：统一为 Rust：
- PC 端：无 FFI 开销，直接调用
- 小程序端：WASM 产物更小（Rust WASM 比 Go WASM 小 30-50%）
- 统一技术栈，减少维护负担

**设计原则**：
- 核心扫描能力（Rust）共享，两版本前端独立
- 小程序版：轻量拉新，受微信 API 限制，Rust 核心编译为 WASM
- PC 版：功能完整，无限制，Rust 核心直接集成

---

## 3. 核心扫描能力（Rust）

### 3.1 技术选型

- **语言**：Rust 1.75+（nightly for WASM）
- **异步**：tokio + async/await
- **WASM**：wasm-bindgen + wasm-pack
- **输出**：WASM（小程序）+ 原生库（PC）

### 3.2 功能列表

| 功能 | 说明 |
|------|------|
| C1 · mDNS 发现 | 发现局域网 mDNS 服务（`_http._tcp` 等） |
| C2 · UDP SSDP | M-SEARCH 广播，解析 UPnP 设备 |
| C3 · TCP 端口扫描 | 并发扫描，支持全端口 |
| C4 · Banner 抓取 | 协议探针，读取服务banner |
| C5 · 服务指纹 | 内置规则库，匹配服务类型 |
| C6 · MAC OUI | 厂商识别（离线库） |

### 3.3 文件结构

```
core/
├── scanner/
│   ├── mdns.rs          # mDNS 发现
│   ├── ssdp.rs          # UDP SSDP
│   ├── tcp.rs           # TCP 端口扫描
│   ├── banner.rs        # Banner 抓取
│   └── registry.rs      # 服务指纹规则库
├── util/
│   ├── oui.rs           # MAC OUI 厂商库
│   └── ip.rs            # IP/子网工具
└── Cargo.toml
```

---

## 4. 微信小程序版

### 4.1 技术选型

- **框架**：Taro 4.x + React 18
- **编译目标**：微信小程序
- **状态管理**：Zustand
- **Canvas**：原生 API

### 4.2 功能列表

| 功能 | 说明 |
|------|------|
| F1-1 · mDNS 服务扫描 | `wx.startLocalServiceDiscovery` |
| F1-2 · UDP SSDP 探测 | `wx.createUDPSocket` 发送 M-SEARCH |
| F1-3 · TCP 端口探测 | 白名单端口（80/443/8080/554/5000/9000） |
| F1-4 · 设备拓扑图 | Canvas 绘制，MAC OUI 识别厂商 |
| F1-5 · 本地 IP 感知 | `wx.getLocalIPAddress` 推断子网 |
| F1-6 · 扫描历史记录 | `wx.setStorage` 持久化 |

### 4.3 文件结构

```
src/
├── pages/
│   ├── index/           # 首页，扫描入口
│   ├── devices/         # 设备列表
│   ├── topology/        # 拓扑图
│   └── history/         # 扫描历史
├── components/
│   ├── DeviceCard/
│   ├── TopoCanvas/
│   └── ScanButton/
├── services/
│   ├── mdns.ts
│   ├── udp.ts
│   ├── tcp.ts
│   └── storage.ts
├── stores/
│   └── deviceStore.ts
└── utils/
    ├── oui.ts
    └── ip.ts
```

### 4.4 关键 API 设计

**mDNS 发现**：
```typescript
wx.startLocalServiceDiscovery({
  serviceType: '_http._tcp',
  fail: (err) => {
    if (err.errCode === -1) fallbackToTCPScan()
  }
})

wx.onLocalServiceFound((res) => {
  addDevice(res)
})
```

**TCP 端口探测**：
```typescript
const WHITE_PORTS = [80, 443, 8080, 554, 5000, 9000, 49152]

async function probePorts(ip: string, ports: number[]) {
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

## 5. PC 客户端版（完整功能）

### 5.1 技术选型

- **框架**：Tauri 2.x（Rust 原生，无 FFI 开销）
- **前端**：React + TypeScript
- **IPC**：Tauri commands（直接调用 Rust Core）

### 5.2 定位

用户电脑上安装，全部功能本地运行，无任何限制：
- 无微信 API 限制
- 无网络访问限制
- 无端口黑名单

### 5.3 功能列表

| 功能 | 说明 |
|------|------|
| P1-1 · 完整端口扫描 | 全端口 TCP（1-65535），无限制 |
| P1-2 · mDNS / UDP SSDP | 完整实现 |
| P1-3 · 设备拓扑图 | Canvas，更流畅 |
| P1-4 · Banner 抓取 | 全协议支持（HTTP/SSH/FTP/SMTP/MySQL 等）|
| P1-5 · 服务指纹识别 | 内置规则库，协议识别 |
| P1-6 · TLS 审计 | 证书检查、弱套件检测、过期检测 |
| P1-7 · 扫描历史 | 本地 SQLite |
| P1-8 · 报告导出 | PDF/JSON/HTML |

### 5.4 文件结构

```
netprowl-pc/
├── src/                  # React 前端
│   ├── pages/
│   ├── components/
│   └── stores/
├── src-tauri/           # Rust 后端
│   ├── main.rs
│   ├── commands/
│   └── scanner/         # Rust 原生扫描模块
└── Cargo.toml
```

---

## 6. 数据流

```
用户操作
    │
    ├─── 微信小程序版
    │         │
    │         ├─── mDNS（wx.startLocalServiceDiscovery）
    │         ├─── UDP SSDP（wx.createUDPSocket）
    │         └─── TCP 白名单端口（wx.createTCPSocket）
    │
    └─── PC 客户端版
              │
              ├─── Rust Core（mDNS/UDP/全端口 TCP）
              ├─── Banner 抓取
              └─── TLS 审计
```

---

## 7. MVP 验收标准

### 7.1 微信小程序版
- [ ] iOS / Android 真机均能正常发现局域网设备
- [ ] 设备拓扑图在 10+ 设备时不卡顿
- [ ] 扫描全程不触发微信安全拦截
- [ ] 历史记录可正常读写，不超存储上限（10MB）

### 7.2 PC 客户端版
- [ ] 全端口 TCP 扫描正常（100+ 并发）
- [ ] Banner 抓取成功（HTTP/SSH/FTP 等）
- [ ] 设备拓扑图流畅渲染 20+ 设备
- [ ] 扫描历史正确存取

---

## 8. Phase 1 里程碑

| 周次 | 任务 |
|------|------|
| W1-2 | 技术可行性验证（Rust Core + WASM 真机测试） |
| W3-4 | Rust 核心扫描能力完成 |
| W5 | 小程序版 UI / 拓扑图（WASM 集成） |
| W6 | PC 客户端版 UI / 拓扑图（Rust 直接调用） |
| W7 | 两版本集成测试 + Bug 修复 |

---

## 9. 未来扩展（Phase 2+）

| 组件 | 说明 |
|------|------|
| Probe Agent | 可选部署，解锁全端口扫描（小程序版） |
| 云端中台 | DeepSeek AI / CVE 库 / 扫描历史云同步 |
| 安全检测 | 默认凭据检测 / TLS 审计 / 未授权访问 |
| 公网侦察 | Shodan/FOFA 集成 / 子域名枚举 |

---

*规格书版本：v1.3 · NetProwl Phase 1 MVP（Rust 统一语言）*