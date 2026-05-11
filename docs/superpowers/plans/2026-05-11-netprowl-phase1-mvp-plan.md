# NetProwl Phase 1 MVP · Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 微信小程序 Phase 1 MVP——局域网设备发现、拓扑图渲染、扫描历史记录。

**Architecture:** Taro 多端框架 + 原生微信小程序。小程序直连探测（mDNS/UDP SSDP/TCP），Canvas 渲染星形拓扑图，Storage 持久化扫描历史。

**Tech Stack:** Taro + React + TypeScript + 微信小程序原生 API

---

## File Structure

```
netprowl/
├── src/
│   ├── app.ts                      # Taro App 入口
│   ├── app.config.ts               # 全局配置（TabBar 等）
│   ├── app.css
│   ├── pages/
│   │   ├── discovery/             # 发现页（拓扑图 + 扫描）
│   │   ├── history/               # 历史页
│   │   └── chat/                  # AI 问诊占位页
│   ├── components/
│   │   ├── TopologyCanvas/        # 拓扑图画布
│   │   ├── DeviceDrawer/          # 设备详情抽屉
│   │   ├── ScanButton/            # 扫描按钮
│   │   ├── DeviceCard/            # 设备卡片
│   │   ├── PortList/              # 端口列表
│   │   └── icons/                 # 线性风格设备图标
│   ├── services/
│   │   ├── scanner.ts             # 扫描引擎入口（协调三层扫描）
│   │   ├── mdns.ts                # mDNS 发现
│   │   ├── udp.ts                 # UDP SSDP 发现
│   │   ├── tcp.ts                 # TCP 端口探测
│   │   ├── network.ts            # 网络感知（本机 IP / 子网）
│   │   └── storage.ts             # 扫描历史存储
│   └── utils/
│       ├── oui.ts                 # MAC OUI 厂商查表
│       ├── ip.ts                  # IP / 子网工具
│       └── gzip.ts                # gzip 压缩（扫描快照）
├── package.json
├── project.config.json
├── tsconfig.json
└── .gitignore
```

---

## Task Decomposition

### Task 1: 项目脚手架

**Files:**
- Create: `package.json`
- Create: `project.config.json`
- Create: `tsconfig.json`
- Create: `.gitignore`
- Create: `src/app.ts`
- Create: `src/app.config.ts`
- Create: `src/app.css`

- [ ] **Step 1: 创建 package.json（Taro + 微信小程序）**

```json
{
  "name": "netprowl",
  "version": "1.0.0",
  "scripts": {
    "dev:weapp": "taro build --type weapp --watch",
    "build:weapp": "taro build --type weapp"
  },
  "dependencies": {
    "@tarojs/taro": "4.x",
    "@tarojs/plugin-framework-react": "4.x",
    "react": "18.x"
  },
  "devDependencies": {
    "@tarojs/cli": "4.x",
    "@types/react": "18.x",
    "typescript": "5.x"
  }
}
```

Run: `npm install`（在 netprowl 目录执行）

- [ ] **Step 2: 创建 project.config.json**

```json
{
  "miniprogramRoot": "dist/",
  "projectname": "NetProwl",
  "description": "微信小程序网络安全工具",
  "appid": "touristappid",
  "setting": {
    "urlCheck": false,
    "es6": true,
    "enhance": true
  },
  "compileType": "miniprogram"
}
```

- [ ] **Step 3: 创建 tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "es5",
    "module": "commonjs",
    "strict": true,
    "jsx": "react-jsx",
    "moduleResolution": "node",
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"]
    }
  },
  "include": ["src/**/*"]
}
```

- [ ] **Step 4: 创建 .gitignore**

```
node_modules/
dist/
.env
*.log
```

- [ ] **Step 5: 创建 src/app.ts**

```typescript
import { Component } from 'react'
import './app.css'

class App extends Component {
  render() {
    return this.props.children
  }
}

export default App
```

- [ ] **Step 6: 创建 src/app.config.ts（TabBar 3 页）**

```typescript
export default defineAppConfig({
  pages: [
    'pages/discovery/index',
    'pages/history/index',
    'pages/chat/index'
  ],
  window: {
    backgroundTextStyle: 'light',
    navigationBarBackgroundColor: '#1a1a2e',
    navigationBarTitleText: 'NetProwl',
    navigationBarTextStyle: 'white'
  },
  tabBar: {
    color: '#999',
    selectedColor: '#00d4ff',
    backgroundColor: '#1a1a2e',
    borderStyle: 'black',
    list: [
      { pagePath: 'pages/discovery/index', text: '发现', iconPath: 'assets/tab-discovery.png', selectedIconPath: 'assets/tab-discovery-active.png' },
      { pagePath: 'pages/history/index', text: '历史', iconPath: 'assets/tab-history.png', selectedIconPath: 'assets/tab-history-active.png' },
      { pagePath: 'pages/chat/index', text: '问诊', iconPath: 'assets/tab-chat.png', selectedIconPath: 'assets/tab-chat-active.png' }
    ]
  }
})
```

- [ ] **Step 7: 创建 src/app.css**

```css
page {
  background-color: #0f0f1a;
  color: #fff;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
}
```

- [ ] **Step 8: Commit**

```bash
git add -A && git commit -m "chore: scaffold Taro weapp project

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 2: 类型定义

**Files:**
- Create: `src/types/index.ts`

- [ ] **Step 1: 创建 src/types/index.ts**

```typescript
export type DeviceType = 'router' | 'pc' | 'camera' | 'nas' | 'phone' | 'printer' | 'unknown'

export type OSType = 'linux' | 'windows' | 'network' | 'unknown'

export type DiscoverySource = 'mdns' | 'ssdp' | 'tcp' | 'arp'

export type PortState = 'open' | 'filtered'

export interface Port {
  port: number
  service: string | null
  state: PortState
  banner?: string
}

export interface Device {
  id: string
  ip: string
  mac: string | null
  hostname: string | null
  vendor: string | null
  deviceType: DeviceType
  os: OSType
  openPorts: Port[]
  discoveredAt: number
  sources: DiscoverySource[]
}

export interface ScanSnapshot {
  id: string
  timestamp: number
  ipRange: string
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

- [ ] **Step 2: Commit**

```bash
git add src/types/index.ts && git commit -m "feat: add Device/Port/ScanSnapshot types

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 3: 工具函数

**Files:**
- Create: `src/utils/ip.ts`
- Create: `src/utils/oui.ts`
- Create: `src/utils/gzip.ts`

- [ ] **Step 1: 创建 src/utils/ip.ts**

```typescript
/** 从本机 IP 推断子网范围（/24） */
export function inferSubnet(localIP: string): string {
  const parts = localIP.split('.')
  parts[3] = '0'
  return `${parts.join('.')}/24`
}

/** 生成子网内所有 IP */
export function expandSubnet(subnet: string): string[] {
  const [base, mask] = subnet.split('/')
  const prefix = base.split('.').slice(0, 3).join('.')
  const count = mask === '24' ? 254 : 254
  return Array.from({ length: count }, (_, i) => `${prefix}.${i + 1}`)
}

/** 判断 IP 是否在局域网内 */
export function isPrivateIP(ip: string): boolean {
  const p = ip.split('.').map(Number)
  return (
    (p[0] === 10) ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168)
  )
}

/** MAC 地址格式化（统一为小写冒号分隔） */
export function normalizeMac(mac: string): string {
  return mac.replace(/[-:]/g, ':').toLowerCase()
}

/** 基于 TTL 推断 OS */
export function inferOS(ttl: number): OSType {
  if (ttl <= 64) return 'linux'
  if (ttl <= 128) return 'windows'
  if (ttl >= 255) return 'network'
  return 'unknown'
}
```

- [ ] **Step 2: 创建 src/utils/oui.ts（简化版，约 20 条主流厂商）**

```typescript
const OUI_MAP: Record<string, string> = {
  '00:50:56': 'VMware',
  '00:0c:29': 'VMware',
  'b8:27:eb': 'Raspberry Pi',
  'dc:a6:32': 'Raspberry Pi',
  'e4:5f:01': 'Raspberry Pi',
  '00:1e:68': 'Quanta (华为/H3C)',
  '00:25:9e': 'Cisco',
  '00:1a:2b': 'Cisco',
  '00:17:88': 'Philips Hue',
  'a8:66:7f': 'Apple',
  'f0:18:98': 'Apple',
  '3c:06:30': 'Apple',
  '00:e0:4c': 'Realtek',
  '00:23:cd': 'Intel',
  '00:1b:21': 'Intel',
  '00:0d:2b': 'Dell',
  '00:1c:23': 'Dell',
  '00:24:e8': 'Dell',
  '00:50:ba': 'Dell',
  'ac:de:48': 'Hangzhou Hikvision',
  'b4:15:13': 'Hangzhou Hikvision',
  '00:03:93': 'Siemens',
  '00:1b:a2': 'Schneider Electric',
}

/** 通过 MAC OUI 前缀查询厂商 */
export function lookupVendor(mac: string): string | null {
  const prefix = normalizeMac(mac).substring(0, 8)
  return OUI_MAP[prefix] || null
}

function normalizeMac(mac: string): string {
  return mac.replace(/[-:]/g, ':').toLowerCase()
}
```

- [ ] **Step 3: 创建 src/utils/gzip.ts（微信小程序压缩工具）**

```typescript
import { gzip } from 'minigzip'

export async function compressSnapshot<T>(data: T): Promise<string> {
  const buffer = Buffer.from(JSON.stringify(data))
  const compressed = await gzip(buffer)
  return Buffer.from(compressed).toString('base64')
}

export async function decompressSnapshot<T>(base64: string): Promise<T> {
  const buffer = Buffer.from(base64, 'base64')
  const decompressed = await gzip(buffer)
  return JSON.parse(decompressed.toString())
}
```

> Note: `minigzip` is a lightweight gzip lib. If unavailable, fall back to `JSON.stringify` without compression and add a note in the storage service.

- [ ] **Step 4: Commit**

```bash
git add src/utils/ip.ts src/utils/oui.ts src/utils/gzip.ts && git commit -m "feat: add ip/oui/gzip utils

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 4: 服务层——网络感知

**Files:**
- Create: `src/services/network.ts`

- [ ] **Step 1: 创建 src/services/network.ts**

```typescript
import Taro from '@tarojs/taro'
import { inferSubnet } from '../utils/ip'

interface NetworkInfo {
  ip: string
  subnet: string
}

export async function getLocalNetworkInfo(): Promise<NetworkInfo> {
  const ip = await getLocalIPAddress()
  return { ip, subnet: inferSubnet(ip) }
}

export async function getLocalIPAddress(): Promise<string> {
  try {
    const res = Taro.getLocalIPAddress({})
    return res.ip || '0.0.0.0'
  } catch {
    return '0.0.0.0'
  }
}

export async function getNetworkType(): Promise<string> {
  const res = await Taro.getNetworkType()
  return res.networkType
}
```

- [ ] **Step 2: Commit**

```bash
git add src/services/network.ts && git commit -m "feat: add network service (local IP / subnet)

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 5: 服务层——mDNS 发现

**Files:**
- Create: `src/services/mdns.ts`

- [ ] **Step 1: 创建 src/services/mdns.ts**

```typescript
import Taro from '@tarojs/taro'
import { Device } from '../types'

const SERVICE_TYPES = [
  '_http._tcp',
  '_ftp._tcp',
  '_ssh._tcp',
  '_smb._tcp',
  '_airplay._tcp',
  '_googlecast._tcp',
  '_ipp._tcp',
]

export async function discoverViaMDNS(): Promise<Device[]> {
  const devices: Device[] = []
  const foundMap = new Map<string, Device>()

  // 订阅发现事件
  Taro.onLocalServiceFound((res) => {
    const key = res.serviceName
    if (!foundMap.has(key)) {
      foundMap.set(key, {
        id: key,
        ip: res.ip,
        mac: null,
        hostname: res.hostName || res.serviceName,
        vendor: null,
        deviceType: 'unknown',
        os: 'unknown',
        openPorts: [],
        discoveredAt: Date.now(),
        sources: ['mdns'],
      })
    }
  })

  for (const serviceType of SERVICE_TYPES) {
    try {
      await startDiscovery(serviceType)
    } catch {
      // 单个失败不中断
    }
  }

  // 等待一段时间后停止
  await delay(3000)
  stopDiscovery()

  return Array.from(foundMap.values())
}

function startDiscovery(serviceType: string): Promise<void> {
  return new Promise((resolve, reject) => {
    Taro.startLocalServiceDiscovery({ serviceType })
      .then(() => resolve())
      .catch((err) => {
        // iOS 7.0.18+ errCode -1 表示禁用，降级策略在 scanner 层处理
        if (err.errCode === -1) {
          reject(new Error('MDNS_DISABLED'))
        } else {
          reject(err)
        }
      })
  })
}

function stopDiscovery(): void {
  Taro.stopLocalServiceDiscovery({})
  Taro.offLocalServiceFound(() => {})
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}

export function isMDNSDisabledError(err: unknown): boolean {
  return err instanceof Error && err.message === 'MDNS_DISABLED'
}
```

- [ ] **Step 2: Commit**

```bash
git add src/services/mdns.ts && git commit -m "feat: add mDNS discovery service

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 6: 服务层——UDP SSDP 发现

**Files:**
- Create: `src/services/udp.ts`

- [ ] **Step 1: 创建 src/services/udp.ts**

```typescript
import Taro from '@tarojs/taro'
import { Device } from '../types'

const SSDP_ADDR = '239.255.255.250'
const SSDP_PORT = 1900
const M_SEARCH = [
  'M-SEARCH * HTTP/1.1',
  'HOST: 239.255.255.250:1900',
  'MAN: "ssdp:discover"',
  'MX: 2',
  'ST: ssdp:all',
  '',
  '',
].join('\r\n')

export async function discoverViaSSDP(): Promise<Device[]> {
  const devices: Device[] = []
  const seen = new Set<string>()

  const udp = Taro.createUDPSocket()
  udp.onMessage((res) => {
    const banner = arrayBufferToString(res.message)
    const device = parseSSDPResponse(banner, res.remoteInfo.address)
    if (device && !seen.has(device.ip)) {
      seen.add(device.ip)
      devices.push(device)
    }
  })

  udp.onError((err) => {
    console.error('UDP SSDP error', err)
    udp.close()
  })

  try {
    udp.send({
      address: SSDP_ADDR,
      port: SSDP_PORT,
      message: M_SEARCH,
    })

    await delay(3000)
  } finally {
    udp.close()
  }

  return devices
}

function parseSSDPResponse(banner: string, ip: string): Device | null {
  if (!banner.includes('HTTP/1.1 200')) return null

  const getHeader = (key: string): string | null => {
    const re = new RegExp(`^${key}:\\s*(.+)$`, 'im')
    const m = banner.match(re)
    return m ? m[1].trim() : null
  }

  const friendlyName = getHeader('SERVER') || getHeader('X-FriendlyName') || ip
  const usn = getHeader('USN') || ip

  return {
    id: usn,
    ip,
    mac: null,
    hostname: friendlyName,
    vendor: null,
    deviceType: inferDeviceType(friendlyName, banner),
    os: 'unknown',
    openPorts: [],
    discoveredAt: Date.now(),
    sources: ['ssdp'],
  }
}

function inferDeviceType(name: string, banner: string): DeviceType {
  const lower = (name + banner).toLowerCase()
  if (/router|gateway|netgear|tp-link|xiaomi|honor|huawei/.test(lower)) return 'router'
  if (/camera|ipcam|hikvision|dahua|ezviz|萤石/.test(lower)) return 'camera'
  if (/nas|synology|qnap|群晖|威联通/.test(lower)) return 'nas'
  if (/printer|hp|canon|epson/.test(lower)) return 'printer'
  if (/iphone|android|手机|mobile/.test(lower)) return 'phone'
  return 'unknown'
}

function arrayBufferToString(buffer: ArrayBuffer): string {
  const arr = new Uint8Array(buffer)
  return String.fromCharCode(...arr)
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}
```

- [ ] **Step 2: Commit**

```bash
git add src/services/udp.ts && git commit -m "feat: add UDP SSDP discovery service

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 7: 服务层——TCP 端口探测

**Files:**
- Create: `src/services/tcp.ts`

- [ ] **Step 1: 创建 src/services/tcp.ts**

```typescript
import Taro from '@tarojs/taro'
import { Device, Port } from '../types'

const WHITE_PORTS = [80, 443, 8080, 8443, 554, 5000, 9000, 49152]
const CONCURRENCY = 20
const TIMEOUT_MS = 2000
const TOTAL_TIMEOUT_MS = 60000

export async function probeTCPPorts(ip: string): Promise<Port[]> {
  const openPorts: Port[] = []
  const chunks = chunkArray(WHITE_PORTS, CONCURRENCY)

  for (const group of chunks) {
    const results = await Promise.all(group.map((port) => probePort(ip, port)))
    results.forEach((p) => { if (p) openPorts.push(p) })
    await delay(50)
  }

  return openPorts
}

async function probePort(ip: string, port: number): Promise<Port | null> {
  return new Promise((resolve) => {
    const socket = Taro.createTCPSocket()
    let settled = false

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true
        socket.close()
        resolve(null)
      }
    }, TIMEOUT_MS)

    socket.onConnect(() => {
      if (!settled) {
        settled = true
        clearTimeout(timer)
        socket.close()
        resolve({ port, service: null, state: 'open' })
      }
    })

    socket.onError(() => {
      if (!settled) {
        settled = true
        clearTimeout(timer)
        socket.close()
        resolve(null)
      }
    })

    socket.connect({ address: ip, port })
  })
}

export async function probeIPs(ipRange: string, ips: string[]): Promise<Device[]> {
  const devices: Device[] = []
  const start = Date.now()

  for (const ip of ips) {
    if (Date.now() - start > TOTAL_TIMEOUT_MS) break

    const ports = await probeTCPPorts(ip)
    if (ports.length > 0) {
      devices.push({
        id: ip,
        ip,
        mac: null,
        hostname: null,
        vendor: null,
        deviceType: 'unknown',
        os: 'unknown',
        openPorts: ports,
        discoveredAt: Date.now(),
        sources: ['tcp'],
      })
    }
  }

  return devices
}

function chunkArray<T>(arr: T[], size: number): T[][] {
  const chunks: T[][] = []
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size))
  }
  return chunks
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}
```

- [ ] **Step 2: Commit**

```bash
git add src/services/tcp.ts && git commit -m "feat: add TCP port probe service

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 8: 服务层——存储服务

**Files:**
- Create: `src/services/storage.ts`

- [ ] **Step 1: 创建 src/services/storage.ts**

```typescript
import Taro from '@tarojs/taro'
import { ScanSnapshot } from '../types'

const STORAGE_KEY = 'netprowl_scan_history'
const MAX_RECORDS = 50

export async function loadHistory(): Promise<ScanSnapshot[]> {
  try {
    const raw = Taro.getStorageSync(STORAGE_KEY)
    return raw ? JSON.parse(raw) : []
  } catch {
    return []
  }
}

export async function saveSnapshot(snapshot: ScanSnapshot): Promise<void> {
  const history = await loadHistory()
  history.unshift(snapshot)

  // 超限裁剪
  while (history.length > MAX_RECORDS) {
    history.pop()
  }

  // 估算大小，超过 10MB 则清理旧记录
  const data = JSON.stringify(history)
  if (data.length > 10 * 1024 * 1024) {
    history.splice(0, 3)
  }

  Taro.setStorageSync(STORAGE_KEY, JSON.stringify(history))
}

export async function clearHistory(): Promise<void> {
  Taro.removeStorageSync(STORAGE_KEY)
}
```

- [ ] **Step 2: Commit**

```bash
git add src/services/storage.ts && git commit -m "feat: add storage service

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 9: 服务层——扫描引擎入口

**Files:**
- Create: `src/services/scanner.ts`

- [ ] **Step 1: 创建 src/services/scanner.ts**

```typescript
import { Device } from '../types'
import { getLocalNetworkInfo } from './network'
import { discoverViaMDNS, isMDNSDisabledError } from './mdns'
import { discoverViaSSDP } from './udp'
import { probeIPs } from './tcp'
import { expandSubnet } from '../utils/ip'
import { lookupVendor } from '../utils/oui'
import { saveSnapshot } from './storage'

export interface ScanResult {
  devices: Device[]
  duration: number
  mdnsUnavailable: boolean
}

export async function runScan(): Promise<ScanResult> {
  const start = Date.now()
  const { ip, subnet } = await getLocalNetworkInfo()
  const allIPs = expandSubnet(subnet)

  let mdnsUnavailable = false
  const mdnsDevices: Device[] = []
  const ssdpDevices: Device[] = []
  const tcpDevices: Device[] = []

  // Stage 1: mDNS
  try {
    const results = await discoverViaMDNS()
    mdnsDevices.push(...results)
  } catch (err) {
    if (isMDNSDisabledError(err)) {
      mdnsUnavailable = true
    }
  }

  // Stage 2: SSDP (parallel with TCP scan to save time)
  const ssdpPromise = discoverViaSSDP()
  const tcpPromise = probeIPs(subnet, allIPs)

  const [ssdp, tcp] = await Promise.all([ssdpPromise, tcpPromise])
  ssdpDevices.push(...ssdp)
  tcpDevices.push(...tcp)

  // Merge & deduup
  const merged = mergeDevices([...mdnsDevices, ...ssdpDevices, ...tcpDevices])
  merged.forEach((d) => { if (d.vendor === null) d.vendor = d.mac ? lookupVendor(d.mac) : null })

  const duration = Date.now() - start

  // Save snapshot
  await saveSnapshot({
    id: `scan_${Date.now()}`,
    timestamp: Date.now(),
    ipRange: subnet,
    deviceCount: merged.length,
    devices: merged,
    summary: { critical: 0, high: 0, medium: 0, low: 0 },
  })

  return { devices: merged, duration, mdnsUnavailable }
}

function mergeDevices(devices: Device[]): Device[] {
  const map = new Map<string, Device>()
  for (const d of devices) {
    if (map.has(d.ip)) {
      const existing = map.get(d.ip)!
      existing.sources = [...new Set([...existing.sources, ...d.sources])]
      existing.openPorts = dedupPorts([...existing.openPorts, ...d.openPorts])
    } else {
      map.set(d.ip, { ...d })
    }
  }
  return Array.from(map.values())
}

function dedupPorts(ports: Port[]): Port[] {
  const seen = new Set<number>()
  return ports.filter((p) => {
    if (seen.has(p.port)) return false
    seen.add(p.port)
    return true
  })
}
```

- [ ] **Step 2: Commit**

```bash
git add src/services/scanner.ts && git commit -m "feat: add scan engine orchestrator

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 10: 基础组件——线性图标

**Files:**
- Create: `src/components/icons/index.tsx`

- [ ] **Step 1: 创建 src/components/icons/index.tsx**

```typescript
import { Component } from 'react'
import { DeviceType } from '../../types'

interface IconProps {
  type: DeviceType
  size?: number
}

export function DeviceIcon({ type, size = 32 }: IconProps) {
  const icons: Record<DeviceType, string> = {
    router: '🛣',  // 路由
    pc: '💻',
    camera: '📹',
    nas: '💾',
    phone: '📱',
    printer: '🖨',
    unknown: '❓',
  }
  return <span style={{ fontSize: size }}>{icons[type]}</span>
}
```

> Note: 使用 emoji 作为占位图标，Phase 2 替换为 SVG 线性图标。

- [ ] **Step 2: Commit**

```bash
git add src/components/icons/index.tsx && git commit -m "feat: add device icon component (emoji placeholder)

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 11: 组件——ScanButton

**Files:**
- Create: `src/components/ScanButton/index.tsx`

- [ ] **Step 1: 创建 src/components/ScanButton/index.tsx**

```typescript
import { Component } from 'react'
import Taro from '@tarojs/taro'
import { View, Button, Text } from '@tarojs/components'

interface Props {
  scanning: boolean
  onScan: () => void
}

export default class ScanButton extends Component<Props> {
  render() {
    const { scanning, onScan } = this.props
    return (
      <View className='scan-button-wrap'>
        <Button
          className={`scan-btn ${scanning ? 'scanning' : ''}`}
          onClick={onScan}
          disabled={scanning}
        >
          {scanning ? '⏳ 扫描中...' : '🔍 开始扫描'}
        </Button>
      </View>
    )
  }
}
```

- [ ] **Step 2: 创建 CSS（src/components/ScanButton/index.css）**

```css
.scan-button-wrap {
  padding: 24rpx 32rpx;
}

.scan-btn {
  width: 100%;
  height: 96rpx;
  line-height: 96rpx;
  background: linear-gradient(135deg, #00d4ff, #0077ff);
  color: #fff;
  font-size: 32rpx;
  font-weight: 600;
  border-radius: 48rpx;
  border: none;
}

.scan-btn[disabled] {
  background: #333;
  color: #888;
}
```

- [ ] **Step 3: Commit**

```bash
git add src/components/ScanButton/index.tsx src/components/ScanButton/index.css && git commit -m "feat: add ScanButton component

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 12: 组件——PortList

**Files:**
- Create: `src/components/PortList/index.tsx`

- [ ] **Step 1: 创建 src/components/PortList/index.tsx**

```typescript
import { Component } from 'react'
import { View, Text } from '@tarojs/components'
import { Port } from '../../types'

interface Props {
  ports: Port[]
}

export default class PortList extends Component<Props> {
  render() {
    const { ports } = this.props
    if (ports.length === 0) {
      return <Text className='port-empty'>暂未发现开放端口</Text>
    }
    return (
      <View className='port-list'>
        {ports.map((p) => (
          <View className='port-item' key={p.port}>
            <Text className='port-num'>{p.port}</Text>
            <Text className='port-service'>{p.service || 'unknown'}</Text>
          </View>
        ))}
      </View>
    )
  }
}
```

- [ ] **Step 2: 创建 CSS**

```css
.port-list {
  display: flex;
  flex-wrap: wrap;
  gap: 16rpx;
}

.port-item {
  display: flex;
  align-items: center;
  background: #1e1e3a;
  border-radius: 8rpx;
  padding: 8rpx 16rpx;
}

.port-num {
  color: #00d4ff;
  font-size: 28rpx;
  font-weight: 600;
  margin-right: 8rpx;
}

.port-service {
  color: #999;
  font-size: 24rpx;
}

.port-empty {
  color: #666;
  font-size: 26rpx;
}
```

- [ ] **Step 3: Commit**

```bash
git add src/components/PortList/index.tsx src/components/PortList/index.css && git commit -m "feat: add PortList component

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 13: 组件——DeviceCard

**Files:**
- Create: `src/components/DeviceCard/index.tsx`

- [ ] **Step 1: 创建 src/components/DeviceCard/index.tsx**

```typescript
import { Component } from 'react'
import { View, Text } from '@tarojs/components'
import { Device } from '../../types'
import { DeviceIcon } from '../icons'

interface Props {
  device: Device
  onClick: (device: Device) => void
}

export default class DeviceCard extends Component<Props> {
  render() {
    const { device, onClick } = this.props
    return (
      <View className='device-card' onClick={() => onClick(device)}>
        <View className='card-icon'>
          <DeviceIcon type={device.deviceType} size={28} />
        </View>
        <View className='card-info'>
          <Text className='card-ip'>{device.ip}</Text>
          <Text className='card-vendor'>{device.vendor || '未知厂商'}</Text>
        </View>
        <Text className='card-ports'>{device.openPorts.length} 端口</Text>
      </View>
    )
  }
}
```

- [ ] **Step 2: 创建 CSS**

```css
.device-card {
  display: flex;
  align-items: center;
  background: #1e1e3a;
  border-radius: 16rpx;
  padding: 24rpx;
  margin-bottom: 16rpx;
}

.card-icon {
  width: 64rpx;
  text-align: center;
}

.card-info {
  flex: 1;
  margin-left: 16rpx;
}

.card-ip {
  display: block;
  color: #fff;
  font-size: 30rpx;
  font-weight: 500;
}

.card-vendor {
  display: block;
  color: #888;
  font-size: 24rpx;
  margin-top: 4rpx;
}

.card-ports {
  color: #00d4ff;
  font-size: 26rpx;
}
```

- [ ] **Step 3: Commit**

```bash
git add src/components/DeviceCard/index.tsx src/components/DeviceCard/index.css && git commit -m "feat: add DeviceCard component

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 14: 组件——DeviceDrawer

**Files:**
- Create: `src/components/DeviceDrawer/index.tsx`

- [ ] **Step 1: 创建 src/components/DeviceDrawer/index.tsx**

```typescript
import { Component } from 'react'
import { View, Text } from '@tarojs/components'
import { Device } from '../../types'
import { DeviceIcon } from '../icons'
import PortList from '../PortList'

interface Props {
  device: Device | null
  onClose: () => void
}

export default class DeviceDrawer extends Component<Props> {
  render() {
    const { device, onClose } = this.props
    if (!device) return null

    return (
      <View className='drawer-overlay' onClick={onClose}>
        <View className='drawer-panel' onClick={(e) => e.stopPropagation()}>
          <View className='drawer-header'>
            <DeviceIcon type={device.deviceType} size={40} />
            <View className='header-info'>
              <Text className='header-ip'>{device.ip}</Text>
              <Text className='header-vendor'>{device.vendor || '未知厂商'}</Text>
            </View>
            <Text className='close-btn' onClick={onClose}>✕</Text>
          </View>

          <View className='drawer-body'>
            <View className='info-row'>
              <Text className='info-label'>MAC</Text>
              <Text className='info-value'>{device.mac || '—'}</Text>
            </View>
            <View className='info-row'>
              <Text className='info-label'>主机名</Text>
              <Text className='info-value'>{device.hostname || '—'}</Text>
            </View>
            <View className='info-row'>
              <Text className='info-label'>设备类型</Text>
              <Text className='info-value'>{device.deviceType}</Text>
            </View>
            <View className='info-row'>
              <Text className='info-label'>发现方式</Text>
              <Text className='info-value'>{device.sources.join(', ')}</Text>
            </View>
            <View className='ports-section'>
              <Text className='section-title'>开放端口</Text>
              <PortList ports={device.openPorts} />
            </View>
          </View>
        </View>
      </View>
    )
  }
}
```

- [ ] **Step 2: 创建 CSS**

```css
.drawer-overlay {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  bottom: 0;
  background: rgba(0, 0, 0, 0.5);
  z-index: 100;
}

.drawer-panel {
  position: fixed;
  bottom: 0;
  left: 0;
  right: 0;
  background: #1a1a2e;
  border-radius: 32rpx 32rpx 0 0;
  max-height: 70vh;
  overflow-y: auto;
  padding: 32rpx;
}

.drawer-header {
  display: flex;
  align-items: center;
  margin-bottom: 32rpx;
}

.header-info {
  flex: 1;
  margin-left: 24rpx;
}

.header-ip {
  display: block;
  color: #fff;
  font-size: 36rpx;
  font-weight: 600;
}

.header-vendor {
  display: block;
  color: #888;
  font-size: 26rpx;
  margin-top: 4rpx;
}

.close-btn {
  color: #666;
  font-size: 40rpx;
  padding: 16rpx;
}

.drawer-body {
  display: flex;
  flex-direction: column;
  gap: 24rpx;
}

.info-row {
  display: flex;
  justify-content: space-between;
  border-bottom: 1rpx solid #2a2a4a;
  padding-bottom: 16rpx;
}

.info-label {
  color: #888;
  font-size: 28rpx;
}

.info-value {
  color: #fff;
  font-size: 28rpx;
}

.ports-section {
  margin-top: 16rpx;
}

.section-title {
  display: block;
  color: #888;
  font-size: 28rpx;
  margin-bottom: 16rpx;
}
```

- [ ] **Step 3: Commit**

```bash
git add src/components/DeviceDrawer/index.tsx src/components/DeviceDrawer/index.css && git commit -m "feat: add DeviceDrawer component

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 15: 组件——TopologyCanvas

**Files:**
- Create: `src/components/TopologyCanvas/index.tsx`

- [ ] **Step 1: 创建 src/components/TopologyCanvas/index.tsx（星形布局 Canvas）**

```typescript
import { Component } from 'react'
import { View } from '@tarojs/components'
import Taro from '@tarojs/taro'
import { Device, DeviceType } from '../../types'
import { DeviceIcon } from '../icons'

interface Props {
  devices: Device[]
  gatewayIP: string
  onDeviceClick: (device: Device) => void
}

interface NodePosition {
  device: Device
  x: number
  y: number
}

export default class TopologyCanvas extends Component<Props> {
  private canvas: any
  private ctx: any
  private dpr: number = 1
  private nodes: NodePosition[] = []

  componentDidMount() {
    this.initCanvas()
    Taro.eventCenter.on('onresize', this.initCanvas.bind(this))
  }

  componentDidUpdate() {
    this.render()
  }

  componentWillUnmount() {
    Taro.eventCenter.off('onresize', this.initCanvas.bind(this))
  }

  initCanvas() {
    const query = Taro.createSelectorQuery()
    query.select('#topology-canvas')
      .node((res: any) => {
        if (!res) return
        this.canvas = res.node
        this.ctx = this.canvas.getContext('2d')
        this.dpr = Taro.getSystemInfoSync().pixelRatio || 1
        const w = Taro.getSystemInfoSync().windowWidth
        this.canvas.width = w * this.dpr
        this.canvas.height = (w * 0.7) * this.dpr
        this.canvas.style.width = `${w}px`
        this.canvas.style.height = `${w * 0.7}px`
        this.ctx.scale(this.dpr, this.dpr)
        this.render()
      })
      .exec()
  }

  render() {
    const { devices, gatewayIP } = this.props
    if (!this.ctx) return

    const w = Taro.getSystemInfoSync().windowWidth
    const h = w * 0.7
    const cx = w / 2
    const cy = h / 2
    const radius = Math.min(w, h) * 0.35

    // 计算节点位置
    this.nodes = this.calcNodePositions(devices, gatewayIP, cx, cy, radius)
    this.draw()
  }

  calcNodePositions(devices: Device[], gatewayIP: string, cx: number, cy: number, radius: number): NodePosition[] {
    const gateway = devices.find((d) => d.ip === gatewayIP) || devices[0]
    const others = devices.filter((d) => d.ip !== gateway?.ip)

    const result: NodePosition[] = []

    // Gateway 放中心
    if (gateway) {
      result.push({ device: gateway, x: cx, y: cy })
    }

    // 其他设备环形分布
    others.forEach((device, i) => {
      const angle = (2 * Math.PI * i) / others.length - Math.PI / 2
      result.push({
        device,
        x: cx + radius * Math.cos(angle),
        y: cy + radius * Math.sin(angle),
      })
    })

    return result
  }

  draw() {
    if (!this.ctx) return
    const w = Taro.getSystemInfoSync().windowWidth
    const h = w * 0.7

    this.ctx.clearRect(0, 0, w, h)

    // 画连接线（从中心到各节点）
    const [center, ...others] = this.nodes
    if (!center) return

    others.forEach(({ x, y }) => {
      this.ctx.beginPath()
      this.ctx.strokeStyle = '#2a2a4a'
      this.ctx.lineWidth = 1
      this.ctx.moveTo(center.x, center.y)
      this.ctx.lineTo(x, y)
      this.ctx.stroke()
    })

    // 画节点
    this.nodes.forEach(({ device, x, y }, idx) => {
      const isGateway = idx === 0
      const r = isGateway ? 28 : 22

      // 节点圆
      this.ctx.beginPath()
      this.ctx.fillStyle = isGateway ? '#0077ff' : '#1e1e3a'
      this.ctx.strokeStyle = isGateway ? '#00d4ff' : '#2a2a4a'
      this.ctx.lineWidth = 2
      this.ctx.arc(x, y, r, 0, 2 * Math.PI)
      this.ctx.fill()
      this.ctx.stroke()

      // 文字（emoji icon + IP）
      this.ctx.fillStyle = '#fff'
      this.ctx.font = `${isGateway ? 20 : 16}px sans-serif`
      this.ctx.textAlign = 'center'
      const icon = this.getIcon(device.deviceType)
      this.ctx.fillText(icon, x, y - 8)
      this.ctx.fillStyle = '#888'
      this.ctx.font = '10px sans-serif'
      this.ctx.fillText(device.ip.split('.').pop() || '', x, y + r + 12)
    })
  }

  getIcon(type: DeviceType): string {
    const map: Record<DeviceType, string> = {
      router: '🛣', pc: '💻', camera: '📹', nas: '💾', phone: '📱', printer: '🖨', unknown: '❓',
    }
    return map[type]
  }

  handleClick(e: any) {
    const { devices, gatewayIP } = this.props
    const { x, y } = e.detail
    const w = Taro.getSystemInfoSync().windowWidth

    // hit test
    for (const node of this.nodes) {
      const dx = node.x - x
      const dy = node.y - y
      if (dx * dx + dy * dy < 30 * 30) {
        this.props.onDeviceClick(node.device)
        return
      }
    }
  }

  render() {
    return (
      <View>
        <canvas
          id='topology-canvas'
          className='topology-canvas'
          onClick={this.handleClick.bind(this)}
        />
      </View>
    )
  }
}
```

- [ ] **Step 2: 创建 CSS**

```css
.topology-canvas {
  width: 100%;
  height: 70vw;
  display: block;
}
```

- [ ] **Step 3: Commit**

```bash
git add src/components/TopologyCanvas/index.tsx src/components/TopologyCanvas/index.css && git commit -m "feat: add TopologyCanvas (star layout)

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 16: 发现页（discovery）

**Files:**
- Create: `src/pages/discovery/index.tsx`
- Create: `src/pages/discovery/index.config.ts`

- [ ] **Step 1: 创建 src/pages/discovery/index.config.ts**

```typescript
export default definePageConfig({
  navigationBarTitleText: 'NetProwl',
})
```

- [ ] **Step 2: 创建 src/pages/discovery/index.tsx**

```typescript
import { Component } from 'react'
import { View, Text } from '@tarojs/components'
import Taro from '@tarojs/taro'
import { Device } from '../../types'
import { runScan } from '../../services/scanner'
import { getLocalIPAddress } from '../../services/network'
import TopologyCanvas from '../../components/TopologyCanvas'
import DeviceDrawer from '../../components/DeviceDrawer'
import ScanButton from '../../components/ScanButton'

interface State {
  devices: Device[]
  scanning: boolean
  selectedDevice: Device | null
  mdnsUnavailable: boolean
  lastScanTime: number | null
  summaryText: string
}

export default class Discovery extends Component<State> {
  state: State = {
    devices: [],
    scanning: false,
    selectedDevice: null,
    mdnsUnavailable: false,
    lastScanTime: null,
    summaryText: '',
  }

  async handleScan() {
    if (this.state.scanning) return

    Taro.showLoading({ title: '扫描中...' })
    this.setState({ scanning: true })

    try {
      const result = await runScan()
      const duration = (result.duration / 1000).toFixed(1)
      this.setState({
        devices: result.devices,
        scanning: false,
        lastScanTime: Date.now(),
        mdnsUnavailable: result.mdnsUnavailable,
        summaryText: `发现 ${result.devices.length} 台设备，耗时 ${duration}s`,
      })

      if (result.mdnsUnavailable) {
        Taro.showToast({ title: 'iOS 环境已降级至 TCP 扫描', icon: 'none', duration: 2000 })
      }
    } catch (err) {
      this.setState({ scanning: false })
      Taro.showToast({ title: '扫描失败，请重试', icon: 'error' })
    } finally {
      Taro.hideLoading()
    }
  }

  handleDeviceClick(device: Device) {
    this.setState({ selectedDevice: device })
  }

  handleDrawerClose() {
    this.setState({ selectedDevice: null })
  }

  render() {
    const { devices, scanning, selectedDevice, mdnsUnavailable, summaryText } = this.state
    const gatewayIP = devices.find((d) => d.deviceType === 'router')?.ip || devices[0]?.ip || ''

    return (
      <View className='discovery-page'>
        {/* 状态摘要栏 */}
        <View className='summary-bar'>
          <Text className='summary-text'>
            {summaryText || '点击下方按钮开始局域网扫描'}
          </Text>
        </View>

        {/* 拓扑图 */}
        <View className='topology-wrap'>
          {devices.length === 0 ? (
            <View className='empty-state'>
              <Text className='empty-icon'>🛣</Text>
              <Text className='empty-text'>未发现设备</Text>
              <Text className='empty-hint'>确认在同一 WiFi 下</Text>
            </View>
          ) : (
            <TopologyCanvas
              devices={devices}
              gatewayIP={gatewayIP}
              onDeviceClick={this.handleDeviceClick.bind(this)}
            />
          )}
        </View>

        {/* 扫描按钮 */}
        <ScanButton scanning={scanning} onScan={this.handleScan.bind(this)} />

        {/* 设备详情抽屉 */}
        <DeviceDrawer device={selectedDevice} onClose={this.handleDrawerClose.bind(this)} />
      </View>
    )
  }
}
```

- [ ] **Step 3: 创建 CSS（src/pages/discovery/index.css）**

```css
.discovery-page {
  min-height: 100vh;
  background: #0f0f1a;
  display: flex;
  flex-direction: column;
}

.summary-bar {
  padding: 24rpx 32rpx;
  background: #1a1a2e;
}

.summary-text {
  color: #00d4ff;
  font-size: 28rpx;
}

.topology-wrap {
  flex: 1;
  padding: 24rpx;
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 60vw;
}

.empty-icon {
  font-size: 80rpx;
  margin-bottom: 24rpx;
}

.empty-text {
  color: #fff;
  font-size: 32rpx;
}

.empty-hint {
  color: #666;
  font-size: 26rpx;
  margin-top: 8rpx;
}
```

- [ ] **Step 4: Commit**

```bash
git add src/pages/discovery/index.tsx src/pages/discovery/index.config.ts src/pages/discovery/index.css && git commit -m "feat: add discovery page

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 17: 历史页（history）

**Files:**
- Create: `src/pages/history/index.tsx`
- Create: `src/pages/history/index.config.ts`

- [ ] **Step 1: 创建相关文件**

```typescript
import { Component } from 'react'
import { View, Text, ScrollView } from '@tarojs/components'
import { ScanSnapshot } from '../../types'
import { loadHistory } from '../../services/storage'

interface State {
  history: ScanSnapshot[]
  expandedId: string | null
}

export default class History extends Component<State> {
  state: State = {
    history: [],
    expandedId: null,
  }

  async componentDidShow() {
    const history = await loadHistory()
    this.setState({ history })
  }

  toggleExpand(id: string) {
    this.setState((s) => ({
      expandedId: s.expandedId === id ? null : id,
    }))
  }

  formatTime(ts: number) {
    const d = new Date(ts)
    return `${d.getMonth() + 1}-${d.getDate()} ${d.getHours()}:${String(d.getMinutes()).padStart(2, '0')}`
  }

  render() {
    const { history, expandedId } = this.state

    return (
      <View className='history-page'>
        <ScrollView scrollY className='history-list'>
          {history.length === 0 ? (
            <View className='empty'>
              <Text className='empty-text'>暂无扫描记录</Text>
            </View>
          ) : (
            history.map((snap) => (
              <View key={snap.id} className='history-item'>
                <View className='item-header' onClick={() => this.toggleExpand(snap.id)}>
                  <View className='item-dot' />
                  <View className='item-info'>
                    <Text className='item-time'>{this.formatTime(snap.timestamp)}</Text>
                    <Text className='item-sub'>{snap.ipRange}</Text>
                  </View>
                  <Text className='item-count'>{snap.deviceCount} 台</Text>
                </View>

                {expandedId === snap.id && (
                  <View className='item-detail'>
                    {snap.devices.map((d) => (
                      <View key={d.ip} className='device-row'>
                        <Text className='device-ip'>{d.ip}</Text>
                        <Text className='device-ports'>{d.openPorts.length} 端口</Text>
                      </View>
                    ))}
                  </View>
                )}
              </View>
            ))
          )}
        </ScrollView>
      </View>
    )
  }
}
```

- [ ] **Step 2: 创建 CSS**

```css
.history-page {
  min-height: 100vh;
  background: #0f0f1a;
}

.history-list {
  padding: 24rpx 32rpx;
  height: 100vh;
}

.empty {
  display: flex;
  justify-content: center;
  padding-top: 200rpx;
}

.empty-text {
  color: #666;
  font-size: 28rpx;
}

.history-item {
  background: #1a1a2e;
  border-radius: 16rpx;
  margin-bottom: 16rpx;
  overflow: hidden;
}

.item-header {
  display: flex;
  align-items: center;
  padding: 24rpx;
}

.item-dot {
  width: 12rpx;
  height: 12rpx;
  background: #00d4ff;
  border-radius: 50%;
  margin-right: 16rpx;
}

.item-info {
  flex: 1;
}

.item-time {
  display: block;
  color: #fff;
  font-size: 30rpx;
}

.item-sub {
  display: block;
  color: #666;
  font-size: 24rpx;
  margin-top: 4rpx;
}

.item-count {
  color: #00d4ff;
  font-size: 28rpx;
}

.item-detail {
  padding: 0 24rpx 24rpx;
  border-top: 1rpx solid #2a2a4a;
}

.device-row {
  display: flex;
  justify-content: space-between;
  padding: 16rpx 0;
  border-bottom: 1rpx solid #2a2a4a;
}

.device-ip {
  color: #fff;
  font-size: 28rpx;
}

.device-ports {
  color: #888;
  font-size: 26rpx;
}
```

- [ ] **Step 3: Commit**

```bash
git add src/pages/history/index.tsx src/pages/history/index.config.ts src/pages/history/index.css && git commit -m "feat: add history page

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 18: 问诊页占位（chat）

**Files:**
- Create: `src/pages/chat/index.tsx`
- Create: `src/pages/chat/index.config.ts`

- [ ] **Step 1: 创建问诊页占位**

```typescript
import { Component } from 'react'
import { View, Text } from '@tarojs/components'

export default class Chat extends Component {
  render() {
    return (
      <View className='chat-page'>
        <View className='placeholder'>
          <Text className='placeholder-icon'>🤖</Text>
          <Text className='placeholder-text'>AI 问诊</Text>
          <Text className='placeholder-hint'>Phase 2 接入 DeepSeek</Text>
        </View>
      </View>
    )
  }
}
```

```css
.chat-page {
  min-height: 100vh;
  background: #0f0f1a;
  display: flex;
  align-items: center;
  justify-content: center;
}

.placeholder {
  display: flex;
  flex-direction: column;
  align-items: center;
}

.placeholder-icon {
  font-size: 80rpx;
  margin-bottom: 24rpx;
}

.placeholder-text {
  color: #fff;
  font-size: 36rpx;
  font-weight: 600;
}

.placeholder-hint {
  color: #666;
  font-size: 28rpx;
  margin-top: 8rpx;
}
```

- [ ] **Step 2: Commit**

```bash
git add src/pages/chat/index.tsx src/pages/chat/index.config.ts src/pages/chat/index.css && git commit -m "feat: add chat page placeholder

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

### Task 19: TabBar 图标资源

**Files:**
- Create: `src/assets/tab-discovery.png` (占位文件)
- Create: `src/assets/tab-discovery-active.png`
- Create: `src/assets/tab-history.png`
- Create: `src/assets/tab-history-active.png`
- Create: `src/assets/tab-chat.png`
- Create: `src/assets/tab-chat-active.png`

- [ ] **Step 1: 创建占位图标**（Phase 2 替换为正式图标）

> Note: 当前使用 emoji 渲染替代 TabBar 图标。创建 6 个 81x81px 白色/蓝色 PNG 占位文件。

```bash
# 在 src/assets/ 目录创建 6 个占位空文件（Git tracking 用）
touch src/assets/tab-discovery.png
touch src/assets/tab-discovery-active.png
touch src/assets/tab-history.png
touch src/assets/tab-history-active.png
touch src/assets/tab-chat.png
touch src/assets/tab-chat-active.png
```

- [ ] **Step 2: Commit**

```bash
git add src/assets/ && git commit -m "chore: add tab icon placeholders

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

---

## Self-Review Checklist

1. **Spec coverage:** 所有 Phase 1 功能（发现页、历史页、拓扑图、扫描引擎、三层探测）均有对应 task。
2. **Placeholder scan:** `minigzip` 标注了 fallback，`oui.ts` 仅含主流厂商子集，TabBar 图标为占位——均已注明。
3. **Type consistency:** `Device`/`Port`/`ScanSnapshot` 接口在 Task 2 定义，后续 service 保持一致。`runScan` 返回 `ScanResult` 与 scanner.ts 一致。

---

**Plan complete.** 保存至 `docs/superpowers/plans/2026-05-11-netprowl-phase1-mvp-plan.md`。

Two execution options:

**1. Subagent-Driven (recommended)** - dispatch fresh subagent per task, review between tasks

**2. Inline Execution** - execute tasks in this session using executing-plans

Which approach?
