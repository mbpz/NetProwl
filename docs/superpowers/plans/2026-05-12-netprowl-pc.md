# NetProwl PC Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tauri PC 客户端，调用 Go core 扫描局域网设备，Canvas 绘制拓扑图

**Architecture:** Tauri 2.x + React + TypeScript。Rust 后端调用 Go core（WASM 编译）。React 前端负责 UI 和 Canvas 拓扑图。

**Tech Stack:** Tauri 2.x, React 18, TypeScript, canvas API

---

## File Structure

```
netprowl-pc/
├── src-tauri/           # Rust 后端
│   ├── Cargo.toml
│   ├── tauri.conf.json
│   ├── build.rs
│   └── src/
│       ├── main.rs       # 入口
│       ├── commands.rs   # Tauri commands (IPC)
│       └── core.rs      # 调用 Go core (WASM)
├── src/                  # React 前端
│   ├── App.tsx
│   ├── main.tsx
│   ├── pages/
│   │   ├── Home.tsx     # 首页，扫描入口
│   │   ├── Devices.tsx  # 设备列表
│   │   └── Topology.tsx # 拓扑图
│   ├── components/
│   │   ├── DeviceCard.tsx
│   │   ├── TopoCanvas.tsx
│   │   └── ScanButton.tsx
│   ├── hooks/
│   │   └── useScanner.ts
│   └── stores/
│       └── deviceStore.ts
├── package.json
└── tsconfig.json
```

---

## Task 1: 项目初始化

**Files:**
- Create: `netprowl-pc/package.json`
- Create: `netprowl-pc/tsconfig.json`
- Create: `netprowl-pc/index.html`
- Create: `netprowl-pc/src/main.tsx`
- Create: `netprowl-pc/src/App.tsx`
- Create: `netprowl-pc/src-tauri/Cargo.toml`
- Create: `netprowl-pc/src-tauri/tauri.conf.json`
- Create: `netprowl-pc/src-tauri/build.rs`
- Create: `netprowl-pc/src-tauri/src/main.rs`

- [ ] **Step 1: 创建 package.json**

```json
{
  "name": "netprowl-pc",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "tauri": "tauri"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "@tauri-apps/api": "^2.0.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.0",
    "@types/react-dom": "^18.2.0",
    "@tauri-apps/cli": "^2.0.0",
    "typescript": "^5.0.0",
    "vite": "^5.0.0",
    "@vitejs/plugin-react": "^4.0.0"
  }
}
```

- [ ] **Step 2: 创建 tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["ES2020", "DOM", "DOM.Iterable"],
    "module": "ESNext",
    "skipLibCheck": true,
    "moduleResolution": "bundler",
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx",
    "strict": true
  },
  "include": ["src"]
}
```

- [ ] **Step 3: 创建 index.html**

```html
<!DOCTYPE html>
<html lang="zh-CN">
  <head>
    <meta charset="UTF-8" />
    <title>NetProwl</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 4: 创建 src/main.tsx**

```tsx
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
```

- [ ] **Step 5: 创建 src/App.tsx**

```tsx
import { useState } from 'react'

function App() {
  const [scanState, setScanState] = useState<'idle' | 'scanning' | 'done'>('idle')

  return (
    <div className="app">
      <header>
        <h1>NetProwl</h1>
      </header>
      <main>
        <button onClick={() => setScanState('scanning')}>
          {scanState === 'scanning' ? '扫描中...' : '开始扫描'}
        </button>
      </main>
    </div>
  )
}

export default App
```

- [ ] **Step 6: 创建 src-tauri/Cargo.toml**

```toml
[package]
name = "netprowl-pc"
version = "0.1.0"

[build-dependencies]
tauri-build = { version = "2", features = [] }

[dependencies]
tauri = { version = "2", features = [] }
tauri-plugin-shell = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"

[profile.release]
panic = "abort"
codegen-units = 1
lto = true
opt-level = "s"
strip = true
```

- [ ] **Step 7: 创建 src-tauri/tauri.conf.json**

```json
{
  "$schema": "https://schema.tauri.app/config/2",
  "productName": "NetProwl",
  "version": "0.1.0",
  "build": {
    "beforeDevCommand": "npm run dev",
    "devUrl": "http://localhost:5173",
    "beforeBuildCommand": "npm run build",
    "frontendDist": "../dist"
  },
  "app": {
    "withGlobalTauri": true
  }
}
```

- [ ] **Step 8: 创建 src-tauri/build.rs**

```rust
fn main() {
    tauri_build::build()
}
```

- [ ] **Step 9: 创建 src-tauri/src/main.rs**

```rust
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

- [ ] **Step 10: Commit**

```bash
cd netprowl-pc && git init && git add -A && git commit -m "feat(pc): init Tauri project structure"
```

---

## Task 2: Tauri Commands - 调用 Go Core

**Files:**
- Create: `netprowl-pc/src-tauri/src/commands.rs`
- Modify: `netprowl-pc/src-tauri/src/main.rs`

- [ ] **Step 1: 创建 src-tauri/src/commands.rs**

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Device {
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub device_type: String,
    pub os: String,
    pub open_ports: Vec<Port>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Port {
    pub port: u16,
    pub service: String,
    pub state: String,
}

#[tauri::command]
pub fn scan_network() -> Result<Vec<Device>, String> {
    // TODO: 调用 Go core WASM
    // 暂时返回空列表，后续集成
    Ok(vec![])
}

#[tauri::command]
pub fn get_local_ip() -> Result<String, String> {
    // TODO: 获取本机 IP
    Ok("192.168.1.1".to_string())
}
```

- [ ] **Step 2: 修改 main.rs 引入 commands**

```rust
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            commands::scan_network,
            commands::get_local_ip,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
```

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "feat(pc): add Tauri commands for network scanning"
```

---

## Task 3: React 前端 - 设备状态管理

**Files:**
- Create: `netprowl-pc/src/stores/deviceStore.ts`
- Create: `netprowl-pc/src/hooks/useScanner.ts`

- [ ] **Step 1: 创建 src/stores/deviceStore.ts**

```typescript
import { create } from 'zustand'

interface Device {
  ip: string
  mac?: string
  hostname?: string
  vendor?: string
  deviceType: string
  os: string
  openPorts: Array<{ port: number; service: string; state: string }>
}

interface DeviceStore {
  devices: Device[]
  scanning: boolean
  setDevices: (devices: Device[]) => void
  setScanning: (scanning: boolean) => void
}

export const useDeviceStore = create<DeviceStore>((set) => ({
  devices: [],
  scanning: false,
  setDevices: (devices) => set({ devices }),
  setScanning: (scanning) => set({ scanning }),
}))
```

- [ ] **Step 2: 创建 src/hooks/useScanner.ts**

```typescript
import { useCallback } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { useDeviceStore } from '../stores/deviceStore'

export function useScanner() {
  const { setDevices, setScanning, devices } = useDeviceStore()

  const startScan = useCallback(async () => {
    setScanning(true)
    try {
      const result = await invoke<Device[]>('scan_network')
      setDevices(result)
    } catch (error) {
      console.error('Scan failed:', error)
    } finally {
      setScanning(false)
    }
  }, [setDevices, setScanning])

  return { startScan, devices, scanning: useDeviceStore((s) => s.scanning) }
}
```

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "feat(pc): add device store and scanner hook"
```

---

## Task 4: React 前端 - 页面布局

**Files:**
- Create: `netprowl-pc/src/pages/Home.tsx`
- Create: `netprowl-pc/src/pages/Devices.tsx`
- Create: `netprowl-pc/src/pages/Topology.tsx`
- Modify: `netprowl-pc/src/App.tsx`

- [ ] **Step 1: 创建 src/pages/Home.tsx**

```tsx
import { useScanner } from '../hooks/useScanner'

export function Home() {
  const { startScan, scanning } = useScanner()

  return (
    <div className="home">
      <h2>网络扫描</h2>
      <button onClick={startScan} disabled={scanning}>
        {scanning ? '扫描中...' : '开始扫描'}
      </button>
    </div>
  )
}
```

- [ ] **Step 2: 创建 src/pages/Devices.tsx**

```tsx
import { useDeviceStore } from '../stores/deviceStore'
import { DeviceCard } from '../components/DeviceCard'

export function Devices() {
  const devices = useDeviceStore((s) => s.devices)

  return (
    <div className="devices">
      <h2>发现设备 ({devices.length})</h2>
      <div className="device-list">
        {devices.map((device) => (
          <DeviceCard key={device.ip} device={device} />
        ))}
      </div>
    </div>
  )
}
```

- [ ] **Step 3: 创建 src/pages/Topology.tsx**

```tsx
import { TopoCanvas } from '../components/TopoCanvas'
import { useDeviceStore } from '../stores/deviceStore'

export function Topology() {
  const devices = useDeviceStore((s) => s.devices)

  return (
    <div className="topology">
      <h2>网络拓扑</h2>
      <TopoCanvas devices={devices} width={800} height={600} />
    </div>
  )
}
```

- [ ] **Step 4: 修改 App.tsx 路由**

```tsx
import { useState } from 'react'
import { Home } from './pages/Home'
import { Devices } from './pages/Devices'
import { Topology } from './pages/Topology'

type Tab = 'home' | 'devices' | 'topology'

function App() {
  const [tab, setTab] = useState<Tab>('home')

  return (
    <div className="app">
      <nav>
        <button onClick={() => setTab('home')}>首页</button>
        <button onClick={() => setTab('devices')}>设备</button>
        <button onClick={() => setTab('topology')}>拓扑</button>
      </nav>
      <main>
        {tab === 'home' && <Home />}
        {tab === 'devices' && <Devices />}
        {tab === 'topology' && <Topology />}
      </main>
    </div>
  )
}

export default App
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(pc): add page components and routing"
```

---

## Task 5: React 前端 - DeviceCard 组件

**Files:**
- Create: `netprowl-pc/src/components/DeviceCard.tsx`

- [ ] **Step 1: 创建 src/components/DeviceCard.tsx**

```tsx
interface Device {
  ip: string
  mac?: string
  hostname?: string
  vendor?: string
  deviceType: string
  os: string
  openPorts: Array<{ port: number; service: string; state: string }>
}

interface DeviceCardProps {
  device: Device
}

export function DeviceCard({ device }: DeviceCardProps) {
  return (
    <div className="device-card">
      <div className="device-header">
        <span className="device-ip">{device.ip}</span>
        <span className="device-vendor">{device.vendor || 'Unknown'}</span>
      </div>
      <div className="device-body">
        {device.hostname && <div>Hostname: {device.hostname}</div>}
        {device.mac && <div>MAC: {device.mac}</div>}
        <div>Type: {device.deviceType}</div>
        <div>OS: {device.os}</div>
        {device.openPorts.length > 0 && (
          <div className="ports">
            <span>开放端口: </span>
            {device.openPorts.map((p) => (
              <span key={p.port} className="port-tag">
                {p.port}/{p.service}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
```

- [ ] **Step 2: Commit**

```bash
git add -A && git commit -m "feat(pc): add DeviceCard component"
```

---

## Task 6: React 前端 - TopoCanvas 拓扑图

**Files:**
- Create: `netprowl-pc/src/components/TopoCanvas.tsx`

- [ ] **Step 1: 创建 src/components/TopoCanvas.tsx**

```tsx
import { useEffect, useRef } from 'react'

interface Device {
  ip: string
  deviceType: string
}

interface TopoCanvasProps {
  devices: Device[]
  width: number
  height: number
}

const DEVICE_ICONS: Record<string, string> = {
  router: '🖧',
  pc: '💻',
  camera: '📷',
  nas: '💾',
  phone: '📱',
  printer: '🖨️',
  unknown: '❓',
}

export function TopoCanvas({ devices, width, height }: TopoCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    // Clear canvas
    ctx.clearRect(0, 0, width, height)

    // Draw devices in a grid layout
    const cols = Math.ceil(Math.sqrt(devices.length))
    const cellWidth = width / cols
    const cellHeight = height / Math.ceil(devices.length / cols)

    devices.forEach((device, index) => {
      const col = index % cols
      const row = Math.floor(index / cols)
      const x = col * cellWidth + cellWidth / 2
      const y = row * cellHeight + cellHeight / 2

      // Draw device icon
      const icon = DEVICE_ICONS[device.deviceType] || DEVICE_ICONS.unknown
      ctx.font = '24px sans-serif'
      ctx.textAlign = 'center'
      ctx.textBaseline = 'middle'
      ctx.fillText(icon, x, y - 10)

      // Draw IP label
      ctx.font = '12px sans-serif'
      ctx.fillText(device.ip, x, y + 15)
    })

    // Draw lines between devices (simplified - connect to first device as "gateway")
    if (devices.length > 1) {
      ctx.strokeStyle = '#ccc'
      ctx.beginPath()
      ctx.moveTo(cellWidth / 2, cellHeight / 2)
      ctx.lineTo(cellWidth / 2, cellHeight / 2)
      // Connect first device to others as "discovered from"
      for (let i = 1; i < devices.length; i++) {
        const col = i % cols
        const row = Math.floor(i / cols)
        const x = col * cellWidth + cellWidth / 2
        const y = row * cellHeight + cellHeight / 2
        ctx.moveTo(cellWidth / 2, cellHeight / 2)
        ctx.lineTo(x, y)
      }
      ctx.stroke()
    }
  }, [devices, width, height])

  return (
    <canvas
      ref={canvasRef}
      width={width}
      height={height}
      style={{ border: '1px solid #ccc' }}
    />
  )
}
```

- [ ] **Step 2: Commit**

```bash
git add -A && git commit -m "feat(pc): add TopoCanvas topology visualization"
```

---

## Task 7: 基本样式

**Files:**
- Create: `netprowl-pc/src/index.css`
- Modify: `netprowl-pc/src/App.tsx`

- [ ] **Step 1: 创建 src/index.css**

```css
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: #f5f5f5;
}

.app {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

nav {
  display: flex;
  gap: 10px;
  margin-bottom: 20px;
  padding: 10px;
  background: white;
  border-radius: 8px;
}

nav button {
  padding: 8px 16px;
  border: none;
  background: #e0e0e0;
  border-radius: 4px;
  cursor: pointer;
}

nav button.active {
  background: #007bff;
  color: white;
}

button {
  padding: 10px 20px;
  background: #007bff;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
}

button:disabled {
  background: #ccc;
}

.device-list {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 16px;
}

.device-card {
  background: white;
  border-radius: 8px;
  padding: 16px;
  box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.device-header {
  display: flex;
  justify-content: space-between;
  margin-bottom: 12px;
}

.device-ip {
  font-weight: bold;
  font-size: 16px;
}

.port-tag {
  display: inline-block;
  padding: 2px 8px;
  margin: 2px;
  background: #e0e0e0;
  border-radius: 4px;
  font-size: 12px;
}
```

- [ ] **Step 2: 修改 App.tsx 引入样式**

```tsx
import './index.css'
// ... rest of App.tsx
```

- [ ] **Step 3: Commit**

```bash
git add -A && git commit -m "feat(pc): add basic styles"
```

---

## Spec Coverage Check

| 规格书功能 | 实现位置 |
|-----------|---------|
| P1-1 · 完整端口扫描 | Task 2 (commands.rs) - TODO 集成 Go core |
| P1-2 · mDNS / UDP SSDP | Task 2 (commands.rs) - TODO 集成 Go core |
| P1-3 · 设备拓扑图 | Task 6 (TopoCanvas.tsx) |
| P1-4 · Banner 抓取 | Task 2 (commands.rs) - TODO 集成 Go core |
| P1-5 · 服务指纹识别 | Task 2 (commands.rs) - TODO 集成 Go core |
| P1-6 · 扫描历史 | 未实现（后续 Task）|
| P1-7 · 报告导出 | 未实现（后续 Task）|
| P1-8 · TLS 审计 | 未实现（后续 Task）|

**Gap:** Task 2 中的 commands.rs 是 stub，需要后续集成 Go core 编译的 WASM 或共享库。

---

## Placeholder Scan

- Task 2 `scan_network()` 返回空列表 - 正确标记为 TODO
- Task 2 `get_local_ip()` 返回硬编码 - 正确标记为 TODO

All steps have actual code. No TBD/TODO beyond stub markers.

---

**Plan complete.** Saved to `docs/superpowers/plans/2026-05-12-netprowl-pc.md`

**Two execution options:**

1. **Subagent-Driven (recommended)** - dispatch fresh subagent per task, review between tasks
2. **Inline Execution** - execute tasks in this session using executing-plans

Which approach?