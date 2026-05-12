# Rust Core 迁移设计

> **版本**：v1.0
> **更新**：2026-05-12
> **状态**：已批准

---

## 1. 背景

规格书 v1.3 确定统一语言为 Rust，替换现有 Go Core：
- Go → Rust（core/ 所有包）
- 功能不变（F1/F2 特性保持）
- 删除 Go 代码（`go.mod`, `core/` 下所有 .go 文件）

---

## 2. 架构

```
netprowl-mini/                    小程序前端（Taro + React）
    └── src/services/
          ├── scanner.ts           # 调用 WASM glue
          ├── ssdp.ts              # SSDP 调用
          └── ...

core/                             Rust crate（迁移目标）
    ├── Cargo.toml
    ├── src/
    │   ├── lib.rs                # 入口，wasm_bindgen exports
    │   ├── types.rs             # Device, Port, ScanResult 等
    │   ├── scanner/
    │   │   ├── mod.rs
    │   │   ├── mdns.rs
    │   │   ├── ssdp.rs
    │   │   ├── tcp.rs
    │   │   ├── banner.rs
    │   │   └── registry.rs
    │   └── util/
    │       ├── mod.rs
    │       ├── ip.rs
    │       └── oui.rs
    └── build/                    # wasm-pack 输出
          ├── netprowl_core.js    # JS glue
          ├── netprowl_core_bg.wasm
          └── netprowl_core.d.ts  # TypeScript 类型

netprowl-pc/                      PC 客户端（Tauri + React）
    └── src-tauri/
          └── scanner/           # 直接引用 core/ 作为 Rust 依赖
```

---

## 3. 导出 API

独立函数导出，JS 层组合流程：

```rust
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub async fn discover_ssdp() -> JsValue

#[wasm_bindgen]
pub async fn scan_tcp(ip: &str, ports: Vec<u16>) -> JsValue

#[wasm_bindgen]
pub async fn grab_banner(ip: &str, port: u16, cfg: JsValue) -> JsValue

#[wasm_bindgen]
pub async fn run_full_scan(subnet: &str) -> JsValue

#[wasm_bindgen]
pub async fn grab_http_banner(ip: &str, port: u16, deep_scan: bool) -> JsValue

#[wasm_bindgen]
pub async fn grab_rtsp_banner(ip: &str, port: u16, get_sdp: bool) -> JsValue
```

Taro 调用示例：
```typescript
import init, { discover_ssdp, scan_tcp, grab_banner } from '@/wasm_pkg/netprowl_core'

await init()
const ssdpDevices = await discover_ssdp()
const openPorts = await scan_tcp('192.168.1.1', [80, 443, 8080])
const banner = await grab_banner('192.168.1.1', 80, JSON.stringify({timeout_ms: 3000}))
```

---

## 4. 类型定义（types.rs）

```rust
pub struct Device {
    pub id: String,
    pub ip: String,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub vendor: Option<String>,
    pub device_type: String,  // router/pc/camera/nas/phone/printer/unknown
    pub os: String,           // linux/windows/network/unknown
    pub open_ports: Vec<Port>,
    pub discovered_at: u64,   // unix timestamp ms
    pub sources: Vec<String>,  // mdns/ssdp/tcp/banner
}

pub struct Port {
    pub port: u16,
    pub service: String,
    pub state: String,         // open/filtered/closed
    pub banner: Option<String>,
}

pub struct ScanResult {
    pub devices: Vec<Device>,
    pub duration_ms: u64,
}

pub struct BannerConfig {
    pub timeout_ms: u32,
    pub include_deep_scan: bool,
    pub include_rtspsdp: bool,
}

pub struct RTSPStreamInfo {
    pub server: String,
    pub stream_url: String,
    pub camera_brand: String,  // Hikvision/Dahua/Uniview/Ezviz/Generic RTSP
    pub auth: String,           // none/basic/digest
}
```

---

## 5. Rust 技术栈

| 组件 | 技术 |
|------|------|
| 语言 | Rust 1.75+ |
| 异步 | tokio + async/await |
| WASM | wasm-bindgen + wasm-pack |
| WASM target | `wasm-pack build --target web` |
| HTTP client | reqwest（banner 抓取）|
| 网络 | tokio::net（TCP/UDP）|
| 多播 | socket2（UDP multicast for SSDP/mDNS）|

---

## 6. 运行时模型

全局 static runtime，避免重复创建开销：

```rust
use once_cell::sync::Lazy;
use tokio::runtime::Runtime;

static RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
});
```

---

## 7. 各模块设计

### 7.1 scanner/ssdp.rs

```rust
pub async fn discover_ssdp() -> Result<JsValue, JsValue>
```

- UDP multicast: 239.255.255.250:1900
- 发送 M-SEARCH 请求
- 解析 HTTP 200 响应，提取 LOCATION/Server/ST 等字段
- 返回 JSON 数组（ip, port, name, vendor, model）

### 7.2 scanner/mdns.rs

```rust
pub async fn discover_mdns(service_types: Vec<String>) -> Result<JsValue, JsValue>
```

- UDP multicast: 224.0.255.253:5353
- 查询指定 serviceType（`_http._tcp` 等）
- 解析响应，提取 instance name / hostname / port

### 7.3 scanner/tcp.rs

```rust
pub async fn scan_tcp(ip: &str, ports: Vec<u16>) -> Result<JsValue, JsValue>
```

- 并发扫描（tokio::spawn，每个 port 一个 task）
- timeout 控制
- 返回 open ports 列表

### 7.4 scanner/banner.rs

```rust
pub async fn grab_banner(ip: &str, port: u16, cfg: JsValue) -> Result<JsValue, JsValue>
pub async fn grab_http_banner(ip: &str, port: u16, deep_scan: bool) -> Result<JsValue, JsValue>
pub async fn grab_rtsp_banner(ip: &str, port: u16, get_sdp: bool) -> Result<JsValue, JsValue>
```

- HTTP: HEAD / + deep scan paths（/, /admin, /wp-login.php, /phpmyadmin/, /robots.txt, /owa/）
- HTTP: 解析 Server/X-Powered-By/X-Generator，提取 title，CMS 检测（WordPress/Drupal/Joomla/Nginx/Apache/Express/Django/Laravel/IIS/Tomcat）
- SSH/FTP: 读取 banner 字符串
- RTSP: OPTIONS + DESCRIBE，SDP 解析，camera brand 检测（Hikvision/Dahua/Uniview/Ezviz）

### 7.5 scanner/registry.rs

```rust
pub struct ServiceRule {
    pub ports: Vec<u16>,
    pub service: String,
    pub device_type: String,
    pub patterns: Vec<Regex>,
}
```

内置规则：http(80/8080/8443), https, ssh(22), ftp(21), hikvision-camera(554), synology-nas(5000), rtsp(554/5000), http-proxy(3128), upnp(1900)

### 7.6 util/ip.rs

```rust
pub fn infer_subnet(local_ip: &str) -> String        // "192.168.1.0/24"
pub fn expand_subnet(subnet: &str) -> Vec<String>   // ["192.168.1.1", ...]
pub fn is_private_ip(ip: &str) -> bool
pub fn guess_gateway(local_ip: &str) -> String       // base + ".1"
```

### 7.7 util/oui.rs

```rust
pub fn lookup_vendor(mac: &str) -> Option<String>
```

内置 OUI 库（约 800KB），覆盖常见厂商。MAC 格式容忍：`AA:BB:CC:DD:EE:FF` 或 `AA-BB-CC-DD-EE-FF` 或 `AABBCCDDEEFF`。

---

## 8. 迁移顺序

1. `Cargo.toml` + `src/lib.rs` + `src/types.rs`（基础结构）
2. `util/ip.rs`（最先完成，无外部依赖）
3. `util/oui.rs`（OUI 数据嵌入）
4. `scanner/ssdp.rs`（UDP multicast）
5. `scanner/mdns.rs`（mDNS 查询）
6. `scanner/tcp.rs`（TCP 端口扫描）
7. `scanner/registry.rs`（服务指纹规则）
8. `scanner/banner.rs`（Banner 抓取）
9. wasm-pack build 验证
10. 删除 Go 代码

---

## 9. 验收标准

- [ ] `wasm-pack build --target web` 成功，无 warning
- [ ] 所有 exported 函数返回正确 JsValue（JSON）
- [ ] 小程序端 `import init from '@/wasm_pkg/netprowl_core'` 能正常初始化
- [ ] SSDP 发现返回设备列表
- [ ] TCP 端口扫描返回 open ports
- [ ] HTTP Banner 抓取解析 Server/CMS/Title
- [ ] RTSP Banner 抓取返回 camera brand
- [ ] go.mod 删除，Go 文件删除
- [ ] go build ./... 在旧代码上报错（确认删除）

---

*设计版本：v1.0 · Go → Rust Core Migration*