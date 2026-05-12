# NetProwl 工具集成设计

> **版本**：v1.0
> **日期**：2026-05-12
> **状态**：待评审

---

## 1. 目标

PC 版（Tauri）通过 Rust 层调用外部安全工具，构建"端口发现 → 服务识别 → 漏洞检测"流水线。

Phase 1 核心能力不变（Rust 自研扫描），此为**扩展层**，定位类似 hackingtool 的工具聚合。

---

## 2. 集成工具

| 工具 | 用途 | JSON 输出 |
|------|------|-----------|
| masscan | 快速端口发现 | 无，需解析 stdout |
| nmap | banner 抓取/服务识别 | `-oA json` |
| rustscan | 快速端口 + banner | JSON |
| nuclei | 漏洞检测/POC | JSON (`-json`) |
| ffuf | WEB fuzz | JSON (`-of json`) |
| feroxbuster | 目录/文件 fuzz | JSON (`-j`) |

---

## 3. 架构

```
┌──────────────────────────────┐
│  Frontend (React)             │
│  - UnifiedResultsPanel       │
│  - PipelineStatusBar         │
│  - ToolParamForm (可选)       │
└──────────────┬───────────────┘
               │ Tauri invoke
┌──────────────▼───────────────┐
│  src-tauri/src/commands/     │
│  - scan_commands.rs          │
│    - masscan_scan()         │
│    - nmap_scan()            │
│    - rustscan_scan()        │
│    - nuclei_scan()          │
│    - ffuf_scan()            │
│    - feroxbuster_scan()    │
└──────────────┬───────────────┘
               │ std::process::Command
┌──────────────▼───────────────┐
│  External Binaries           │
│  nmap / masscan / nuclei /  │
│  ffuf / feroxbuster / rustscan │
└──────────────────────────────┘
```

---

## 4. 数据流（流水线）

```
用户输入目标 IP/域名
    │
    ▼
masscan 快速扫描（默认 1-10000 端口）
    │ 可选：切换 nmap / rustscan
    ▼
nmap -sT -sV -oA json（补全 banner / 服务识别）
    │ 自动跳过未检测到服务的端口
    ▼
nuclei -json（漏洞检测，默认自动触发，可取消）
ffuf -of json（WEB fuzz，nuclei 完成后跑）
feroxbuster -j（目录 fuzz，与 nuclei 并行或串行）
    │
    ▼
结果统一写入 UnifiedResultsStore
    │
    ▼
统一结果面板展示（tag 区分类型：port/service/vuln/fuzz）
```

---

## 5. 状态机

```
IDLE → SCANNING → DETECTING → FUZZING → DONE
         │           │           │
         ▼           ▼           ▼
      masscan    nuclei       ffuf
      nmap       ffuf      feroxbuster
      rustscan   feroxbuster
```

用户可随时取消。

---

## 6. 工具检测 + 安装

```rust
fn check_tool(name: &str) -> bool {
    which(name).is_some()
}

fn install_missing(tools: &[&str]) -> Result<()> {
    // 调用 install.sh 或提示用户手动安装
}
```

启动时检测，状态显示：
```
✔ masscan installed   ✔ nmap installed   ✘ nuclei not found [Install]
```

---

## 7. 结果数据模型

```rust
enum ResultItem {
    Port { ip: String, port: u16, state: String },
    Service { ip: String, port: u16, service: String, banner: String },
    Vulnerability { ip: String, port: u16, template: String, severity: String, matched: String },
    FuzzResult { url: String, method: String, status: u16, length: usize },
}
```

统一面板用 tag + 颜色区分类型。

---

## 8. 前端组件

| 组件 | 职责 |
|------|------|
| PipelinePanel | 流水线控制（开始/取消/切换工具）|
| UnifiedResultsPanel | 结果列表，tag 筛选 |
| ToolStatusBar | 工具安装状态 + 版本 |
| QuickScanButton | 一键默认扫描 |

---

## 9. 验收标准

- [ ] masscan/nmap/rustscan 任选其一可正常扫描并返回端口
- [ ] nuclei 可对发现端口自动触发并返回漏洞结果
- [ ] ffuf/feroxbuster 可并行或串行跑
- [ ] 工具未安装时提示清晰，可一键跳转 install.sh
- [ ] 流水线可取消
- [ ] 结果统一展示，tag 筛选正常

---

*规格书版本：v1.0 · NetProwl 工具集成*
