# NetProwl 项目状态 & 竞品对比 & 演进路线

> **日期**：2026-05-14
> **版本**：v1.0
> **作者**：AI 辅助分析（基于 roadmap.md / Phase 1 规格书 / PC 端完成状态 / rs-core 源码）

---

## 1. 当前架构全景

```
┌─────────────────────────────────────────────────────────────────┐
│                        NetProwl 整体架构                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌─────────────────────────┐    ┌─────────────────────────────┐ │
│  │    微信小程序版          │    │       PC 客户端版            │ │
│  │    Taro + React          │    │    Tauri 2.x + React         │ │
│  │                          │    │                              │ │
│  │  ✅ index (入口)         │    │  ✅ Home (首页/ScanPage)     │ │
│  │  ✅ discovery (发现)     │    │  ✅ Devices (设备列表)       │ │
│  │  ✅ history (历史)       │    │  ✅ Topology (拓扑图)        │ │
│  │  ✅ chat (AI 问诊)      │    │  ✅ PipelinePanel (管道)     │ │
│  │  ✅ DeviceCard/TopoCanvas│    │  ✅ HistoryDrawer (历史)     │ │
│  │  ✅ deviceStore (Zustand)│    │  ✅ ExportPanel (导出)       │ │
│  │                          │    │  ✅ TLSResultPanel           │ │
│  │  WASM 调用 ──────────┐   │    │  ✅ ToolStatusBar            │ │
│  └──────────────────────┼───┘    │  ✅ pipelineStore/historyStore│ │
│                          │        │  Native 调用 ────────┐       │ │
│                          ▼        └──────────────────────┼───────┘ │
│  ┌──────────────────────────────────────────────────────┼───────┐ │
│  │                  Rust 核心层                           │       │ │
│  │                                                        │       │ │
│  │  core/ (netprowl-core) ◄── PC 版直接依赖               │       │ │
│  │  ├── scanner/mdns.rs    ✅ mDNS 服务发现                │       │ │
│  │  ├── scanner/ssdp.rs    ✅ UDP SSDP M-SEARCH           │       │ │
│  │  ├── scanner/tcp.rs     ✅ 全端口 TCP 扫描              │       │ │
│  │  ├── scanner/banner.rs  ✅ Banner 抓取                 │       │ │
│  │  ├── scanner/registry.rs✅ 服务指纹规则库               │       │ │
│  │  ├── util/oui.rs        ✅ MAC OUI 厂商识别             │       │ │
│  │  └── util/ip.rs         ✅ IP/子网工具                  │       │ │
│  │                                                        │       │ │
│  │  rs-core/ ◄── 小程序 WASM 编译目标                     │       │ │
│  │  ├── 同上有 scanner 全套                               │       │ │
│  │  ├── ai/        🔲 banner_parse/attack_chain/diagnosis │       │ │
│  │  ├── cve/       🔲 CVE 数据库 (结构已有)               │       │ │
│  │  ├── security/  🔲 credentials/default_creds/eos_db    │       │ │
│  │  └── recon/     🔲 dns/shodan/threat_intel/waf         │       │ │
│  └────────────────────────────────────────────────────────┘       │
│                                                                   │
│  ┌────────────────────────────────────────────────────────┐       │
│  │              PC 版扩展层 (src-tauri/src/)               │       │
│  │                                                        │       │
│  │  ✅ tls/          rustls+x509 TLS审计 + testssl.sh     │       │
│  │  ✅ history/      SQLite 扫描历史 (清理策略)            │       │
│  │  ✅ pipeline.rs   工具管道编排器 (CancelToken)          │       │
│  │  ✅ report.rs     报告构建 (PDF/JSON/HTML/CSV)          │       │
│  │  ✅ tool_commands  masscan/nmap/rustscan/nuclei/ffuf   │       │
│  │  ✅ tool_discovery 外部工具自动发现                     │       │
│  │  ✅ os_fingerprint OS 指纹 (TTL/TCP窗口)                │       │
│  └────────────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────┘

图例: ✅ 已完成  🔲 代码已有但未集成/Phase 2+
```

---

## 2. Phase 完成度矩阵

### 2.1 Phase 1 · 局域网服务发现（MVP）

| 功能 | PC 版 | 小程序版 | 核心库 |
|------|:-----:|:--------:|:------:|
| F1-1 mDNS 服务扫描 | ✅ | ✅ | ✅ |
| F1-2 UDP SSDP 探测 | ✅ | ✅ | ✅ |
| F1-3 TCP 端口探测 | ✅ 全端口 | ✅ 白名单 | ✅ |
| F1-4 设备拓扑图 | ✅ Canvas | ✅ Canvas | — |
| F1-5 本地 IP 感知 | ✅ | ✅ | ✅ |
| F1-6 扫描历史记录 | ✅ SQLite | ✅ Storage | — |

### 2.2 Phase 1 PC 扩展（规格书外已实现）

| 功能 | 状态 | 文件 |
|------|:----:|------|
| Banner 抓取 (HTTP/SSH/FTP/SMTP/MySQL) | ✅ | `scanner/banner.rs` |
| 服务指纹识别 | ✅ | `scanner/registry.rs` |
| TLS 审计 (rustls + testssl.sh) | ✅ | `tls/mod.rs`, `tls/rules.rs` |
| 报告导出 (PDF/JSON/HTML/CSV) | ✅ | `ExportPanel.tsx`, `report.rs` |
| 工具聚合 (masscan/nmap/rustscan/nuclei/ffuf/feroxbuster) | ✅ | `tool_commands.rs` |
| Pipeline 编排器 (CancelToken 取消机制) | ✅ | `pipeline.rs` |
| 外部工具自动发现 | ✅ | `scanner/tool_discovery.rs` |
| OS 指纹 (TTL/TCP 窗口/HTTP User-Agent) | ✅ | `scanner/os_fingerprint.rs` |

### 2.3 Phase 2-4 代码骨架（rs-core 中已有，未集成）

| 模块 | 状态 | 文件 |
|------|:----:|------|
| AI Banner 语义解析 | 🔲 | `rs-core/src/ai/banner_parser.rs` |
| AI 攻击链推理 | 🔲 | `rs-core/src/ai/attack_chain.rs` |
| AI 诊断与修复建议 | 🔲 | `rs-core/src/ai/diagnosis.rs`, `fix_suggest.rs` |
| CVE 数据库 | 🔲 | `rs-core/src/cve/db.rs`, `types.rs` |
| 默认凭据检测 (2000+ 设备) | 🔲 | `rs-core/src/security/default_creds.rs` |
| 未授权访问检测 | 🔲 | `rs-core/src/security/unauthorized.rs` |
| EOS/固件风险评估 | 🔲 | `rs-core/src/security/eos_db.rs`, `firmware.rs` |
| TLS 审计 (深度) | 🔲 | `rs-core/src/security/tls_audit.rs` |
| 公网侦察 (Shodan/FOFA) | 🔲 | `rs-core/src/recon/shodan.rs` |
| DNS/子域名枚举 | 🔲 | `rs-core/src/recon/dns.rs` |
| HTTP 安全头审计 | 🔲 | `rs-core/src/recon/http_audit.rs` |
| WAF/CDN 识别 | 🔲 | `rs-core/src/recon/waf.rs` |
| Web 漏洞被动检测 | 🔲 | `rs-core/src/recon/web_vuln.rs` |
| 威胁情报聚合 | 🔲 | `rs-core/src/recon/threat_intel.rs` |
| 安全报告生成 | 🔲 | `rs-core/src/security/report.rs` |

**结论：Phase 1 PC 版 100% 完成，小程序版约 80%（缺 Banner/报告/工具聚合），Phase 2-4 模块在 rs-core 中有完整代码骨架，核心工作在于"集成串联"而非"从零开发"。**

---

## 3. 多维度竞品对比

### 3.1 核心维度对比

| 维度 | **NetProwl** | **nmap/Zenmap** | **RustScan** | **Sniffnet** | **Angry IP Scanner** | **Fing** | **OpenVAS** |
|------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **定位** | 安全自检工具 | 通用端口扫描器 | 高速端口扫描 | 网络流量分析 | IP/端口扫描 | 设备发现 | 漏洞扫描套件 |
| **平台** | 微信小程序 + PC | CLI + Java GUI | CLI | 桌面 (iced) | Java GUI | 移动 + 桌面 | Web / CLI |
| **语言** | Rust + React | C + Lua + Java | Rust | Rust | Java | 混合 | C + Python |
| **安装门槛** | 扫码即用 | 需安装 | Cargo/二进制 | Cargo/二进制 | 需 JRE | App Store | Docker/包管理 |
| **GitHub Stars** | 新项目 | ~18.5k | ~15.5k | ~20k | ~5k | 闭源 | ~15k |

### 3.2 功能维度对比

| 功能 | NetProwl | nmap | RustScan | Sniffnet | Angry IP | Fing | OpenVAS |
|------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| mDNS / SSDP 发现 | ✅ 原生 | ⚠️ NSE 脚本 | ❌ | ❌ | ❌ | ✅ | ❌ |
| 端口扫描 | ✅ 全端口+多引擎 | ✅ 标杆 | ✅ 极速 | ❌ 被动监听 | ✅ 快速 | ✅ | ✅ |
| Banner 抓取 | ✅ 多协议 | ✅ NSE | ⚠️ 委托 nmap | ❌ | ❌ | ❌ | ✅ |
| 服务指纹 | ✅ 内置规则库 | ✅ NSE 600+ | ⚠️ 委托 nmap | ❌ | ❌ | ⚠️ 基础 | ✅ |
| TLS 审计 | ✅ rustls+testssl | ✅ NSE | ❌ | ❌ | ❌ | ❌ | ✅ |
| 漏洞检测 | ✅ nuclei | ✅ NSE | ❌ | ❌ | ❌ | ❌ | ✅ 核心能力 |
| Web Fuzzing | ✅ ffuf+feroxbuster | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| AI 语义分析 | 🔲 Phase 2 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| CVE 离线库 | 🔲 Phase 2 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| 攻击链推理 | 🔲 Phase 3 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| 默认凭据检测 | 🔲 Phase 3 | ⚠️ NSE | ❌ | ❌ | ❌ | ❌ | ✅ |
| 公网侦察 | 🔲 Phase 4 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| 扫描历史 | ✅ SQLite | ⚠️ XML | ❌ | ❌ | ❌ | ✅ 云端 | ✅ |
| 报告导出 | ✅ PDF/JSON/HTML | ✅ XML/HTML | ❌ | ❌ | ✅ CSV | ✅ | ✅ PDF/HTML |
| 工具编排 Pipeline | ✅ 原生 | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 任务调度 |
| 中国生态 (微信/DeepSeek) | ✅ 独占 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |

### 3.3 差异化优势

1. **唯一覆盖「微信小程序 + PC 桌面」双端**——零安装门槛 + 深度功能，无竞品做到
2. **唯一集成 AI 语义分析层**（Phase 2）——非技术人员也能读懂安全报告
3. **唯一内置 Pipeline 编排器**——自动串联 masscan → nuclei → ffuf → TLS 审计，无需手工脚本
4. **中国市场独占优势**——DeepSeek 私有化可选，微信生态 13 亿用户，数据不出境
5. **Rust 全栈**——统一技术栈，PC 端无 FFI 开销，WASM 产物比 Go 小 30-50%

### 3.4 与标杆差距

**vs nmap（标杆）：**
- 差距：NSE 脚本生态 600+ 脚本，25 年社区积累，OS 指纹库极全
- 策略：nuclei 替代 NSE（社区 8000+ 模板），AI 层弥补规则覆盖盲区

**vs OpenVAS（企业级）：**
- 差距：无持续漏洞 Feed 更新，CVE 库未填充，无 SCAP 合规
- 策略：Phase 2 CVE 离线库 + NVD JSON feeds 每周同步

---

## 4. 未来演进路线

### 4.1 方向一：夯实 Phase 1 基础（近期 2-4 周）

| 事项 | 优先级 | 说明 |
|------|:------:|------|
| **统一 core/ 和 rs-core/ 代码** | P0 | 两个 crate 存在 scanner 模块重复，应合并为 Cargo workspace 多 crate 结构 |
| 小程序 Banner 抓取 | P1 | 通过 WASM TCP 实现基础抓取（当前完全缺失） |
| 真机兼容性验证 | P1 | iOS mDNS 禁用降级策略、Android 各版本兼容 |
| CI/CD 完善 | P1 | GitHub Actions 已有骨架，补全 test/lint/build/release |
| Docker 支持 | P2 | `docker-compose.yml` 已有，完善容器化构建 |

### 4.2 方向二：Phase 2 · AI + CVE 落地（中期 4-8 周）

| 事项 | 优先级 | 说明 |
|------|:------:|------|
| **DeepSeek API 集成** | P0 | `parse_banner_ai` Tauri command 已定义，需填充实际调用 + streaming |
| **CVE 离线库填充** | P1 | `rs-core/src/cve/db.rs` 结构已有，导入 NVD JSON feeds → SQLite |
| AI 安全报告生成 | P2 | 扫描结果 + CVE 映射 → DeepSeek 自然语言报告（`fix_suggest.rs`） |
| 服务指纹规则库扩展 | P2 | 当前 `registry.rs` 规则有限，扩展至 200+ 指纹 |
| AI 诊断对话 | P2 | 小程序 chat 页面已预留，接入 DeepSeek 对话式安全问诊 |

### 4.3 方向三：Phase 3 · 安全检测深度（中远期 8-16 周）

| 事项 | 优先级 | 说明 |
|------|:------:|------|
| **默认凭据检测** | P0 | 2000+ 设备默认密码库（`default_creds.rs` 结构已有） |
| 未授权访问检测 | P1 | Redis / MongoDB / Docker API / Elasticsearch / etcd |
| 攻击链推理 | P2 | 多漏洞关联：TLS 弱套件 + 弱密码 + 未授权 → 攻击路径 |
| EOS / 固件风险 | P3 | 设备固件版本 → EOL 状态映射（`eos_db.rs`） |
| HTTP 认证暴力检测 | P3 | Basic/Digest/NTLM 弱口令（`http_auth.rs`） |

### 4.4 方向四：Phase 4 · 公网侦察（远期 16-24 周）

| 事项 | 优先级 | 说明 |
|------|:------:|------|
| Shodan / FOFA 集成 | P1 | 自有域名中转，避免小程序审核风险 |
| 子域名枚举 | P2 | DNS 爆破 + 证书透明日志 (crt.sh) |
| WAF / CDN 识别 | P3 | `waf.rs` 已有结构，WAFW00F 指纹库 |
| Web 漏洞被动检测 | P3 | CSP/CORS/SRI 等 Header 审计 |
| 威胁情报聚合 | P3 | AlienVault OTX / 微步在线 / VirusTotal |

### 4.5 方向五：产品化 & 商业化

| 事项 | 优先级 | 说明 |
|------|:------:|------|
| 微信小程序上架审核 | P1 | 安全工具白名单申请 + 演示模式 + 合规声明 |
| Probe Agent | P2 | Docker 一键部署、mDNS 自动发现配对、小程序全端口解锁 |
| Pro 订阅体系 | P3 | AI 次数限制 / 历史时长 / 公网侦察功能分层 |
| 社区建设 | P3 | 设备指纹贡献、CVE 规则社区维护、GitHub Discussions |

---

## 5. 架构改进建议

### 5.1 当前问题：core/ 和 rs-core/ 代码重复

两个 crate 各自实现了完整的 scanner 模块（mdns/ssdp/tcp/banner/registry），存在大量重复代码：

```
当前结构:                          建议结构:
core/ (netprowl-core)               crates/
├── scanner/mdns.rs                 ├── netprowl-core/      # 共享 scanner 逻辑
├── scanner/ssdp.rs                 │   └── scanner/
├── scanner/tcp.rs                  ├── netprowl-wasm/      # WASM 绑定层
├── scanner/banner.rs               ├── netprowl-ai/        # AI 语义层 (DeepSeek)
├── scanner/registry.rs             ├── netprowl-cve/       # CVE 离线库
└── util/                           ├── netprowl-security/  # 安全检测模块
                                     └── netprowl-recon/    # 公网侦察模块
rs-core/
├── scanner/... (重复!)             Cargo workspace 统一管理
├── ai/...                          workspace = { members = ["crates/*"] }
├── cve/...
├── security/...
└── recon/...
```

**收益：**
- 消除 scanner 模块的 100% 重复代码
- AI / CVE / Security / Recon 模块可被 PC 版直接复用（目前仅 WASM 编译目标可用）
- 单一 `cargo test --workspace` 跑所有测试
- 清晰的模块边界，便于独立版本控制和发布

### 5.2 netprowl-pc 依赖关系修正

当前 `netprowl-pc/src-tauri/Cargo.toml`:
```toml
netprowl-core = { path = "../../core" }
```

但 `lib.rs` 中调用了 `rs_core::ai::banner_parser::parse_banner_with_ai`——这意味着 rs-core 也被隐式依赖。应在 workspace 中明确声明，统一为一个入口。

---

## 6. 里程碑预测

```
2026-05 (当前)
  ✅ Phase 1 PC 版完成
  ✅ Phase 1 小程序版基础完成
  🔲 代码架构统一 (core/ + rs-core/ → workspace)

2026-06 (近期)
  🔲 DeepSeek API 集成上线
  🔲 CVE 离线库初版 (NVD feeds 导入)
  🔲 小程序真机兼容性验证通过

2026-07 ~ 08 (中期)
  🔲 AI 安全报告生成
  🔲 默认凭据检测 (2000+ 规则)
  🔲 未授权访问检测
  🔲 服务指纹规则库扩展至 200+

2026-09 ~ 12 (远期)
  🔲 攻击链推理 AI
  🔲 公网侦察 (Shodan/FOFA)
  🔲 Probe Agent (小程序全端口解锁)
  🔲 微信小程序上架审核

2027+ (商业化)
  🔲 Pro 订阅上线
  🔲 Enterprise 私有化部署
  🔲 社区生态建设
```

---

## 7. 总结

NetProwl 在 **Phase 1 PC 端**已具备相当完整的能力闭环：

> 设备发现 (mDNS/SSDP) → 端口扫描 (masscan/nmap/rustscan) → Banner 抓取 → 服务指纹 → TLS 审计 → 漏洞检测 (nuclei) → Web Fuzzing (ffuf/feroxbuster) → 历史存储 (SQLite) → 报告导出 (PDF/JSON/HTML)

在「桌面 GUI + 多工具编排 + 一站式安全检测」这个细分领域**已超越大部分开源竞品**。小程序版完成了基础发现能力，在深度功能上受微信 API 限制。

Phase 2-4 的代码骨架已在 `rs-core/` 中就位，接下来的关键不是"从零开发"而是"**集成串联**"——把 DeepSeek API 接进来、把 CVE 数据灌进去、把安全检测规则库填充起来。

**项目的最大差异化护城河：**
- **AI 语义层** —— 让非技术人员也能理解安全风险
- **微信生态** —— 13 亿用户零安装门槛
- **DeepSeek 私有化** —— 中国市场数据合规无忧

目前还没有任何竞品同时覆盖这三点。

---

*文档版本：v1.0*
*生成方式：基于 roadmap.md / specs/ / 源码 综合分析*
