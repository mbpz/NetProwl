# NetProwl

**网络安全工具** — 从 CLI 到桌面，内外网统一发现与安全检测。

```
发展阶段：
  CLI/TUI  ─────────────────────────────────────────────
  ↓ (2023-2024)
  微信小程序版  ────────────────────────────────
  ↓ (2026)
  双版本并行：微信小程序版 + PC 客户端版
```

## 核心能力

| 功能 | 小程序版 | PC 版 |
|------|---------|-------|
| mDNS / SSDP 发现 | ✅ | ✅ |
| 端口扫描 | 白名单端口 | 全端口 + masscan/rustscan/nmap |
| Banner 抓取 | ❌ | ✅ |
| 服务指纹 | ❌ | ✅ |
| 漏洞检测 | ❌ | ✅ nuclei / ffuf / feroxbuster |
| TLS 审计 | ❌ | ✅ rustls + testssl.sh |
| 扫描历史 | ❌ (10MB) | ✅ SQLite |
| 报告导出 | ❌ | ✅ |

## 技术栈

| 层 | 技术 |
|---|---|
| 核心扫描 | Rust (netprowl-core) |
| 小程序前端 | Taro + React |
| PC 前端 | React + TypeScript |
| PC 后端 | Tauri 2.x + Rust |
| 小程序集成 | wasm-pack (Rust → WASM) |
| PC 集成 | Native Rust 调用 |

## 项目结构

```
NetProwl/
├── core/                  # Rust 核心库（共享）
│   ├── scanner/           # mDNS / SSDP / TCP / Banner
│   ├── security/         # 漏洞规则
│   └── ai/               # AI 层（Phase 2）
├── netprowl-mini/        # 微信小程序版
│   └── src/wasm/         # Rust WASM 集成
├── netprowl-pc/          # PC 客户端版
│   ├── src/             # React 前端
│   └── src-tauri/       # Tauri + Rust 后端
└── docs/                # 规格书 + 设计文档
```

## 安装

### macOS (Homebrew)

```bash
brew install mbpz/tap/NetProwl
```

首次安装需要输入密码授权系统扩展。

### PC 版

```bash
cd netprowl-pc
npm install
# 安装外部工具
./install.sh
# 开发
npm run dev
# 构建
npm run build
```

### 小程序版

```bash
cd netprowl-mini
npm install
npm run dev:weapp
```

## Roadmap

See [roadmap.md](roadmap.md) for full project roadmap covering Phase 1-4.

## 许可证

MIT