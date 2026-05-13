# NetProwl PC 客户端 Phase 1 完成状态

> **日期**：2026-05-13
> **架构演进**：CLI/TUI (2023-2024) → 微信小程序 (2025) → PC 客户端 (2026)

---

## PC 客户端 Phase 1 完成状态总览

<div style="width: 1100px; box-sizing: border-box; position: relative; background: #1e293b; padding: 20px; border-radius: 10px; font-family: sans-serif;">
  <style scoped>
    .arch-wrapper { display: flex; gap: 12px; }.arch-sidebar { width: 180px; flex-shrink: 0; }.arch-main { flex: 1; min-width: 0; }.arch-title { text-align: center; font-size: 20px; font-weight: bold; color: #e2e8f0; margin-bottom: 16px; }
    .arch-layer { margin: 8px 0; padding: 14px; border-radius: 8px; }.arch-layer-title { font-size: 13px; font-weight: bold; margin-bottom: 10px; text-align: center; }
    .arch-grid { display: grid; gap: 8px; }.arch-grid-2 { grid-template-columns: repeat(2, 1fr); }.arch-grid-3 { grid-template-columns: repeat(3, 1fr); }.arch-grid-4 { grid-template-columns: repeat(4, 1fr); }
    .arch-box { border-radius: 6px; padding: 8px; text-align: center; font-size: 11px; font-weight: 600; line-height: 1.35; color: #cbd5e1; background: rgba(51, 65, 85, 0.6); border: 1px solid rgba(148, 163, 184, 0.3); }.arch-box.highlight { background: rgba(59, 130, 246, 0.2); border: 1px solid #60a5fa; color: #93c5fd; }.arch-box.done { background: rgba(16, 185, 129, 0.15); border: 1px solid #34d399; color: #6ee7b7; }.arch-box.pending { background: rgba(239, 68, 68, 0.1); border: 1px solid #f87171; color: #fca5a5; }.arch-box.tech { font-size: 10px; color: #94a3b8; background: rgba(30, 41, 59, 0.6); }
    .arch-layer.user { background: rgba(59, 130, 246, 0.06); border: 1px solid #60a5fa; }.arch-layer.user .arch-layer-title { color: #93c5fd; }.arch-layer.application { background: rgba(245, 158, 11, 0.06); border: 1px solid #fbbf24; }.arch-layer.application .arch-layer-title { color: #fcd34d; }.arch-layer.ai { background: rgba(16, 185, 129, 0.06); border: 1px solid #34d399; }.arch-layer.ai .arch-layer-title { color: #6ee7b7; }.arch-layer.data { background: rgba(236, 72, 153, 0.06); border: 1px solid #f472b6; }.arch-layer.data .arch-layer-title { color: #f9a8d4; }.arch-layer.infra { background: rgba(139, 92, 246, 0.06); border: 1px solid #a78bfa; }.arch-layer.infra .arch-layer-title { color: #c4b5fd; }
    .arch-sidebar-panel { border-radius: 8px; padding: 10px; background: rgba(51, 65, 85, 0.3); border: 1px solid #475569; margin-bottom: 8px; }.arch-sidebar-title { font-size: 12px; font-weight: bold; text-align: center; color: #94a3b8; margin-bottom: 6px; }.arch-sidebar-item { font-size: 10px; text-align: center; color: #cbd5e1; background: rgba(30, 41, 59, 0.5); padding: 5px; border-radius: 4px; margin: 3px 0; border: 1px solid rgba(51, 65, 85, 0.6); }.arch-sidebar-item.metric { background: rgba(59, 130, 246, 0.12); border: 1px solid rgba(96, 165, 250, 0.4); color: #93c5fd; font-weight: 600; }.arch-sidebar-item.done { background: rgba(16, 185, 129, 0.12); border: 1px solid rgba(52, 211, 153, 0.4); color: #6ee7b7; }.arch-sidebar-item.pending { background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(248, 113, 113, 0.3); color: #fca5a5; }
    .legend { display: flex; gap: 16px; justify-content: center; margin-bottom: 12px; font-size: 11px; }.legend-item { display: flex; align-items: center; gap: 6px; color: #cbd5e1; }.legend-dot { width: 12px; height: 12px; border-radius: 3px; }
  </style>
  <div class="arch-title">NetProwl PC 客户端 Phase 1 架构图</div>
  <div class="legend">
    <div class="legend-item"><div class="legend-dot" style="background: rgba(16, 185, 129, 0.5); border: 1px solid #34d399;"></div>已完成</div>
    <div class="legend-item"><div class="legend-dot" style="background: rgba(239, 68, 68, 0.3); border: 1px solid #f87171;"></div>待完成</div>
    <div class="legend-item"><div class="legend-dot" style="background: rgba(59, 130, 246, 0.3); border: 1px solid #60a5fa;"></div>Phase 2+</div>
  </div>
  <div class="arch-wrapper">
    <div class="arch-sidebar">
      <div class="arch-sidebar-panel"><div class="arch-sidebar-title">前端组件</div>
        <div class="arch-sidebar-item done">PipelinePanel ✅</div>
        <div class="arch-sidebar-item done">UnifiedResultsPanel ✅</div>
        <div class="arch-sidebar-item done">ToolStatusBar ✅</div>
        <div class="arch-sidebar-item done">TLSResultPanel ✅</div>
        <div class="arch-sidebar-item done">HistoryDrawer ✅</div>
        <div class="arch-sidebar-item done">ExportPanel ✅</div>
        <div class="arch-sidebar-item done">TopoCanvas ✅</div>
      </div>
      <div class="arch-sidebar-panel"><div class="arch-sidebar-title">状态管理</div>
        <div class="arch-sidebar-item done">pipelineStore ✅</div>
        <div class="arch-sidebar-item done">historyStore ✅</div>
      </div>
      <div class="arch-sidebar-panel"><div class="arch-sidebar-title">外部工具</div>
        <div class="arch-sidebar-item done">masscan ✅</div>
        <div class="arch-sidebar-item done">nmap ✅</div>
        <div class="arch-sidebar-item done">rustscan ✅</div>
        <div class="arch-sidebar-item done">nuclei ✅</div>
        <div class="arch-sidebar-item done">ffuf ✅</div>
        <div class="arch-sidebar-item done">feroxbuster ✅</div>
      </div>
    </div>
    <div class="arch-main">
      <div class="arch-layer user">
        <div class="arch-layer-title">前端 UI 层 (React + TypeScript)</div>
        <div class="arch-grid arch-grid-4">
          <div class="arch-box done">ScanPage<br><small>扫描入口</small></div>
          <div class="arch-box done">TopoCanvas<br><small>设备拓扑图 Canvas</small></div>
          <div class="arch-box done">HistoryDrawer<br><small>历史记录侧边栏</small></div>
          <div class="arch-box done">ExportPanel<br><small>PDF/JSON/HTML导出</small></div>
        </div>
      </div>
      <div class="arch-layer application">
        <div class="arch-layer-title">Rust 核心扫描层 (src-tauri/src/scanner/)</div>
        <div class="arch-grid arch-grid-4">
          <div class="arch-box done">mdns.rs ✅<br><small>mDNS 服务发现</small></div>
          <div class="arch-box done">ssdp.rs ✅<br><small>UDP SSDP M-SEARCH</small></div>
          <div class="arch-box done">tcp.rs ✅<br><small>全端口 TCP 扫描</small></div>
          <div class="arch-box done">banner.rs ✅<br><small>Banner 抓取 HTTP/SSH/FTP</small></div>
          <div class="arch-box done">registry.rs ✅<br><small>服务指纹规则库</small></div>
          <div class="arch-box done">oui.rs ✅<br><small>MAC OUI 厂商识别</small></div>
          <div class="arch-box done">ip.rs ✅<br><small>IP/子网工具</small></div>
          <div class="arch-box done">tool_discovery.rs ✅<br><small>外部工具自动发现</small></div>
        </div>
      </div>
      <div class="arch-layer ai">
        <div class="arch-layer-title">工具管道层 (tool_commands.rs)</div>
        <div class="arch-grid arch-grid-3">
          <div class="arch-box done">masscan + nmap + rustscan<br><small>端口扫描聚合</small></div>
          <div class="arch-box done">nuclei<br><small>漏洞检测</small></div>
          <div class="arch-box done">ffuf + feroxbuster<br><small>Web 目录/ fuzz</small></div>
        </div>
      </div>
      <div class="arch-layer data">
        <div class="arch-layer-title">数据层</div>
        <div class="arch-grid arch-grid-4">
          <div class="arch-box done">tls/mod.rs ✅<br><small>rustls + x509 TLS审计</small></div>
          <div class="arch-box done">tls/rules.rs ✅<br><small>弱套件/过期检测</small></div>
          <div class="arch-box done">tls/testssl.rs ✅<br><small>testssl.sh 集成</small></div>
          <div class="arch-box done">history/mod.rs ✅<br><small>SQLite 扫描历史</small></div>
        </div>
      </div>
      <div class="arch-layer infra">
        <div class="arch-layer-title">Phase 2+ 待完成</div>
        <div class="arch-grid arch-grid-4">
          <div class="arch-box pending">DeepSeek AI 语义解析<br><small>Banner 模糊匹配</small></div>
          <div class="arch-box pending">攻击链推理<br><small>多漏洞关联分析</small></div>
          <div class="arch-box pending">默认凭据检测<br><small>弱口令规则库</small></div>
          <div class="arch-box pending">CVE 版本映射<br><small>离线 CVE 规则库</small></div>
        </div>
      </div>
    </div>
  </div>
</div>

---

## Phase 1 功能完成清单

### ✅ 已完成

| 功能 | 文件 | 说明 |
|------|------|------|
| P1-1 全端口 TCP 扫描 | `scanner/tcp.rs` | 并发扫描，FULL_PORTS 支持 |
| P1-2 mDNS 发现 | `scanner/mdns.rs` | Tokio async mDNS |
| P1-2 UDP SSDP | `scanner/ssdp.rs` | M-SEARCH 广播解析 |
| P1-3 设备拓扑图 | `TopoCanvas.tsx` | Canvas 绘制，设备图标分类 |
| P1-4 Banner 抓取 | `scanner/banner.rs` | HTTP/SSH/FTP/SMTP/MySQL |
| P1-5 服务指纹 | `scanner/registry.rs` | 内置规则库匹配 |
| P1-6 TLS 审计 | `tls/mod.rs`, `tls/rules.rs` | 证书链解析、弱套件、过期检测 |
| P1-7 扫描历史 | `history/mod.rs` | SQLite 本地持久化 |
| P1-8 报告导出 | `ExportPanel.tsx`, `PrintReport.tsx` | PDF(print+pdfmake)/JSON/HTML |
| 工具聚合 | `tool_commands.rs` | masscan/rustscan/nmap/nuclei/ffuf/feroxbuster |
| Pipeline 编排 | `pipeline.rs` | CancelToken 取消机制 |
| 外部工具自动发现 | `scanner/tool_discovery.rs` | check_all_tools() |

### 🔲 Phase 2+ 待完成

| 功能 | 说明 | 关联 Phase |
|------|------|-----------|
| DeepSeek AI Banner 解析 | 模糊 Banner 语义匹配 | Phase 2 |
| 攻击链推理 | 多漏洞关联利用分析 | Phase 3 |
| 默认凭据检测 | 2000+ 设备默认密码规则 | Phase 3 |
| CVE 版本映射 | 离线 CVE SQLite 库 | Phase 2 |
| 未授权访问检测 | Redis/MongoDB/Docker API | Phase 3 |
| 公网侦察 | Shodan/FOFA 集成 | Phase 4 |

---

## 验收标准检查

| 验收项 | 状态 | 说明 |
|--------|------|------|
| 全端口 TCP 扫描（100+ 并发）| ✅ | `TcpConfig { concurrency }` 可配置 |
| Banner 抓取（HTTP/SSH/FTP）| ✅ | `banner.rs` 支持多协议 |
| 设备拓扑图 20+ 设备流畅 | ✅ | Canvas 渲染，macOS 原生 |
| 扫描历史正确存取 | ✅ | `HistoryDb` SQLite |
