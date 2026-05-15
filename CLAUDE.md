# NetProwl 开发约束

**规格书**：`docs/superpowers/specs/2026-05-11-netprowl-phase1-design.md`
所有开发必须遵循规格书 v1.3。

**架构原则**：

1. **双版本并行**
   - 微信小程序版（netprowl-mini/）：Taro + React，微信原生 API（mDNS/TCP/UDP），WASM 仅用于纯计算（OUI/IP）
   - PC 客户端版（netprowl-pc/）：Tauri + React，Rust 原生全部功能

2. **Rust 核心统一**（rs-core/）
   - 唯一权威 Rust 核心库
   - 模块：scanner（mDNS/UDP SSDP/TCP/Banner/Registry）+ ip/oui/consts/types
   - Phase 2+ 模块：ai/（攻击链、诊断、修复建议、Banner 解析）、cve/（CVE 数据库）、
     security/（凭据检测、固件、TLS 审计、未授权访问）、recon/（Shodan/FOFA/DNS/HTTP 审计/WAF/威胁情报）
   - PC：src-tauri/src 通过 thin wrapper 调用 rs-core
   - 小程序：wasm-pack 编译 rs-core 为 WASM（仅纯计算函数，网络函数仅 native）

3. **实际 Phase 进展（2026-05-15）**
   - Phase 1（局域网服务发现）：✅ 完成 — mDNS/SSDP/TCP/Banner/服务指纹/OUI
   - Phase 2（服务指纹与协议识别）：✅ 完成 — 服务指纹规则库 / TLS 审计 / AI Banner 解析 / CVE 库
   - Phase 3（安全弱点检测）：✅ 完成 — 默认凭据检测 / TLS 审计 / 未授权访问 / 固件风险评估 / 报告导出
   - Phase 4（公网侦察）：✅ 完成 — Shodan/FOFA / DNS 侦察 / HTTP 安全头审计 / WAF/CDN 检测 / 威胁情报
   - Probe Agent：未实现（Phase 2+ 可选方案）

**禁止**：
- 引入 `core/` 目录（已删除，rs-core 是唯一核心库）
- 在 PC scanner 中重复实现 rs-core 已有模块（已收敛为 thin wrapper）
- 在 WASM 中导出网络扫描函数（WASM 仅用于纯计算）

**开发流程**：
1. 读规格书
2. 写 plan（docs/superpowers/plans/）
3. 实现
4. commit
