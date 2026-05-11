# NetProwl 开发约束

**规格书**：`docs/superpowers/specs/2026-05-11-netprowl-phase1-design.md`
所有开发必须遵循规格书 v1.2。

**架构原则**：

1. **Phase 1 双版本并行**
   - 微信小程序版（netprowl-mini/）：Taro + React，受微信 API 限制
   - PC 客户端版（netprowl-pc/）：Tauri + React，全部功能本地运行

2. **Go 核心共享**（core/）
   - mDNS / UDP SSDP / TCP 扫描 / Banner 抓取
   - 两版本前端独立，核心能力复用

3. **Phase 2+ 才引入**
   - Probe Agent（可选部署）
   - 云端中台（DeepSeek AI / CVE 库）

**禁止**：
- 引入与规格书不符的架构（如旧 probe-agent/、cloud/）
- 在 Phase 1 做 Phase 2+ 的功能
- 破坏双版本并行结构

**开发流程**：
1. 读规格书
2. 写 plan（docs/superpowers/plans/）
3. 实现
4. commit