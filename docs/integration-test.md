# 集成测试文档

## 前置条件
- Go 1.21+
- Node.js 18+
- 微信开发者工具
- Rust 1.70+

## 小程序测试
```bash
cd netprowl-mini
npm install
npm run dev:weapp
```
打开微信开发者工具，导入项目，验证：
- [ ] mDNS 发现设备
- [ ] SSDP 发现设备
- [ ] TCP 白名单端口扫描正常
- [ ] 拓扑图正常渲染
- [ ] 历史记录保存

## PC 测试
```bash
cd netprowl-pc
npm install
npm run tauri dev
```
验证：
- [ ] 全端口 TCP 扫描正常
- [ ] Banner 正确抓取
- [ ] 设备列表正常显示

## Commit

```bash
git add docs/integration-test.md
git commit -m "docs: add integration test guide"
```