# Cloudflare 边缘复验与修复

本机只有 GitHub 凭据，没有 Cloudflare Zone 的管理凭据，因此不能代替账号所有者修改以下两项。

1. Cloudflare Dashboard → SSL/TLS → Edge Certificates → Minimum TLS Version，设为 `TLS 1.3`。不要只开启 “TLS 1.3” 开关；该开关允许 1.3，但只有 Minimum TLS Version 才会拒绝 1.2。
2. Cloudflare Dashboard → Web Analytics → 对 `test.pixcora.com` 选择 Manage Site → Automatic setup 设为 `Disable`。当前应用没有接入该分析功能，Cloudflare 却按真实浏览器 UA 自动注入 `beacon.min.js`，并被应用的严格 `script-src 'self'` 正确拦截。不建议为未使用的分析脚本放宽 CSP。
3. 等待边缘配置传播后复验：公网 `openssl s_client -tls1_2` 必须失败，`-tls1_3` 必须成功；再次运行 `scripts/browser-matrix.cjs`，结果必须为 105 route checks、0 route failure、0 overflow、0 error group。

官方说明：

- https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/
- https://developers.cloudflare.com/web-analytics/get-started/
