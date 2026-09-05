# Agent / Client Web 管理归属

Web 按被管理对象划分，不按 React、原生 JavaScript、浏览器或目录名称划分。

- 管理 Server 的用户、设备记录、备份任务、管理员和服务端配置的页面，以及其管理 API client，归 Server Foundation。
- 管理本机 Agent/客户端的配置、配对、启停、诊断和本机状态的页面，归 Agent Foundation；产品页面与业务操作留在产品 agent/client 源码中。
- Agent 为本机页面提供 loopback HTTP，并不使该客户端进程成为受 Server target 限制的业务 Server。
- 两侧不得通过导入另一侧基础仓库的认证、Web shell 或 Runtime 来隐式混合行为；公共安全修复须分别评估两侧。

## 当前消费者

Host、Media、Sunshine、Sentinel 和 Dufs 的 `clients/web` 都管理各自的 Server，保持 Server Profile。
Host Agent 的 Windows 托盘本地配置页面则属于客户端：
`clients/host-monitor/src/windows/tray/configuration_ui.rs`、`assets/configuration.js`、
`control_server.rs`、`control_routes.rs`、`control_response.rs` 及对应测试，均纳入 `sarmg-agent.toml` 的客户端检查范围。

桌面客户端通过可选 `local-web-management` 能力声明这一形态。当前本地 Web Adapter 由产品拥有，
不声称已提炼出通用 Agent Web UI 包。其本地一次性入口凭证、loopback Host/Origin、Bearer 会话、
本机权限提升与服务控制边界独立于 Server 的管理员 Cookie/CSRF 协议，不能用 Server 政策覆盖它们。

Host 托盘的公开 Server 健康探测经 `tray_support/server_health` 调用 Agent Foundation
同步 HTTP 适配器，不再有产品本地 blocking HTTP 客户端。只发送不带 Agent 凭据的
`GET /health/live`，不读取 ProgramData 配置/凭据；结果不能证明服务身份下的 mTLS 或遥测投递。

目前未新增页面、未迁移业务路由、未改变本机会话协议。Agent 的规范检查覆盖 Rust、JavaScript、HTML、
TypeScript、Swift 和 Kotlin；Windows 本地控制台的目标原生运行验收仍需 Windows 环境。
