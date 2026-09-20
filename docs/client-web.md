# Client / Client Web 管理归属

Web 按被管理对象划分，不按 React、原生 JavaScript、浏览器或目录名称划分。

- 管理 Server 的用户、设备记录、备份任务、管理员和服务端配置的页面，以及其管理 API client，归 Server Foundation。
- 管理本机 Client/客户端的配置、配对、启停、诊断和本机状态的页面，归 Client Foundation；产品页面与业务操作留在产品 client/client 源码中。
- Client 为本机页面提供 loopback HTTP，并不使该客户端进程成为受 Server target 限制的业务 Server。
- 两侧不得通过导入另一侧基础仓库的认证、Web shell 或 Runtime 来隐式混合行为；公共安全修复须分别评估两侧。

## 当前消费者

Host、Media、Sunshine、Sentinel 和 Dufs 的管理 Web 都管理各自的 Server，保持 Server Profile；具体目录
由产品仓库决定，不能假定都叫 `clients/web`。当前已登记的 Client 产品没有本机 Web 管理入口，Host
Client 也已移除旧 Windows 托盘和 loopback 配置页。

桌面客户端将来若增加本机 Web，应通过可选 `local-web-management` 能力声明这一形态。本地 Web Adapter 由产品拥有，
不声称已提炼出通用 Client Web UI 包。其本地一次性入口凭证、loopback Host/Origin、Bearer 会话、
本机权限提升与服务控制边界独立于 Server 的管理员 Cookie/CSRF 协议，不能用 Server 政策覆盖它们。

Foundation 当前只提供 `authenticated-local-status` 的只读 Unix socket/Windows named pipe 通道，不提供
HTML 页面、浏览器会话或控制路由。Client 的规范检查可扫描 Rust、JavaScript、HTML、TypeScript、Swift
和 Kotlin；若产品新增本机 Web，仍需在目标操作系统完成原生运行与权限验收。
