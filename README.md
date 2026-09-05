# Sarmg Foundation Agent

`sarmg-foundation-agent` 是独立的 Agent/客户端规范、基础实现和验收工具仓库。
只规定桌面 Agent、Android/iOS 客户端、移动 FFI 和管理这些客户端自身的 Web 的行为。
管理 Server 的 Web 归 `sarmg-foundation-server`；管理 Agent/客户端本机配置、配对和服务状态的 Web 归本仓。
不能仅凭浏览器技术或 `clients/web` 目录名判定归属。

## 当前组件

| 包 | 客户端职责 |
|---|---|
| `sarmg-agent-runtime` | 有界队列、Spool、退避、投递、健康与关闭 |
| `sarmg-mobile-ffi` | ABI 2、结果所有权、panic 边界、代际句柄与 JNI |
| `sarmg-agent-fs-safety` | 私有目录、持有句柄的文件操作、原子发布与锁 |
| `sarmg-agent-secret-envelope` | 客户端对象与域绑定的有界密钥封装 |
| `sarmg-agent-secret` | 脱敏并清零的内存秘密 |
| `sarmg-agent-error` | 客户端错误与协议错误解析基础类型 |
| `sarmg-agent-secure-http` | 客户端出站 HTTP 的地址、超时和响应预算 |

Profile 仅有 `desktop-agent` 和 `mobile-agent`，机器事实源在 `profiles/`。
客户端产品通过 `sarmg-agent.toml` 声明 Profile、能力及检查范围；服务端另用 `sarmg-product.toml`。
客户端清单里的版本是开发工作区身份，不构成不可变发布或跨仓库升级证明。

两个基础仓库不互相依赖。客户端需要的通用机制在拆分时从原实现提取为独立命名的客户端包，
保留许可证与测试；它们不是旧包的转发器或兼容别名。两侧分别维护和验收，安全修复须评估是否同时影响两侧。
业务协议仍由产品拥有，服务器和 Agent 的业务 DTO 不因基础仓库拆分而变更。

## 验证

```sh
python3 scripts/check-foundation.py
python3 -m unittest discover -s tools/tests -v
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
python3 scripts/check-foundation.py --product-root ../host-monitoring
python3 scripts/check-foundation.py --product-root ../media-backup
```

本仓可独立构建，无需克隆 Server 仓库。首个独立源码发行版本为 `0.6.0`；
消费者发布必须同时锁定本仓完整 Git revision 和精确 crate 版本，不能使用同级工作区路径。
Linux/JVM/C 主机验证不能代替 Android/iOS/Windows/macOS 原生验收。

## 规范

- [客户端 Web 管理边界](docs/client-web.md)
- [Spool](docs/agent-spool.md)
- [身份与凭据快照](docs/agent-identity.md)
- [Mobile FFI](docs/mobile-ffi.md)
- [文件句柄](docs/filesystem-handles.md)
- [安全 HTTP 工厂](docs/secure-http.md)

只支持当前合同，不提供旧版本升级、旧读取器、旧名称入口、双路径或 fallback。
