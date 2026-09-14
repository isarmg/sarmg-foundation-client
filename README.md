# Sarmg Foundation Client

当前源码版本为 `0.9.4`，统一采用 Client 命名；未通过对应原生 CI 前，不宣称跨平台验收完成。

桌面 Profile 可由 `sarmg-client-runtime::local_status` 完整提供本地只读状态通道。产品只提交绑定代次、有效配置
revision 和业务观察字段；Unix 对端身份校验、Windows 受保护命名管道、消息上限及生命周期均由 Foundation
实现，产品不得再保留等价副本。

`sarmg-client-cli` 完整提供公共参数合同、脱敏输出、受保护输入和 Linux/Windows/macOS 服务生命周期。产品
声明自己的选项、服务名、可执行文件、配置路径和日志路径，并保留业务命令及业务状态机；Foundation 不按
产品名分支。
历史 `0.6.0` 的限制见 [历史发布记录](docs/releases/0.6.0.md)，本次命名变更不改写历史标签或制品。

`sarmg-foundation-client` 是独立的 Client/客户端规范、基础实现和验收工具仓库。
只规定桌面 Client、Android/iOS 客户端、移动 FFI 和管理这些客户端自身的 Web 的行为。
管理 Server 的 Web 归 `sarmg-foundation-server`；管理 Client/客户端本机配置、配对和服务状态的 Web 归本仓。
不能仅凭浏览器技术或 `clients/web` 目录名判定归属。

## 当前组件

| 包 | 客户端职责 |
|---|---|
| `sarmg-client-runtime` | 有界队列、Spool、退避、投递、健康与关闭 |
| `sarmg-mobile-ffi` | ABI 2、结果所有权、panic 边界、代际句柄与 JNI |
| `sarmg-client-fs-safety` | 私有目录、持有句柄的文件操作、原子发布与锁 |
| `sarmg-client-secret-envelope` | 客户端对象与域绑定的有界密钥封装 |
| `sarmg-client-secret` | 脱敏并清零的内存秘密 |
| `sarmg-client-error` | 客户端错误与协议错误解析基础类型 |

Profile 仅有 `desktop-client` 和 `mobile-client`，机器事实源在 `profiles/`。
客户端产品通过 `sarmg-client.toml` 声明 Profile、能力及检查范围；服务端另用 `sarmg-product.toml`。
客户端清单里的版本是开发工作区身份，不构成不可变发布或跨仓库升级证明。

两个基础仓库不互相依赖。客户端需要的通用机制在拆分时从原实现提取为独立命名的客户端包，
保留许可证与测试；它们不是旧包的转发器或兼容别名。两侧分别维护和验收，安全修复须评估是否同时影响两侧。
业务协议仍由产品拥有，服务器和 Client 的业务 DTO 不因基础仓库拆分而变更。

## 验证

```sh
python3 scripts/check-foundation.py
python3 -m unittest discover -s tools/tests -v
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
python3 scripts/check-foundation.py --product-root ../host-monitoring-client
python3 scripts/check-foundation.py --product-root ../media-backup-client
```

本仓可独立构建，无需克隆 Server 仓库。Client 命名基线为 `0.7.0`；
消费者发布必须同时锁定本仓完整 Git revision 和精确 crate 版本，不能使用同级工作区路径。
Linux/JVM/C 主机验证不能代替 Android/iOS/Windows/macOS 原生验收。

## 规范

- [客户端 Web 管理边界](docs/client-web.md)
- [Spool](docs/client-spool.md)
- [身份与凭据快照](docs/client-identity.md)
- [Mobile FFI](docs/mobile-ffi.md)
- [文件句柄](docs/filesystem-handles.md)

只支持当前合同，不提供旧版本升级、旧读取器、旧名称入口、双路径或 fallback。
