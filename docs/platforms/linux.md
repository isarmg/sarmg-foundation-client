# Linux：原生库接入与验证

正式目标为 `x86_64-unknown-linux-gnu`。本页面向把 xcsc 编译进产品的开发者；客户端安装和 systemd 服务部署由具体产品提供。先完成[依赖与产品清单](../getting-started.md)，再验证 Linux 的存储和运行身份。

## 工具链与编译

准备 Rust `1.99.0`、Python 3、GNU C/C++ 编译工具链。启用 `offline-maintenance` 时会编译随依赖提供的 SQLite，需要可用的 C 编译器。在 xcsc 仓库根目录运行：

```sh
rustup target add --toolchain 1.99.0 x86_64-unknown-linux-gnu
cargo +1.99.0 check --locked -p xcsc --target x86_64-unknown-linux-gnu
cargo +1.99.0 test --locked -p xcsc --all-targets --all-features
cargo +1.99.0 clippy --locked -p xcsc --all-targets --all-features -- -D warnings
```

后两条在 Linux x86_64 原生主机执行，`--all-features` 包含 Linux 离线维护模块。跨目标 `check` 只检查编译。提交前另运行[公共检查](../development.md)。

## 桌面与离线工具接入

- 桌面客户端选择 `desktop-client`，默认 features 足以接入身份、私有状态、队列和投递。
- 离线工具选择 `offline-maintenance` profile 与同名 feature，使用 `state_file`、`sqlite` 和 `OpenAt2Root`。正式目标仅为 Linux x86_64 GNU。
- 产品负责服务名、状态路径、服务停止策略、数据库业务 SQL 和恢复流程。字段与预算统一见[能力配置](../configuration.md)。

普通私有状态使用 Unix 描述符相对操作；离线目录锚定能力另要求 Linux `openat2`。部署离线工具时须在目标内核及文件系统验证必需原语，缺失时操作会明确失败。实现与发布语义见[文件系统参考](../filesystem-handles.md)。

## 运行身份与排障

1. 使用产品服务的实际 uid/gid 和绝对物理路径。祖先目录必须存在且不能经过符号链接；最终私有目录为 `0700`，私有文件为 `0600`。
2. 权限失败时先检查运行身份、属主及路径。库只校验既有权限，不会自动修复；不要用扩大权限来消除错误。
3. 普通账户测试不能覆盖 root 管理服务属主状态的场景。Linux CI 的专用 ignored 用例在隔离临时夹具中验证这一点，不应对生产状态目录试跑。
4. `AlreadyRunning` 按[共同排障](../troubleshooting.md)检查现有会话；释放锁后稳定锁文件仍保留。

验收应包括当前服务身份下的创建、重开、锁争用、队列恢复和实际投递。库测试通过后继续执行产品自己的 systemd 与安装测试。

[模块使用](../usage.md) · [选择其他平台](../README.md#选择接入平台)
