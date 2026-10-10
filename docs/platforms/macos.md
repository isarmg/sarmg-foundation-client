# macOS：原生库接入与验证

正式目标为 Apple Silicon `aarch64-apple-darwin` 和 Intel `x86_64-apple-darwin`。本页介绍 Rust 库接入；产品 App、安装器和 launchd 配置由消费方提供。依赖与 `desktop-client` 清单见[开始接入](../getting-started.md)。

## 工具链与构建目标

准备 Rust `1.99.0`、Xcode Command Line Tools 和 Python 3。安装与本机架构匹配的 Rust 工具链，在 xcsc 根目录运行：

```sh
rustc +1.99.0 -vV
cargo +1.99.0 check --locked -p xcsc
```

`rustc -vV` 的 `host` 应与本次原生验收架构一致。产品要分发 Intel 与 Apple Silicon 时分别构建和验证两个目标；Apple Silicon CI 的执行记录只覆盖该运行架构。`offline-maintenance` 的 Linux 状态/SQLite 模块不在 macOS 编译。

## 私有路径与原生验证

macOS 的 `/tmp` 通常是指向 `/private/tmp` 的符号链接。私有文件 API 要求绝对物理路径，并拒绝路径中任何符号链接。先将测试临时根解析为物理路径，再运行：

```sh
export TMPDIR="$(cd "${TMPDIR:-/private/tmp}" && pwd -P)"
cargo +1.99.0 test --locked -p xcsc --all-targets --all-features
cargo +1.99.0 clippy --locked -p xcsc --all-targets --all-features -- -D warnings
bash scripts/test-apple-sandbox.sh
```

沙箱脚本构建 `apple_sandbox` 示例，在临时容器中验证不能读取外部祖先目录时仍可打开、写入、重读容器状态，并拒绝符号链接。成功会输出 `Apple sandbox storage and symlink rejection passed`。脚本只验证库机制；产品的 App Sandbox、entitlement 与 launchd 环境还需分别测试。

## 平台排障

- 私有目录打开失败：核对物理路径、父目录是否存在、当前 uid 和最终目录 `0700` 权限。
- 沙箱中拒绝访问：使用产品被授权的容器路径；不要通过扩大沙箱权限或绕过链接检查来代替定位。
- 前台成功而后台失败：在产品实际 launchd 身份和环境中重现，检查产品选择的状态目录与可执行路径。
- 文件发布后同步错误：按[文件系统参考](../filesystem-handles.md#原子发布与锁)核对已发布状态，再决定恢复或重试。

公共提交检查见[开发指南](../development.md)，业务投递和状态问题见[共同排障](../troubleshooting.md)。

[模块使用](../usage.md) · [选择其他平台](../README.md#选择接入平台)
