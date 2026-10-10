# Windows：原生库接入与验证

正式目标为 `x86_64-pc-windows-msvc`。xcsc 提供可编译进产品的库；安装器、SCM 服务名和账户由具体客户端决定。先按[开始接入](../getting-started.md)固定依赖并声明 `desktop-client` 能力。

## 工具链与原生测试

准备 Rust `1.99.0` MSVC 工具链、Visual Studio C++ Build Tools/Windows SDK、Python 3。在原生 x64 开发终端进入 xcsc 仓库，使用 PowerShell 执行：

```powershell
rustup target add --toolchain 1.99.0 x86_64-pc-windows-msvc
cargo +1.99.0 check --locked -p xcsc --target x86_64-pc-windows-msvc
cargo +1.99.0 test --locked -p xcsc --all-targets --all-features
cargo +1.99.0 clippy --locked -p xcsc --all-targets --all-features -- -D warnings
```

原生测试验证 Windows 句柄、ACL、受限令牌访问、日志轮转与持久化队列。`--all-features` 不会在 Windows 编译 Linux 离线 SQLite 模块。公共 Python、格式及文档检查见[开发指南](../development.md)。

## 选择私有状态策略

- 当前用户程序选择 `WindowsPrivateAccess::for_current_user`。
- SCM 服务产品按自己的确切服务 SID 和账户选择 `for_service`；该身份来自产品真实 SCM 定义。
- 需要内建账户文件访问的产品按接口条件使用 `for_service_account`，不把共享账户身份视为任意目录都可信。
- 将策略传给 `PrivateDirectory::create_with_windows_access` 或 `open_with_windows_access`，后续子目录和会话保留该策略。

完整 ACE、保护锚与继承规则只维护在[Windows 私有状态](../windows-private-state.md)。产品须在安装阶段按所选策略置备目录；公共库不会修改现有不安全 DACL。

## 路径与故障检查

1. 使用完整本地 DOS 驱动器路径，或系统规范化的 verbatim drive 路径；不要以相对路径、共享网络目录或 reparse point 代替私有目录。
2. 访问被拒绝时核对实际进程令牌、服务 SID、属主、DACL 与受保护根。保留当前文件和权限，按产品安装/恢复流程处理。
3. 文件打开失败还要检查多硬链接与句柄生命周期。SQLx 主数据库守卫应在连接显式关闭后释放；临时回滚日志守卫不能跨提交长期持有。
4. SCM 启动或日志问题在产品仓库重现；xcsc 的库测试不会创建和验收每个消费产品的真实服务。

`PublishedDurabilityUnknown`、队列与凭据故障见[共同排障](../troubleshooting.md)。验证应记录原生 Windows 结果，而非仅记录交叉编译成功。

[模块使用](../usage.md) · [选择其他平台](../README.md#选择接入平台)
