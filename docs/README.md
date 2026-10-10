# xcsc 文档总览

本文档集描述当前 `1.0.0` 源码；正式发行状态以对应源码、Git tag 与 Release 资产为准。xcsc 提供产品中立的客户端机制；业务协议、产品状态和用户界面
仍由各产品仓库拥有。发布说明记录历史版本，不能替代当前 API 与能力配置。

| 文档 | 内容 |
|---|---|
| [xcsc 边界](xcsc-boundary.md) | 客户端 xcsc 与产品适配器的职责 |
| [单体客户端](monolithic-client.md) | 唯一根 Cargo 包、模块映射、功能开关、离线工具和验证命令 |
| [客户端 Web 边界](client-web.md) | 按被管理对象划分 Web 所属，以及当前无本机 Web 消费者的事实 |
| [有界子进程捕获](bounded-process.md) | 双管道限量读取、超时、杀进程与回收、平台验证范围 |
| [Spool](client-spool.md) | 容器、容量、隔离、投递、退避、关闭与单实例会话 |
| [客户端身份](client-identity.md) | 运行身份、凭据快照及产品适配器契约 |
| [凭据事务](credential-transactions.md) | 短事务接口、轮换和失效的并发语义 |
| [文件系统句柄](filesystem-handles.md) | Unix/Linux 句柄边界、配置读取和跨平台验收限制 |
| [Windows 私有状态](windows-private-state.md) | 原生 ACL、拥有文件所有权的守卫、SCM SID 与原子名称 |
| [依赖与 unsafe 审查](unsafe-audit.md) | 当前版本选择、模块边界与验证限制 |
| [0.10.0 unsafe 审查](unsafe-review-0.10.0.md) | 保留的原生调用逐函数前置条件与必要性 |
| [移动 FFI](mobile-ffi.md) | ABI 1、结果所有权、句柄、JNI 与验证范围 |
| [仓库与发布来源](split-origin.md) | 独立仓库、源码版本与发布制品 |

机器可检查的能力配置与能力事实源位于 `profiles/`，产品清单格式位于
`schemas/xcsc-client.schema.json`。使用方必须同时固定精确 crate 版本和 Git revision。

## 接入、部署与验证边界

xcsc `1.0.0` 的 CLI、运行时、文件安全、秘密、XML、移动 FFI 与便携日志由唯一根 `Cargo.toml` 和 `Cargo.lock` 承载。日志和错误原语在本仓库独立维护、测试与发布；产品继续拥有业务协议、状态机和界面。它是由产品编译链接的库，没有独立安装、配对或启停的系统服务，升级须由产品更新固定依赖后重新发行。

设备用户按各产品指南操作：[xsoc](https://github.com/isarmg/xsoc/blob/main/docs/platform-setup.md)、[xscc](https://github.com/isarmg/xscc/blob/main/docs/platform-setup.md)、[xcoc](https://github.com/isarmg/xcoc/blob/main/docs/platform-setup.md)、[xszc](https://github.com/isarmg/xszc/blob/main/docs/platform-setup.md)。具体平台以对应产品的实际发行物为准。

产品在根目录维护 `xcsc-client.toml`，声明版本、`desktop-client` / `mobile-client` / `offline-maintenance` 能力配置、能力和检查范围；平台与能力事实源见 [`profiles/`](../profiles/)。消费依赖必须固定精确 crate 版本与完整官方 Git revision，不使用相邻目录路径依赖：

```sh
python3 scripts/check-xcsc.py --product-root /absolute/path/to/product
```

Rust 工具链固定 `1.99.0`；完整开发检查见[单体客户端](monolithic-client.md#开发检查)。通用 Rust 测试不能替代 Android、iOS、Windows、macOS 的原生 CI 与实际交付验收。

[1.0.0 发布说明](releases/1.0.0.md)记录有界子进程捕获在继承屏蔽退出信号时的回收修复，以及 Unix root 对服务账户私有持久化队列的只读检查。当前 C ABI 为修订 1，结果类型与释放函数使用 `V1` / `_v1` 身份，原生调用安全边界见 [unsafe 审查](unsafe-audit.md)。

消费检查区分移动端 ABI 导出 crate 的 panic 翻译、普通业务库、SQLite 私有回调与风险测试；导出 crate 的所有 helper 仍须复用公共 FFI guard。在全部声明源码中拒绝重复实现 HandleRegistry、C 字符串读取、guard_value 与 LAST_ERROR。

代码采用 [Apache License 2.0](../LICENSE)。
