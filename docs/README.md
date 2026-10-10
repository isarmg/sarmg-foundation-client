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
