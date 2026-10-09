# xcsc 文档总览

本文档集描述当前 `1.0.0` 源码；正式发行状态以对应 Source、Git tag 与 Release 资产为准。xcsc 提供产品中立的 Client 机制；业务协议、产品状态和用户界面
仍由各产品仓库拥有。发布说明记录历史版本，不能替代当前 API 与 Profile。

| 文档 | 内容 |
|---|---|
| [xcsc 边界](xcsc-boundary.md) | Server xcss、Client xcsc 与产品 Adapter 的职责 |
| [单体 Client](monolithic-client.md) | 唯一根 Cargo package、模块映射、features、离线工具和验证命令 |
| [Client Web 边界](client-web.md) | 按被管理对象划分 Web 所属，以及当前无本机 Web 消费者的事实 |
| [有界子进程捕获](bounded-process.md) | 双管道限量读取、超时、杀进程与回收、平台验证范围 |
| [Spool](client-spool.md) | 容器、容量、隔离、投递、退避、关闭与单实例会话 |
| [Client identity](client-identity.md) | 运行身份、凭据快照及产品 Adapter 契约 |
| [Credential transactions](credential-transactions.md) | 短事务接口、轮换和失效的并发语义 |
| [Filesystem handles](filesystem-handles.md) | Unix/Linux 句柄边界、配置读取和跨平台验收限制 |
| [Windows 私有状态](windows-private-state.md) | 原生 ACL、owned file guard、SCM SID 与原子名称 |
| [依赖与 unsafe 审查](unsafe-audit.md) | 当前版本选择、模块边界与验证限制 |
| [0.10.0 unsafe 审查](unsafe-review-0.10.0.md) | 保留的原生调用逐函数前置条件与必要性 |
| [Mobile FFI](mobile-ffi.md) | ABI 1、结果所有权、句柄、JNI 与验证范围 |
| [仓库与发布来源](split-origin.md) | 独立仓库、源码版本与发布制品 |

机器可检查的 Profile 与能力事实源位于 `profiles/`，产品清单格式位于
`schemas/xcsc-client.schema.json`。使用方必须同时固定精确 crate 版本和 Git revision。
