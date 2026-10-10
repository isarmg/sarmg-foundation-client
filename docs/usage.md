# 使用公共模块

按产品需要接入相应模块。函数和类型的完整说明可用 `cargo doc --locked --all-features --no-deps --open` 在本地查阅。

## 身份与凭据

1. 用 `ClientIdentity` 固定产品、实例和载荷合同。
2. 实现 `CredentialStore`，在短事务中一致读取身份、修订号和秘密，形成 `CredentialSnapshot`。
3. 在事务外发送请求，让整个请求持有同一快照。
4. 对延迟到达的授权拒绝，按快照修订号调用失效处理，保留已更新的凭据。

身份不匹配的本地记录进入隔离区，保留原始字节供产品诊断。接口语义和并发例子见[客户端身份](client-identity.md)与[凭据事务](credential-transactions.md)。

## 私有文件与队列

1. 选择产品实际状态目录，以服务或应用身份打开 `PrivateDirectory`。
2. 在开始投递和采集前取得 `ClientSession`，持有至工作器关闭。
3. 使用配置中的 `SpoolLimits` 创建队列，交给产品编解码器生成有限大小的载荷。
4. 通过 `DeliveryWorker` 和产品驱动处理投递、重试与授权更新。
5. 关闭时等待正在管理的工作结束，然后释放会话。

Unix 最终私有目录为 `0700`，私有文件为 `0600`，属主与实际服务身份一致。公共 API 校验既有权限；遇到权限错误先核对路径和身份，避免直接扩大权限。Windows 按产品 SCM 身份选择[私有状态策略](windows-private-state.md)。

只读状态页可用 `Spool::inspect_existing`，或对已打开的目录调用 `inspect_directory`。它报告容量和隔离数量；载荷完整性验证在读取投递记录时完成。详见[文件 API](filesystem-handles.md)和[队列参考](client-spool.md)。

## 运行子进程

将产品选择的 `tokio::process::Command` 和 `ProcessLimits` 传给 `capture_bounded`。为超时、stdout 和 stderr 分别设置预算，检查退出状态，再由产品解释输出。输出可能含凭据，日志只记录需要的脱敏摘要。参数范围与取消行为见[有界子进程](bounded-process.md)。

## 移动宿主

- Rust 导出复用 `xcsc::mobile_ffi` 的 guard、句柄和结果类型
- Swift 通过生成的 C 头导入；结果在原存储位置调用 `xcsc_ffi_result_free_v1` 释放
- Android 通过 `jni` guard 处理调用帧、字符串预算与 Java 异常
- 在目标设备验证打开、正常请求、取消、关闭及重新打开

ABI 所有权和错误映射见[移动 FFI](mobile-ffi.md)。
