# 排查问题

先保留错误码、目标平台、xcsc 版本和失败操作。日志中的令牌、凭据、原始载荷和用户私有路径按需要脱敏。平台工具链、文件权限和原生集成问题按 [Linux](platforms/linux.md#运行身份与排障)、[Windows](platforms/windows.md#路径与故障检查)、[macOS](platforms/macos.md#平台排障)、[Android](platforms/android.md#集成顺序与排障)或 [iOS](platforms/ios.md#沙箱路径与故障检查)查阅。

| 现象 | 检查和处理 |
|---|---|
| 消费检查报告依赖来源不同 | 检查产品所有 Cargo 清单、工作区继承、patch/replace 和 `Cargo.lock`，统一精确版本与完整官方 Git revision |
| 能力或预算字段缺失 | 对照所选 profile；`bounded-spool` 同时填写三个 `client_limits` 值 |
| 私有目录打开失败 | 确认绝对物理路径、现有父目录、实际运行身份和权限；Windows 同时核对服务 SID 与 ACL |
| `AlreadyRunning` | 找到正在使用同一状态目录的实例，正常关闭后再启动；保留稳定锁文件 |
| 队列已满 | 查看 `spool_bytes`、条目数和隔离数；恢复投递或按产品流程处理隔离记录 |
| 授权更新后仍有拒绝 | 比较请求捕获的凭据修订与当前修订，检查产品事务适配器是否保留新凭据 |
| `PublishedDurabilityUnknown` | 文件已发布而目录同步失败；先按产品恢复流程检查实际状态，再决定重试 |
| JNI 返回哨兵或 C ABI 返回失败 | 同时检查 Java 异常或 ABI 结果状态；核对长度、句柄代次和结果所有权 |
| 子进程超时或输出超限 | 核对 `ProcessLimits` 与所执行程序；调用返回前会处理直接子进程的停止和回收 |

具体 API 条件见[专题参考](reference/README.md)。如需报告问题，附最小复现、平台及工具链版本、失败测试名称和脱敏输出，并说明是否在目标原生平台重现。
