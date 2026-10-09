# 有界子进程捕获

当前源码提供 `xcsc_runtime::process::capture_bounded`。正式消费者须固定实际正式发行的完整 Git revision 和精确 crate 版本；原生 CI 与发行物分别按最终 Source 核验。

产品选择要执行的程序与参数；xcsc 不识别 ffprobe、摄像头或具体产品。输入为 `&mut tokio::process::Command` 与 `ProcessLimits { timeout, stdout_bytes, stderr_bytes }`。时间必须在 0–600 秒内且大于零，每个管道预算必须为 1–4 MiB。stdin关闭，stdout/stderr分别限量并发读取，子进程退出码和原始有界输出通过标准 `Output` 返回；非零退出是否属于业务失败由产品判定。

超时、任一管道越限或读取/等待失败均停止捕获，kill并wait回收子进程，再返回 typed `ProcessCaptureError`。错误只携带类型、流名称或 `io::ErrorKind`，不把原始stderr、命令参数或凭据写进普通诊断。返回输出字节仍可能包含敏感信息，产品不得直接打印内部错误链或设备凭据。

取消整个调用future时，`kill_on_drop` 请求停止仍持有的子进程；这与已执行kill/wait的超时/越限分支不同。产品的受控shutdown仍应等待自己的调用结束，并明确关闭期限；不能把请求取消立即报告为业务已停止。

行为测试实际启动子进程，检查双管道、输出和非零退出码保留，以及stdout/stderr超限和超时后PID不再运行或等待回收。Unix双管道测试纳入macOS runtime CI；Windows runtime CI编译和执行其适用测试。各平台执行证据按最终 Source 分别记录，不能以 portable API 或单个平台结果代替原生支持证明。

CLI 的系统服务查询与控制复用这一实现。同步 Service 入口使用独立当前线程 reactor，以避免在已有 Tokio 调用方里嵌套 runtime；父管理器退出后的 pipe EOF 也受同一 deadline 约束，后台后代持有管道不会阻止返回。

管理员启动器可能继承屏蔽的 `SIGCHLD`。退出等待保留信号唤醒，并每 25 ms 重新轮询可取消的 `Child::wait`，正常捕获及失败后的回收均使用同一机制，避免已退出的子进程依赖被屏蔽的信号。Unix 回归仅在独立测试子进程中屏蔽该信号，检查退出码、输出和超时后的实际 PID 回收；不会修改并行测试 runner 的信号掩码。

macOS `bootout` 返回后仍可能有加载中的 `SIGTERMed` 定义；停止和 `disable --now` 在原操作 deadline 内确认定义实际移除。每次 `launchctl print` 只使用剩余时间，观察超时返回 `service_state_unconfirmed`，其他错误保留明确失败；不延长期限、重试失败动作或改变一次性启动的原有启动策略。真实 Background LaunchAgent 回归在 `user/<uid>` 域运行，清理自己的定义，产品仍使用固定 system 域。
