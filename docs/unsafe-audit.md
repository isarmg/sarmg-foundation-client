# 依赖和 unsafe 审查

本轮采用 [Rust 1.99.0 正式版](https://blog.rust-lang.org/2026/10/01/Rust-1.99.0/)。现有工具链已是截至 2026-10-07 的最新稳定版，因此保持精确版本，不改为 nightly。Tokio 使用经过本轮构建和行为测试的稳定 `~1.53.2`；版本依据见 [上游发布页](https://github.com/tokio-rs/tokio/releases/tag/tokio-1.53.2)。AES-GCM 0.11.1、HKDF 0.13、Rustix 1.1.5、JNI 0.22.4 继续保留同一代稳定 API，libc、UUID 与 zeroize 提升到当前兼容补丁，实际解析及校验和由根 Cargo.lock 固定。

Rust 实现为根目录唯一 `xcsc` 包，模块位于 `src/<模块>/`，只保留根 Cargo.toml 和 Cargo.lock；不存在独立子包或工作区外壳。CLI 根模块负责参数、错误和输出组合，`terminal.rs` 负责有界控制终端输入与模式恢复，`elevation.rs` 负责 Windows UAC/句柄，`service.rs` 负责系统服务与共享进程捕获，`tail.rs` 负责受预算约束的日志尾读取。产品机制不反向进入 xcsc。

CLI 已删除 crate 级 `allow(unsafe_code)`。根包的 `unsafe_code = deny` 仍有效，仅 `terminal`、Windows `elevation`、Windows 编辑器参数解析函数与构造真实终端的测试局部允许。单体合并只迁移既有原生调用；Windows 日志和离线 SQLite 的必要原生边界连同原安全前提及回归进入相应模块，没有放宽 unsafe 门禁。其必要性及前置条件沿用 [逐函数记录](unsafe-review-0.10.0.md)：信号/控制终端、UAC、ACL/Token/SID、平台本机对端身份以及 C ABI 原始输入与结果所有权均是标准库无等价功能的边界。业务逻辑、服务进程捕获与普通文件字节 I/O 使用安全 API。

Windows terminal、token 和提权进程改由标准库 `OwnedHandle` 管理，删除自定义 `CloseHandle` Drop。接管原始句柄仍需一个局部 unsafe 块，前提是 CreateFileW、OpenProcessToken 或 ShellExecuteExW 已成功且转移唯一所有权。借用句柄只在所有者存活时调用；控制台模式守卫先恢复模式再关闭 input。Windows 完整 CLI、文件与 runtime 含测试源码已通过严格交叉 Clippy。

服务文件 ACL 验证要求 SYSTEM/Administrators、所选 SCM SID 与 OWNER RIGHTS 的完整精确四项授权，不接受缺失 OWNER RIGHTS、掩码子集或超集、重复授权和无效继承标志。服务后代的 NULL security attributes 创建只在持有并复验的同策略私有父链内进行，保护锚还必须保持 protected 和可信 SYSTEM/Administrators/唯一服务 SID 属主；普通用户 protected 策略不变，生产入口不修改权限。打开与每次操作均复验固定锚至目标的所有私有段，不把 ambient 默认权限当作可信来源，不在创建失败后切换策略。新根创建前只查询实际有效 TokenOwner：先取线程令牌，仅 ERROR_NO_TOKEN 使用主令牌；SDK 输出使用对齐、有界存储且转换期间保留令牌和 SID 生命周期。该查询不改变令牌，也不增加生产 NtCreateFile 调用。

新增原生测试只在隔离物理文件中使用 SDK 分配的描述符和真实派生线程令牌；根的 Administrators 属主显式由测试设置，文件在真实派生令牌以真实 CI 用户默认属主创建时就获得继承 ACL，测试不再依赖创建后改属主是否保留 OWNER RIGHTS 的未证实行为。guard 持有派生 token，恢复线程身份后才关闭句柄；对齐、有界 SDK 输出保留至 SID 比较结束，后续管理员授权被禁用且不增加 restricting SID，避免把第二次限制检查误当成属主 WRITE_DAC 被抑制。测试返回前核物理属主、完整有效 ACL 和公共 verify；失败只输出隔离描述符和授权掩码，不输出业务内容。属主负测的管理员控制明确恢复并核对测试夹具精确 DACL，排除 ACL 变化混淆。实际 ACL 改写仅为隔离测试初始化、变异或阳性控制，生产不修复 ACL。Windows 测试按平台职责放在 `src/fs_safety/windows/tests.rs`，同模块私有访问和测试名称保留。这一组新 Windows 行为的执行证据必须来自对应源码的原生 CI；Mac 和 GNU 交叉检查只证明各自范围，消费方仍须证明真实 SCM 服务生命周期。

Unix 私有锁守卫以安全的 `File::unlock` 在销毁时先解锁再关闭独立文件描述符；锁成功后立即由守卫接管，后续复验或同步错误同样释放。锁文件保持原 inode，Windows 锁策略不变。真实同打开文件描述的重复描述符回归覆盖旧守卫销毁后的重新获取，以及关闭旧描述符不会解锁新守卫。Linux 关闭队列后重开的 `AlreadyRunning` 失败与 fork 继承锁的已知机制相符，但该次 CI 的精确 fork 时序未被观测；本机受控 fork 仅证明机制，不能代替 Linux 最终源码回归。独立 `linux::AdvisoryLock::directory` API 复制调用方的目录描述符，不具有此处独立打开的锁文件所有权，本轮不改变其释放策略。此修复不增加 unsafe，也不通过重试或串行化测试隐藏竞争。

服务命令的两个读取线程和无界 join 已被共享 `capture_bounded` 替代。新增真实子进程测试覆盖“父进程已退出，后台子进程仍持有 pipe”及现有 Tokio 内同步调用，明确验证输出、退出码与期限。它不宣称终止任意独立后代进程：超时关闭捕获管道并回收直接 child，执行的是固定系统管理器。

macOS 的成功 `bootout` 与后续卸载观察共享原操作期限：只有实际服务定义不存在才完成，仍加载的 `SIGTERMed` 状态继续观察，未知非零退出和捕获错误明确拒绝。卸载观察中的 timeout 统一报告 `service_state_unconfirmed`，`bootout` 命令自身的 timeout 仍保留 `service_timeout`。此同步修正没有新增 unsafe、产品分支或依赖，也不重试失败的服务动作；禁用后一次性启动的策略恢复不变。真实临时 Background LaunchAgent 使用 `user/<uid>` 域核对立即重载和期限，原有 pipe 测试保持，服务测试归 `service/tests.rs`。消费者完整 system-domain 安装及启动策略仍须在其最终源码原生验收，不由用户域回归替代。

本机 Mac 验证必须使用实际物理临时路径（例如 `TMPDIR=/private/tmp`）；`/var` 的符号链接别名会被不跟随链接安全检查正确拒绝。原生终端测试需要访问一次性 PTY，不能用受限沙箱的权限失败代表程序回归。Windows、Linux、Android/iOS 与真实 JVM 是否通过，由对应最终源码工作流单独证明。

## 当前候选工程约束

候选准备发行；正式状态以 Git tag、最终源码工作流和 Release 产物为准。Rust 1.99.0 是截至 2026-10-07 的当前正式版；Tokio 选择稳定的 ~1.53.2，兼容补丁由根 Cargo.lock 锁定。unsafe 函数内的原始解引用和外部函数调用必须放进显式 unsafe 块（unsafe_op_in_unsafe_fn = deny）。这项约束检查操作边界，不替代原生 ABI、权限与生命周期验证。正式输入和用户数据身份分开记录，不通过发行号推导持久状态。

消费者源码约束现在核对声明的 xcsc 版本、全部 normal/build/dev/target/workspace/patch 依赖的精确版本和单一官方完整 revision，防止清单与实际输入漂移。Mac 的符号链接祖先只在已选项目根处归一化一次；源码自身的符号链接仍拒绝。

## 统一规范适用条款验收

| 条款 | 本轮实施或已有实际边界 | 验证范围 |
|---|---|---|
| 2–4：公共职责、依赖方向与结构 | xcsc 只提供通用 CLI、进程、私有文件、锁、秘密和移动 FFI 机制；产品任务、协议和授权仍由产品拥有。CLI 按终端、提权、服务、尾读职责分模块，不按产品创建分支。 | 源码检查器拒绝服务端业务包、目录逃逸和未授权 ABI owner；日志和错误原语属于 xcsc 自身；消费者核对唯一公共包的官方源码身份。 |
| 5–8：身份、错误和安全 | 软件版本、Profile/ABI、任务及数据身份分别校验；错误有固定 code，输出会脱敏；原生块约束指针、长度、生命周期与句柄所有权。 | 单包 Rust 行为测试；源、清单、版本和所有者的 23 个 Python 用例；Windows 本机身份不由 Mac 结果推导。 |
| 9、11–14：CLI、生命周期和预算 | 公共核心命令结构及有界终端输入/日志尾读保持原 API；管理器输出和退出共享 timeout；不跟随链接、原子提交和锁不削弱。产品决定授权、任务完成与恢复。 | 本机 macOS 默认工作区 113 个 Rust 用例，包括真实终端、子进程 pipe、Background LaunchAgent、私有目录、原子恢复及并发/锁行为；4 个 helper 由父用例调用。 |
| 15–16：日志与界面 | 提供中性错误/输出结构；产品事件、实例身份和界面归产品，xcsc 不承载管理 Web UI。 | 下游 source 检查与产品行为测试；不添加后台服务端依赖。 |
| 19–24：输入、发行、测试与文档 | 单根 Cargo.toml/Cargo.lock、精确 Rust 1.99.0、唯一包 xcsc；源码约束校验所有消费方完整官方 Git revision 与 manifest 版本一致。历史审查与当前职责记录保留。 | fmt、严格 Clippy、Mac Rust/Python、iOS 模拟器库检查已通过；原生 CI、真实 JVM 与实际发行物仍分别验收。 |

这份记录只说明公共层的适用条款。产品的摄像头适配、WSS 管理能力、媒体队列和用户安装路径由各产品的验收记录负责，不将公共单元测试视作完整产品验证。

1.0.0 的有界退出等待复用可取消的 Tokio `Child::wait`，每 25 ms 重新轮询以处理继承屏蔽的 `SIGCHLD`；生产实现没有新增 unsafe。Unix 回归的 `pre_exec` 仅在独立测试子进程中通过 async-signal-safe 调用设置信号掩码，并逐步检查错误，不修改并行测试 runner。持久化队列只读检查复用已有管理目录策略，保留不跟随链接和私有权限验证；root 原生回归比较服务属主测试夹具的 inode、属主、权限及内容，并覆盖链接、公开目录和缺失目录拒绝。

单体结构、客户端日志归属和 Linux 离线维护功能开关的当前约束见[单体说明](monolithic-client.md)。以上历史 macOS 113 项、Python 23 项及交叉检查只记录对应原始源码的事实，不作为当前单体最终验收证据；当前结果由本次最终源码测试和原生 CI 分别记录。

Linux 离线 `state_file` 锁采用私有 RAII guard，在 flock 成功后、身份复验前接管；隐式退出及复验失败显式解开原描述符锁，防止 fork/dup 别名暂存使维护仍被占用。显式交接成功标记不再持锁，避免 Drop 再次解开别名后来取得的新锁。使用安全的 `File::unlock`，不增加 unsafe；回归核对真实同描述符别名、实例/维护双锁、inode与属主权限不变，以及旧 inode 复验失败不会释放替换 inode 上的新 guard。

Windows 编辑器命令解析使用 `CommandLineToArgvW`，因为标准库不提供原生参数拆分。输入保留 UTF-16，拒绝内嵌 NUL；空输入不调用会回退到当前可执行文件的原生 API。成功返回的参数数组和每个 NUL 结尾字符串在唯一 allocation guard 存活期间复制到 `OsString`，随后由 `LocalFree` 释放一次；所有退出路径均由 guard 管理。Unix 使用已有锁定依赖 `shlex` 的字节解析 API，不增加 unsafe。两端都不执行 shell，临时文件路径作为独立参数追加。
