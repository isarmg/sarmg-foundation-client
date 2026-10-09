> 项目名称已规范化，版本、提交、摘要及验收状态保持历史记录，不作为当前验收证据。未经规范化的原始文本仅保存在本次工作区审计备份中；本文件不是逐字原始记录。

# xcsc 0.10.0 unsafe review

范围是本仓库 owned Rust normal/build/dev 源码，第三方依赖由锁文件及其维护者负责。本记录按函数审查能力和前置条件；最终完整 Source SHA、语法 AST 与实际平台结果记录在发行收据，不能把工作树结果当作另一版本的验证。

## 删除可安全替代的机制

Linux `local_status::trusted` 使用 `rustix::net::sockopt::socket_peercred`，删除 `getsockopt`、raw FD 与初始化结构 FFI。Unix `UnixTerminalMode` 与 `unix_terminal_input` 使用 Rustix 的借用 FD、termios、poll 和 read，不再自制 raw `tcgetattr/tcsetattr/poll/read`。Windows named pipe 的字节读取与写入使用 `std::io::{Read,Write}`，只保留 pipe 建立、身份查询和状态控制的 SDK 接口；`last_os_error` 替代额外 `GetLastError` 调用。JNI 生产入口使用 JNI 0.22 的 `EnvUnowned::with_env` 和安全局部对象，不从原始指针手工构造 Env。

## Filesystem Windows SDK

| 函数 | 必要调用、前置条件与所有权 | 替代与验证边界 |
|---|---|---|
| `service_sid` | `RtlUpcaseUnicodeChar` 按值转换一个 UTF-16 单元；不保存指针。先拒空名、NUL、分隔符和超 256 单元。 | Rust Unicode uppercase 的扩展字符语义不能替代 SCM invariant 映射。真实 `sc.exe showsid` 核大小写与非 ASCII。SHA-1 仅是 SCM 标识协议。 |
| `process_token` | `OpenProcessToken` 成功后将唯一 owned handle 转给 File；失败不构造 File。当前进程 pseudo handle不关闭。 | std 不暴露 TokenUser/TokenGroups。进程主令牌身份不等同线程 impersonation。 |
| `token_information` | 二段 SDK 查询；字节预算 64 KiB，初始化 u64 对齐 allocation，成功后才解释 SDK 输出。 | 系统提供的固定信息布局与内部 SID 指针是 SDK 前置条件；不接受调用者提供的原始 token buffer。 |
| `token_user_sid` | 完整 `TOKEN_USER` 大小先检查，SDK SID 指针在 held allocation 活着时转换。 | `process_user_sid` 只读，不改变准入 policy。 |
| `WindowsPrivateAccess::current_process` | 先安全读取 GroupCount、验证完整 SID_AND_ATTRIBUTES 数组 extent，再构造 slice。只接 token enabled 且非 deny-only 的确切五段 service SID。 | 拒绝 ALL SERVICES；产品显式 policy 不扩展任意账户或组。 |
| `WindowsPrivateAccess::descriptor` | NUL 结尾固定 policy SDDL 交 SDK 分配；Allocation唯一持有成功返回的 local memory。 | 不能用继承 ACL 再修复替代原子私有创建。 |
| `Allocation::drop` | 对 SDK 明确交付的 LocalAlloc 指针恰好 LocalFree 一次。 | std allocator不能释放 SDK allocation。 |
| `sid_text` | private unsafe 函数只接 SDK live SID；先判空/IsValidSid。转换结果 LocalFree RAII，UTF-16 scan最多256单元。 | 任意 foreign SID pointer不能由 wrapper证明可读；本函数不公开该输入。 |
| `verify_acl` | 成功 GetSecurityInfo descriptor RAII持有；owner/DACL非空、DACL受保护、ACE类型/最小头/variable SID extent检查后解释允许项。 | std 无 owner/DACL introspection。未知 ACE、继承外部访问和非授权主体拒绝；确切 service只有Modify，OWNER RIGHTS只有READ_CONTROL。 |
| `verify_kind` | 活着的 File handle，初始化 BY_HANDLE_FILE_INFORMATION 输出，成功后检查reparse/目录种类/单链接。 | path metadata不足以保证打开对象类型与link count。 |
| `open_directory` | CreateDirectory/受保护描述符和已持有物理祖先；新目录初始化不产生继承宽松ACL窗口。 | 既有不安全对象拒绝、不修复。 |
| `create_file` | CREATE_NEW、NUL路径、显式SD、安全父目录；成功后唯一File ownership并再次检查对象。 | 普通临时文件继承ACL不能满足私有创建。 |
| `mark_deleted` | SetFileInformationByHandle作用于已检查且DELETE-authorized File，初始化固定disposition结构。 | 路径unlink存在替换对象窗口。 |
| `rename` | 活着的安全临时File；u64对齐variable FILE_RENAME_INFO allocation覆盖完整头和UTF-16 NUL，长度不含NUL；不重叠copy。 | 不删除目标再rename；NoReplace仍由原子native操作保障。现有parent/leaf句柄不共享DELETE。名称替换原生负测是必需门。 |
| `WindowsPrivateFile` | 本 API 无unsafe；复制已持目录/祖先File句柄和policy，leaf guard可独立own。 | 仅Windows；Unix额外同inodeFD关闭可能释放POSIX锁，不能机械照搬。SQLx连接必须先显式关闭，DELETE journal不能跨commit持no-delete guard。 |

## CLI 和 IPC

| 函数 | 必要性与前置条件 | 实际边界 |
|---|---|---|
| `OwnedWindowsHandle::drop` | 仅接成功SDK交付的唯一handle，CloseHandle一次。 | 不接pseudo handle，无重复close。 |
| `windows_is_elevated` | 初始化固定TOKEN_ELEVATION输出，检查returned完整大小，ownedtoken始终live。 | elevation查询是观察，实际执行仍需OS授权。 |
| `windows_relaunch_elevated` | ShellExecuteExW的NUL verb/exe/argv全部live；成功processhandle RAII，bounded Wait和GetExitCodeProcess输出初始化。 | std::process不提供UAC runas；时间到只返回拒绝，不能声称已经终止管理员child。 |
| `TerminalSignalGuard::install/drop` | libc sigaction需要portable Linux/Darwin C布局；全零有效、sigemptyset、固定handler只写atomic；已有action被完整保存，Drop逆序恢复。 | Rustix kernel_sigaction不适合跨Darwin替代。interactive输入被串行化，PTy实测取消、预算、无回显与模式恢复。 |
| `open_console/write_console` | 固定CONIN$/CONOUT$、NUL文本和唯一ownedhandle；UTF-16 slice完整live，written必须等于len。 | 普通stdin重定向不保证私密交互；std没有等效Windows console event/mode API。 |
| `WindowsConsoleMode::drop/windows_terminal_input` | 模式在ownedinput生命周期内恢复；fixed initialized INPUT_RECORD输出，先KEY_EVENT判别再读union，keyboard UnicodeChar解释在合法键事件内。 | timeout/cancel/bodybudget和surrogate检查；不能把native编译当作真实交互测试。 |
| Darwin `local_status::trusted` | 活UnixStream与初始化uid/gid输出；getpeereid失败即拒。 | Rustix目前没有Darwin等价peercred接口；nativeAppleCI实际状态测试。 |
| Windows `trusted` | process/token的唯一File RAII、bounded alignedTokenUser、完整结构与image长度检查、SDK SID在tokenbuffer内live。 | std无process token/image查询；系统服务身份或elevated token且准确image才接收response，失败不回退授权。 |
| Windows `publish` | 固定local-only namedpipe/DACL、SDKdescriptor LocalFree、File唯一own pipe并移入worker，所有SDKoutput live。 | FIRST_PIPE_INSTANCE+REJECT_REMOTE_CLIENTS；半秒消息/ack预算。只有安全字节I/O使用std，pipe控制SDK必要。 |
| Windows `read` | fixed pipe名、identification SQOS、先真实serverPID/服务身份/image检查，initializedoutparams，固定byte mode。 | std无pipe serverPID；最多32KiB响应与半秒deadline，binding mismatch拒绝。此标识不是跨机器网络认证。 |

## Mobile ABI

| 函数 | 必要性与前置条件 | 验证与不能证明的内容 |
|---|---|---|
| `guard` | FFI host须提供有效aligned、独占可写result storage；检查空/alignment后初始化，执行在panic边界内。 | 无法证明任意nonnull外部地址可写；不得伪称普通类型检查能证明foreignallocation。 |
| `checked_input/checked_utf8` | null只允许长度0；最大16MiB、usize/isize界限后from_raw_parts，strictUTF8。 | host需保证borrowedallocation在调用全过程live、没有并发变更；safe Rust slice替代不了C输入。 |
| `xcsc_ffi_result_free_v1` | 接由sharedguard初始化且未复制的result；仅对ownedbytes还原Box<[u8]>；释放后将storage重置。no_mangle是稳定ABI符号要求。 | 重复释放原storage可幂等，复制ownedresult后双free是host违约。真实C/产品mobile执行单独记录。 |
| JNI `guard/read_string/new_string` | 生产路径无ownedunsafe；EnvUnowned通过nativeframe scope借Env，安全JString/JCharArray API；UTF16units先限量再分配，strictsurrogate和最终UTF8限量。 | 实际固定JVM -Xcheck:jni验证emoji/NUL、bytebudget、原异常身份、class、panic脱敏和后续可用。 |
| `native_jvm_keeps_unicode_budgets_pending_exceptions_and_public_errors` | 仅测试from_raw：VM已attach当前thread，borrow限在其liveframe，不detach/逃逸。 | native CI显式执行ignoredtest；不能将普通suite的ignored行当通过证据。 |

Test-only PTY `run_prompt_child` 的 openpty/from_raw_fd、setsid/TIOCSCTTY/tcsetpgrp只运行于受控child，owned File接各成功FD一次，termios与poll输出初始化。这些调用构造真实控制终端与恢复证据，不能由mock代替。FIFO负测只对私有临时路径mkfifo。Windows受限token、unsafeACL、serviceModify/OWNER RIGHTS测试只在本轮私有fixture写SD或impersonate，guard恢复threadtoken；无需系统用户或生产权限变更。Mobile tests调用unsafeABI只传本函数内live Vec与aligned result，核负例不会执行产品逻辑。

本审查不覆盖panic=abort、OS终止、坏foreign pointer或主机绕过ABI所有权规则。这些无法由catch_unwind恢复。依赖升级保持锁定图可追溯；没有新增Client数据库依赖或产品名单分支。
