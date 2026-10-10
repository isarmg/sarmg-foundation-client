# Windows 私有状态

0.9.19 使用原生句柄实现 Windows 私有文件操作。Windows 原生 CI 执行权限负测，三平台 CI 为发行必需门；交叉检查不能代替原生权限验证。

`PrivateDirectory` 只接收完整的本地 DOS 驱动器路径及系统规范化的 verbatim drive 路径，逐级打开且持有不共享删除的祖先目录句柄。目录和文件拒绝 reparse point，文件还拒绝多个硬链接。最终目录、打开的状态文件及锁都校验句柄上的属主和私有 DACL。普通当前用户及账户策略要求受保护 DACL；显式服务策略的继承对象必须位于下述可信保护根内。缺失 DACL、外部用户、未知 ACE 或可继承的外部访问都会拒绝，既有对象的权限不会自动修复。

默认允许当前进程用户、SYSTEM、Administrators，以及当前进程令牌中已启用的确切服务 SID。`WindowsPrivateAccess::for_service` 由产品自身 SCM 定义提供一个五段服务 SID 和 SYSTEM、LocalService 或 NetworkService 属主账户。该账户只用于属主身份校验；新对象只向 SYSTEM/Administrators 授予完整权限、向确切服务 SID 授予 Modify，并以 OWNER RIGHTS READ_CONTROL 禁止服务属主隐式 WRITE_DAC。`for_service_account` 接受固定内建账户的私有 DACL，供经 OS 权限授权的服务账户文件访问；`for_current_user` 不扩展启用的服务组权限；不允许任意用户、所有服务或组通配符。唯一允许的 OWNER RIGHTS ACE 仅有 READ_CONTROL。`PrivateDirectory::{create_with_windows_access,open_with_windows_access}` 保留此策略，子目录继续使用同一策略；`ClientSession::from_directory` 保留已校验的目录和策略。

显式服务策略要求四个有效 Allow ACE 各出现一次：SYSTEM、Administrators 的 `FILE_ALL_ACCESS`，所选服务 SID 的 `0x1301bf`，以及 OWNER RIGHTS 的 `READ_CONTROL`。缺失 OWNER RIGHTS 会恢复账户属主的隐式 `WRITE_DAC`，因此必须拒绝；缺少角色、重复角色、掩码子集或超集、额外授权和仅继承而不作用于本对象的 ACE 同样拒绝。目录必须具有 Object/Container Inherit，普通文件不接受这些传播标志；两者可具有 `INHERITED_ACE`，其他标志均拒绝。

服务私有目录的保护锚必须保持 `SE_DACL_PROTECTED`、完整同一服务策略，以及 SYSTEM、Administrators 或所选唯一服务 SID 属主。LocalService/NetworkService 属主和当前精确 DACL 不能单独证明根目录由可信方置备：共享账户可能先创建对象并保留旧 `WRITE_DAC` 句柄。该账户只允许作为已验证保护根内的后代属主。打开继承目录时逐段校验同策略权限、属主和类型，直到可信保护锚；中间目录不匹配、仅立即父目录匹配或缺少锚都会拒绝。持有的锚索引固定，后续每次操作重新核对原始锚及全部私有段，失败不转选另一个锚。

`create_with_windows_access` 保留显式 protected 新根初始化入口：缺失服务根在创建前读取实际有效线程令牌的 `TokenOwner`，仅无线程令牌时读取主令牌，要求新对象默认属主属于上述可信集合。既存目录只按物理属主和 DACL 校验，不根据调用者默认属主拒绝。普通当前用户的新对象仍在原生创建时指定 protected 私有 DACL。

服务子目录只能经 `create_child` 在已持有、完整校验的私有父链下以 NULL security attributes 创建；状态文件、临时文件和锁使用同一受限继承方式。新对象在返回或写入业务字节前检查实际属主、四项有效 ACL 和类型；不会从 ambient 父目录默认继承，不会在 access denied 后切换创建策略。既存对象先打开并验证，错误 ACL 不修复。读取有字节上限；替换和无覆盖发布从已校验文件句柄原子重命名，删除也作用于句柄。发布后的同步失败报告 `PublishedDurabilityUnknown` 并保留已发布数据。锁的持久文件不会在释放时删除。

原生行为测试检查：已有宽松 ACL 拒绝且不修复、私有凭据/主密钥/状态对受限非特权令牌拒绝读和写、硬链接拒绝、持有目录不能移动、正常读写/替换/锁和关闭重开。受限令牌使用 Windows 的第二次 ACL 检查，未创建系统用户。产品自己的 SQLite、凭据格式和业务状态仍由产品管理。

服务 ACL 回归包含物理文件的 OWNER RIGHTS 对照：隔离根显式设为 Administrators 属主，在保留真实管理员组的派生线程令牌上把默认对象属主设为真实 CI 用户，随后经公共 NULL 继承创建文件并恢复线程身份。测试先确认物理属主、完整四项有效 ACL、OWNER RIGHTS 和公共 guard 验证，再禁用实际令牌的 Administrators 授权和权限，不添加会掩盖属主行为的 restricting SID。使用实际文件描述符、实际线程令牌的 `AccessCheck` 和 `SetNamedSecurityInfoW` 分别验证有 OWNER RIGHTS 时不能改 DACL、缺失时能够改 DACL；公共读取、持有文件、替换、锁和删除必须在不改变内容及 ACL 的前提下拒绝错误策略。保护锚属主负测在受控管理员变更后重建隔离测试夹具的精确 DACL，并确认 ACL 仍完整、后代属主仍被接受，才能把拒绝归因于锚的身份要求；生产不执行这种权限修复。继承回归通过真实子目录、状态文件、锁、原子替换及重新打开检查实际标志；另验证 foreign 私有段、失去原锚可信属主、账户属主的 ambient 根和创建前默认属主拒绝。它们是原生机制测试，执行证据来自最终源码的 Windows CI；产品的真实 SCM/LocalService 服务路径由消费方单独验证。

公共 CLI 新增有界尾部读取、固定五个轮转槽的查询和可注入日志源的持续跟踪。产品提供经权限校验的读取以及权威类型化的解码器；公共实现限制字节、记录数、保留量和游标，游标丢失明确报告 gap。首行仅在被字节边界切断时跳过，末尾半行交由类型化的解码器拒绝，不能空成功掩盖损坏。

0.10.0 新增拥有文件所有权的 `WindowsPrivateFile`（`PrivateFileAccess::{ReadOnly,ReadWrite}`）。`PrivateDirectory::open_private_file` 只打开已有私有文件，并复制已验证目录及祖先句柄；不创建文件、不修复权限，借用 File 不能转移其所有权。SQLx 连接必须显式关闭后再释放主数据库守卫，DELETE 模式回滚日志的临时验证守卫不能跨事务提交持有。`service_sid` 按 SCM 协议使用操作系统不受区域设置影响的大写映射推导，无需调用 LookupAccountName 或预安装服务；`process_user_sid` 只读取主令牌用户。原子重命名为可变长度 `FILE_RENAME_INFO` 保留 NUL 的实际存储，长度字段不计 NUL。原生 CI 覆盖规范的 verbatim 路径、不同名称长度、Unicode 名称的替换与重新打开，并核对目录内的准确文件名。
