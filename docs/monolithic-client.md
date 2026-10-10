# 单体客户端基础库

xcsc 的 Rust 部分只有根目录一个包 `xcsc`、一个 `Cargo.toml` 和一个
`Cargo.lock`。`src/lib.rs` 直接导出下表模块，不通过工作区包装独立子包，
也没有内部路径依赖。Windows、macOS、Android 与 iOS 客户端从本仓库获取所需能力。

| 模块 | 作用与边界 |
|---|---|
| `xcsc::cli` | 桌面控制终端、有界秘密输入、服务管理、提权与日志尾读；Android/iOS 不编译此模块 |
| `xcsc::runtime` | 身份、凭据事务、受预算约束的持久化队列、投递、进程捕获和本机状态通道 |
| `xcsc::fs_safety` | 不跟随链接私有目录、ACL、类型化的名称、原子文件和锁；行政操作仍核对真实属主和权限 |
| `xcsc::secret` | 秘密字节、受限序列化和格式化脱敏 |
| `xcsc::secret_envelope` | 与对象绑定的现行 HKDF/AES-GCM 封装 |
| `xcsc::error` | 稳定错误码、请求身份和脱敏错误信封 |
| `xcsc::secure_xml` | 与产品无关的 XML 输入、深度、节点与文本预算 |
| `xcsc::mobile_ffi` | ABI 1、panic guard、结果释放、带代次的句柄和 JNI 边界 |
| `xcsc::log` | UTC 结构化客户端日志、脱敏、有界查询、文件轮转及 `XcscStructuredLayer` |
| `xcsc::contracts` | 离线工具使用的严格发行与 schema 身份；没有管理员认证或 HTTP DTO |
| `xcsc::schema_identity` | 保留现行元数据和逐字节一致的结构指纹的纯校验算法 |
| `xcsc::state_file` | Linux 离线客户端对现有服务私有目录和维护锁的受控操作 |
| `xcsc::sqlite` | Linux 离线客户端的直接 SQLite 连接、原生预算、防御模式与当前数据库结构验证；没有 pool、服务端生命周期或业务迁移 |

`state_file` 使用中立文件名 `.state-instance.lock`、`.state-maintenance.lock`
和 `.state-maintenance-pending.json`，校验当前元数据及精确结构指纹。
这些名称描述当前格式。具体升级定义、恢复日志、服务停止
策略与业务 SQL 由 xssc 拥有，操作前阅读该工具的实际升级说明。客户端自身日志用 `LogRecord::client` 和 `scope=client`；离线查询仍能读取
既有 `scope=server` 记录并保持其身份。

维护及实例 flock 在取得后立即由私有 RAII guard 持有，后续身份检查失败和
隐式 Drop 都先解锁该打开文件描述，再关闭描述符，避免并行进程
短暂继承同一描述符时阻塞恢复。显式交接成功后取消 guard 的解锁责任，保证
旧 guard 的销毁不会解开别名后来重新获得的锁。清理不重新打开、删除或
修复路径；锁文件的 inode、属主与权限校验不变。

`Spool::inspect_directory(&PrivateDirectory, SpoolLimits)` 接受已验证并锚定的
私有目录能力，复用公共库存扫描与健康字段；`inspect_existing` 仅在开目录后
委托。Windows 产品传入自身 SCM 角色策略打开的目录，不在产品内重写持久化队列
命名空间或统计规则；调用保留原目录权限策略、写入方锁和只读、有限预算边界。

## 功能开关与平台

默认功能开关为空。普通桌面客户端可以直接导入 CLI、运行时、文件与秘密
模块；默认依赖不会启用移动导出 ABI 或 SQLite。

| 功能开关 | 启用内容 | 消费约束 |
|---|---|---|
| `mobile-ffi` | `xcsc::mobile_ffi` | 只有导出 ABI 的库需要；必须使用 `panic=unwind`，abort-mode 明确编译失败 |
| `jni` | `mobile-ffi` 和 JNI 适配 | 使用真实 Java 17 JVM 和移动运行时分别验收，不从 host 测试推导 Android 验收 |
| `tracing` | `XcscStructuredLayer` | 客户端 tracing 事件产生客户端 scope；日志输出器失败仍可观察 |
| `offline-maintenance` | Linux 的 `state_file`、SQLite 和所需原生 SQLite 依赖 | 非 Linux target 不编译这两个模块，也不引入 target-specific SQLite 依赖；xssc 使用此功能开关 |

产品固定 `package=xcsc`、精确 `=1.0.0` 和正式发布的完整官方 Git revision，
通过 `xcsc::<module>` 导入。消费清单 `xcsc-client.toml` 使用 `desktop-client`、
`mobile-client` 或 `offline-maintenance` 能力配置。根门禁拒绝子 Cargo 包、
工作区外壳；消费门禁核对所有 manifest、别名、target、patch/replace
与实际 Cargo.lock，要求唯一官方 xcsc 包、精确版本和完整 Git revision。
规范四字母 `product_id` 必须以 `c` 结尾；xczs、xsos、xscs、xszs、xcos、xocs
等服务端不能通过声明客户端能力配置消费本库。非规范名称的通用测试测试夹具
仍使用其原标识，不伪装成正式产品。

## 开发检查

公共政策、Python、Rust 格式与工作区检查统一见[开发指南](development.md)。
平台专项步骤按 [Linux](platforms/linux.md)、[Windows](platforms/windows.md)、
[macOS](platforms/macos.md)、[Android](platforms/android.md)或 [iOS](platforms/ios.md)查阅。

Windows ACL、Apple 沙箱和移动设备结果各自记录；编译检查不会替代原生执行。

## ABI、迁移与历史证据

严格头生成器从 `src/mobile_ffi/mod.rs` 读取源声明；ABI 数字、C 导出名、
结构字段、长度上限、结果所有权和释放函数保持不变。JNI 生命周期和 Windows
ACL 测试随实现移动，包含所有模块子进程 helper 的 `--exact` 路径更新，
避免 helper 移动后运行零个用例仍返回成功。

目录合并和日志归属调整没有改写过去的版本、提交或验收结果。历史 macOS
测试数量与旧审查用于追踪当时实现；当前单体是否可发行，以当前包的
最终源码、原生 CI 和实际产物为准。
