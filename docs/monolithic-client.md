# 单体 Client 基础库

xcsc 的 Rust 部分只有根目录一个 package `xcsc`、一个 `Cargo.toml` 和一个
`Cargo.lock`。`src/lib.rs` 直接导出下表模块，不通过 workspace 包装独立子包，
也没有内部 path dependency。Windows、macOS、Android 与 iOS Client 从本仓库获取所需能力。

| 模块 | 作用与边界 |
|---|---|
| `xcsc::cli` | 桌面控制终端、有界秘密输入、服务管理、提权与日志尾读；Android/iOS 不编译此模块 |
| `xcsc::runtime` | 身份、凭据事务、受预算约束的 spool、投递、进程捕获和本机状态通道 |
| `xcsc::fs_safety` | no-follow 私有目录、ACL、typed 名称、原子文件和锁；行政操作仍核对真实属主和权限 |
| `xcsc::secret` | 秘密字节、受限序列化和格式化脱敏 |
| `xcsc::secret_envelope` | 与对象绑定的现行 HKDF/AES-GCM 封装 |
| `xcsc::error` | 稳定错误码、请求身份和脱敏错误信封 |
| `xcsc::secure_xml` | 与产品无关的 XML 输入、深度、节点与文本预算 |
| `xcsc::mobile_ffi` | ABI 1、panic guard、结果释放、generational handles 和 JNI 边界 |
| `xcsc::log` | UTC 结构化 Client 日志、脱敏、有界查询、文件轮转及 `XcscStructuredLayer` |
| `xcsc::contracts` | 离线工具使用的严格发行与 schema 身份；没有管理员认证或 HTTP DTO |
| `xcsc::schema_identity` | 保留现行元数据和 byte-exact schema fingerprint 的纯校验算法 |
| `xcsc::state_file` | Linux 离线 Client 对现有服务私有目录和维护锁的受控操作 |
| `xcsc::sqlite` | Linux 离线 Client 的直接 SQLite 连接、原生预算、防御模式与当前 schema 验证；没有 pool、Server 生命周期或业务迁移 |

`state_file` 使用中立文件名 `.state-instance.lock`、`.state-maintenance.lock`
和 `.state-maintenance-pending.json`，校验当前元数据及精确 schema 指纹。
不保留旧文件名兼容、fallback 或自动迁移。部署新格式前必须停止旧服务、备份
配置和数据并重新部署；不得混用旧目录。具体升级定义、恢复 journal、服务停止
策略与业务 SQL 由 xssc 拥有。Client 自身日志用 `LogRecord::client` 和 `scope=client`；离线查询仍能读取
既有 `scope=server` 记录并保持其身份。

维护及实例 flock 在取得后立即由私有 RAII guard 持有，后续身份检查失败和
隐式 Drop 都先解锁该 open file description，再关闭描述符，避免并行进程
短暂继承同一描述符时阻塞恢复。显式交接成功后取消 guard 的解锁责任，保证
旧 guard 的销毁不会解开 alias 后来重新获得的锁。清理不重新打开、删除或
修复路径；锁文件的 inode、属主与权限校验不变。

`Spool::inspect_directory(&PrivateDirectory, SpoolLimits)` 接受已验证并锚定的
私有目录能力，复用公共库存扫描与健康字段；`inspect_existing` 仅在开目录后
委托。Windows 产品传入自身 SCM 角色策略打开的目录，不在产品内重写 spool
命名空间或统计规则；调用保留原目录权限策略、writer 锁和只读、有限预算边界。

## Features 与平台

默认 features 为空。普通桌面 Client 可以直接导入 CLI、运行时、文件与秘密
模块；默认依赖不会启用移动导出 ABI 或 SQLite。

| Feature | 启用内容 | 消费约束 |
|---|---|---|
| `mobile-ffi` | `xcsc::mobile_ffi` | 只有导出 ABI 的库需要；必须使用 `panic=unwind`，abort-mode 明确编译失败 |
| `jni` | `mobile-ffi` 和 JNI 适配 | 使用真实 Java 17 JVM 和移动运行时分别验收，不从 host 测试推导 Android 验收 |
| `tracing` | `XcscStructuredLayer` | Client tracing 事件产生 Client scope；日志 sink 失败仍可观察 |
| `offline-maintenance` | Linux 的 `state_file`、SQLite 和所需原生 SQLite 依赖 | 非 Linux target 不编译这两个模块，也不引入 target-specific SQLite 依赖；xssc 使用此 feature |

产品固定 `package=xcsc`、精确 `=1.0.0` 和正式发布的完整官方 Git revision，
通过 `xcsc::<module>` 导入。消费清单 `xcsc-client.toml` 使用 `desktop-client`、
`mobile-client` 或 `offline-maintenance` Profile。根门禁拒绝子 Cargo package、
workspace 外壳；消费门禁核对所有 manifest、别名、target、patch/replace
与实际 Cargo.lock，要求唯一官方 xcsc 包、精确版本和完整 Git revision。
规范四字母 `product_id` 必须以 `c` 结尾；xczs、xsos、xscs、xszs、xcos、xocs
等 Server 不能通过声明 Client Profile 消费本库。非规范名称的通用测试 fixture
仍使用其原标识，不伪装成正式产品。

## 开发检查

在仓库根目录执行：

```sh
python3 scripts/check-xcsc.py
python3 -m unittest discover -s tools/tests -v
cargo fmt --all -- --check
cargo test --locked -p xcsc --all-targets --all-features
cargo clippy --locked -p xcsc --all-targets --all-features -- -D warnings
```

第一条检查单包结构、模块和平台/feature 门禁及根 lock 图。Python 用例验证
依赖方向、官方源码身份、ABI 所有者与严格 C 头生成器的负向边界。`fmt` 检查
格式；Rust 测试运行平台机制；Clippy 将警告视为错误。Linux 的完整测试包含
离线维护能力，Windows/macOS 的 `--all-features` 不编译 Linux 维护模块。

JNI 集成用例明确 ignored，须在 Java 17 环境单独执行：

```sh
cargo test --locked -p xcsc --features jni \
  native_jvm_keeps_unicode_budgets_pending_exceptions_and_public_errors \
  -- --ignored --nocapture
```

该命令覆盖真实 JVM 的 frame、Unicode、字节预算、待处理异常与公开错误，
不会把默认测试跳过状态当作成功证据。root-only spool 检查由 Linux CI 找到
唯一的 xcsc 测试二进制后，执行精确模块路径的 ignored 用例；仅使用临时
服务属主 fixture，不操作运行中的服务或用户数据。

移动交叉检查保持真实 target API：

```sh
cargo check --locked -p xcsc --all-features --lib --target aarch64-linux-android
cargo check --locked -p xcsc --all-features --lib --target aarch64-apple-ios-sim
```

这两条只证明指定 target 可编译。Windows 原生 ACL/轮转、macOS 沙箱/LaunchAgent、
Android/iOS 实际发行物分别由相应最终 Source CI 验收。

## ABI、迁移与历史证据

严格头生成器从 `src/mobile_ffi/mod.rs` 读取源声明；ABI 数字、C 导出名、
结构字段、长度上限、结果所有权和释放函数保持不变。JNI 生命周期和 Windows
ACL 测试随实现移动，包含所有模块子进程 helper 的 `--exact` 路径更新，
避免 helper 移动后运行零个用例仍返回成功。

目录合并和日志归属调整没有改写过去的版本、提交或验收结果。历史 macOS
测试数量与旧审查用于追踪当时实现；当前单体是否可发行，以当前 package 的
最终 Source、原生 CI 和实际产物为准。
