# Foundation Server、Foundation Client 与产品边界

两个 Foundation 仓库都是构建期上游，不是产品功能的集中仓库，也不在生产环境形成中央服务。它们互不依赖；产品分别锁定所需 Foundation 的精确版本和 Git revision。

| 所属 | 应负责 | 不应负责 |
|---|---|---|
| Foundation Server | Server 进程、管理 Server 的 Web、管理员认证、HTTP/数据库/文件安全原语、通用管理 UI 和服务端发布工具 | Client 本机状态、移动 FFI、产品实例/设备/硬件 DTO、产品配对协议和产品页面 |
| Foundation Client | 桌面及移动 Client 的运行时、Spool、文件与秘密安全、原生终端输入、服务生命周期、本机只读状态通道和移动 FFI | 产品配对 wire、远端 API 状态解释、产品错误码及恢复文案、本机第三方服务策略和管理 Server 的 Web |
| 产品仓库 | 业务 DTO、端点、状态机、错误码、恢复步骤、业务页面、业务安全加强和产品发布验收 | 复制 Foundation 已发布的实现并维护第二事实源 |

一项实现只有同时满足以下条件才适合进入 Foundation：

1. API 用平台概念表达，不包含 Host、Sunshine、Sentinel、Media 等产品名称或业务 DTO。
2. Foundation 可以独立测试它，不需要启动某个产品的协议端点或读取产品状态。
3. 产品仍能在 Adapter 前后施加更严格的安全规则；公共实现不会把最强产品规则降成最低共同标准。
4. 至少存在明确的跨产品复用场景；单产品需求先留在产品仓库，成熟后再提取。
5. Foundation 成为唯一实现源后，消费者通过不可变发布包使用它，不复制源码快照。

终端输入 API 只处理控制终端、输入上限、绝对期限和秘密清零，可由多个桌面 Client 复用。`pairing_*` 的 HTTP 含义、用户文案和恢复步骤不符合该边界，必须由定义相应协议的产品提供。`sarmg-client-cli` 只负责稳定错误信封，并通过 `ProductErrorCatalog` 接收产品展示信息。

Profile 也不能把某个产品架构冒充通用要求。`desktop-client` 只要求产品提供 HTTPS 投递 Adapter；Spool、Foundation 私有状态、Doctor、完整服务生命周期和受保护终端输入均按实际采用情况显式声明。实时流 Client 根据实际采用的机制声明能力。

通用机制还必须由实际层级承载。`sarmg-secure-xml` 提供 Client 侧与产品无关的解析预算；业务 XML 协议、命名空间、设备字段和具体预算值由产品定义。Client 不得反向依赖 Foundation Server。

Server 侧内容块也只保留在 `@sarmg/admin-ui`：公共包提供可覆盖的布局、样式和无障碍原语；实例统计、授权码、CPU/GPU/SSD/RAM、摄像头和 Sunshine 控制仍由产品 Web 定义。消费者只导入发布包，不保存内容块 CSS 副本。

仓库检查覆盖根清单、workspace 继承、目标平台依赖以及 Cargo `patch`/`replace`。Client 内部 path 依赖必须指向登记的 crate，并与工作区版本精确匹配。消费者检查同时扫描其完整目录中的 Cargo 清单，不能通过 `source_roots` 排除依赖检查。

`Args::parse` 解析通用选项以及产品显式声明的选项，仅为通用 `--config` 和 `--state` 验证绝对路径。产品选项的含义与路径要求由产品在命令执行前检查，可复用 `absolute`；Foundation 不依据产品选项名推断业务语义。

CLI 输出经过递归脱敏：字段名大小写和连接符不影响匹配，密码、令牌、凭据、证书及 API/私钥字段中的字符串、数字、对象或数组会整体替换为 `{"configured": boolean}`；布尔值保留，供状态标志使用。普通字符串中的控制字符会被移除。产品应使用明确的字段名表达秘密，并且不得将秘密放入普通字段或错误详情中。
