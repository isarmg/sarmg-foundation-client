# 配置能力

xcsc 的配置在构建时完成：Cargo features 决定编译模块，`xcsc-client.toml` 声明产品使用的能力。用户的账户、服务器地址和业务偏好由产品管理。

## 选择目标和功能

| 场景 | Profile | Cargo features | 正式目标 |
|---|---|---|---|
| 桌面客户端 | `desktop-client` | 默认；按需 `tracing` | Linux x86_64 GNU、Windows x86_64 MSVC、macOS Intel/Apple Silicon |
| 移动客户端 | `mobile-client` | `mobile-ffi`；Android JNI 使用 `jni` | Android arm64、iOS arm64、Apple Silicon iOS Simulator |
| 离线维护 | `offline-maintenance` | `offline-maintenance` | Linux x86_64 GNU |

`jni` 包含 `mobile-ffi`。FFI 导出使用 `panic=unwind`，以便公共 guard 把可展开 panic 转为错误；`panic=abort` 构建会被拒绝。`tracing` 启用 `XcscStructuredLayer`。完整模块编译条件见[模块与平台](monolithic-client.md)。

## 产品清单

[最小清单](getting-started.md#2-声明产品使用的能力)中的字段含义：

- `format`：清单格式，目前为 `1`
- `product_id`：产品身份；四字母系列名以 `c` 结尾
- `source_roots`：参与能力检查的产品源码目录，按仓库根目录填写
- `foundation`：公共层代次和精确软件版本
- `components`：组件名称、profile 及实际采用的 capabilities

字段定义见 [JSON Schema](../schemas/xcsc-client.schema.json)，必需和可选能力见 [desktop-client](../profiles/desktop-client.toml)、[mobile-client](../profiles/mobile-client.toml)和 [offline-maintenance](../profiles/offline-maintenance.toml)。

## 设置桌面队列上限

使用 `bounded-spool` 时，在相应组件同时声明三项预算：

```toml
[[components]]
id = "desktop"
profile = "desktop-client"
capabilities = ["https-delivery", "private-state", "bounded-spool"]

[components.client_limits]
max_record_bytes = 1048576
max_spool_bytes = 268435456
max_spool_entries = 4096
```

示例使用当前允许的最大值：单条载荷 1 MiB、队列 256 MiB、4096 条记录。可按产品需要降低预算，并将相同限制传给运行时。队列字节数包含容器元数据与隔离记录；详细统计规则见[持久化队列](client-spool.md)。

移动 FFI 的公共上限为单次输入/输出各 16 MiB、4096 个句柄；产品可以采用更小的预算。业务队列和数据库格式由移动产品定义。
