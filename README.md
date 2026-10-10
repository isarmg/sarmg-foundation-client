# xcsc

xcsc 是桌面、移动和离线客户端的 Rust 公共基础库。各产品通过同一个 `xcsc` 包获取公共能力，自行实现业务协议和用户界面。

## 项目功能

- 私有文件与凭据保护、秘密封装、结构化日志和有界 XML 解析。
- 客户端生命周期、持久化队列、投递、子进程管理和本机状态通道。
- 移动端 C/JNI FFI，以及 Linux 离线维护所需的状态校验和 SQLite 能力。

## 适用平台

- 桌面：Linux x86_64 GNU、Windows x86_64 MSVC、macOS Intel / Apple Silicon。
- 移动：Android arm64、iOS arm64 和 Apple Silicon iOS Simulator。
- 离线维护：仅 Linux x86_64 GNU。

## 快速部署

本项目是编译链接进产品的库，无需单独安装或启动服务。在产品 `Cargo.toml` 中加入固定依赖：

```toml
[dependencies]
xcsc = { git = "https://github.com/isarmg/xcsc.git", rev = "c45e48e93e360542c2e1db6c6441a9e29b344b03", version = "=1.0.0" }
```

默认功能适用于桌面接入；移动导出启用 `mobile-ffi`，Android JNI 启用 `jni`，Linux 离线维护启用 `offline-maintenance`。产品根目录声明 `xcsc-client.toml`，选择对应能力配置并提交 `Cargo.lock`；随后构建、安装该产品。

## 编译部署

准备 Rust `1.99.0`、Python 3 和目标平台的原生编译工具链，在仓库根目录执行：

```sh
python3 scripts/check-xcsc.py
cargo build --release --locked -p xcsc
# 将路径替换为已完成依赖和能力配置的产品仓库。
python3 scripts/check-xcsc.py --product-root /absolute/path/to/product
```

构建得到 Rust 库，位于 `target/release/`。移动端须使用相应 Android NDK / Apple SDK 和目标架构重新编译，由宿主应用链接；升级通过更新产品依赖并重新发行完成。

[详细文档](docs/README.md)
