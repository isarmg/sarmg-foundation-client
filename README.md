# Sarmg Foundation Client

Sarmg Foundation Client `0.9.15` 为桌面和移动 Client 提供共享的安全基础能力。产品可复用命令行约定、私有状态目录、有界队列、HTTPS 投递、凭据封装、文件系统安全、移动 FFI 和受限 XML 解析，同时继续由产品仓库拥有业务协议与状态机。

本仓库只负责 Client 侧基础设施；Server 管理能力由 [sarmg-foundation-server](https://github.com/isarmg/sarmg-foundation-server) 提供。两者可以独立构建和发布。

## Profiles 与接入

仓库提供两个 Profile：

- `desktop-client`：Linux、Windows 与 macOS 原生 Client；
- `mobile-client`：Android、iOS 与 iOS Simulator 嵌入式 Client。

产品在仓库根目录维护 `sarmg-client.toml`，声明 Foundation 版本、Profile、能力和检查范围。可参考现有消费者清单，并运行检查器：

```sh
python3 scripts/check-foundation.py --product-root /absolute/path/to/product
```

发布消费者应同时固定精确 crate 版本与完整 Git revision，不使用相邻目录的 path dependency。能力列表和平台基线以 [`profiles/`](profiles/) 为准。

## 开发验证

```sh
python3 scripts/check-foundation.py
python3 -m unittest discover -s tools/tests -v
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

原生平台是否可交付仍需对应 Android、iOS、Windows 或 macOS CI 验收；通用 Rust 测试不能替代平台测试。

## 文档

- [文档总览](docs/README.md)
- [Foundation Client/Server 与产品边界](docs/foundation-boundary.md)
- [桌面队列与投递](docs/client-spool.md)
- [身份与凭据](docs/client-identity.md)
- [移动 FFI](docs/mobile-ffi.md)
- [文件系统安全](docs/filesystem-handles.md)

代码采用 [Apache License 2.0](LICENSE)。
