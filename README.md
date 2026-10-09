# xcsc

xcsc `1.0.0` 为桌面和移动 Client 提供共享的安全基础能力。产品可复用命令行约定、私有状态目录、有界队列、HTTPS 投递、凭据封装、文件系统安全、移动 FFI 和受限 XML 解析，同时继续由产品仓库拥有业务协议与状态机。

1.0.0 修复继承屏蔽的子进程退出信号时有界捕获和回收停滞的问题，并允许 Unix root 管理员只读检查服务账户持有的私有 spool。当前 C ABI 为修订 1，导出结果类型和释放函数均使用 `V1` / `_v1` 身份。Rust 固定 1.99.0。详见 [发行说明](docs/releases/1.0.0.md) 和 [unsafe 审查](docs/unsafe-audit.md)。

本仓库只负责 Client 侧基础设施；Server 管理能力由 [xcss](https://github.com/isarmg/xcss) 提供。两者可以独立构建和发布。

## 部署入口

xcsc 是由产品编译链接的共享库，没有需要单独安装、配对或启停的系统服务。设备用户请按具体产品的部署指南操作；xcsc 升级由产品固定依赖并重新发行完成。

- [xsoc：Windows、Linux、macOS](https://github.com/isarmg/xsoc/blob/main/docs/platform-setup.md)
- [xscc：Windows、Ubuntu、macOS](https://github.com/isarmg/xscc/blob/main/docs/platform-setup.md)
- [xcoc：Linux、Windows、macOS、Android、iOS](https://github.com/isarmg/xcoc/blob/main/docs/platform-setup.md)
- [xszc：Android、iOS](https://github.com/isarmg/xszc/blob/main/docs/platform-setup.md)

## Profiles 与接入

仓库提供两个 Profile：

- `desktop-client`：Linux、Windows 与 macOS 原生 Client；
- `mobile-client`：Android、iOS 与 iOS Simulator 嵌入式 Client。

产品在仓库根目录维护 `xcsc-client.toml`，声明 xcsc 版本、Profile、能力和检查范围。可参考现有消费者清单，并运行检查器：

```sh
python3 scripts/check-xcsc.py --product-root /absolute/path/to/product
```

发布消费者应同时固定精确 crate 版本与完整 Git revision，不使用相邻目录的 path dependency。能力列表和平台基线以 [`profiles/`](profiles/) 为准。

## 开发验证

```sh
python3 scripts/check-xcsc.py
python3 -m unittest discover -s tools/tests -v
cargo fmt --all -- --check
cargo test --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

原生平台是否可交付仍需对应 Android、iOS、Windows 或 macOS CI 验收；通用 Rust 测试不能替代平台测试。

## 文档

- [文档总览](docs/README.md)
- [xcsc/xcss 与产品边界](docs/xcsc-boundary.md)
- [桌面队列与投递](docs/client-spool.md)
- [身份与凭据](docs/client-identity.md)
- [移动 FFI](docs/mobile-ffi.md)
- [文件系统安全](docs/filesystem-handles.md)

代码采用 [Apache License 2.0](LICENSE)。

消费检查把移动端导出 ABI crate 的 panic 翻译与普通业务库、SQLite 私有回调及风险测试区分；导出 crate 内所有 helper 仍必须复用公共 FFI guard。HandleRegistry、C 字符串读取、guard_value 和 LAST_ERROR 的重复实现依旧在全部声明源码中拒绝。

当前发布版本：**1.0.0**。参见 [1.0.0 发布说明](docs/releases/1.0.0.md)和[项目命名](docs/naming.md)。
