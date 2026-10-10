# iOS：C ABI 与原生库接入

正式目标为实机 `aarch64-apple-ios` 与 Apple Silicon 模拟器 `aarch64-apple-ios-sim`。xcsc 提供 Rust/C ABI 公共机制；产品负责静态库、XCFramework、Swift 应用和签名安装。先按[开始接入](../getting-started.md)添加依赖，使用 `mobile-client` profile 和 `mobile-ffi` feature。

## 检查两个目标

准备 Rust `1.99.0`、Python 3。产品的最终链接和 Xcode 验证在装有对应 iOS SDK 的 Mac 上完成。xcsc 根目录的编译检查为：

```sh
rustup target add --toolchain 1.99.0 aarch64-apple-ios aarch64-apple-ios-sim
cargo +1.99.0 check --locked -p xcsc --all-features --lib --target aarch64-apple-ios
cargo +1.99.0 check --locked -p xcsc --all-features --lib --target aarch64-apple-ios-sim
```

编译检查不创建可安装 App。产品分别构建实机和模拟器库后，按自身脚本生成 XCFramework；不能因二者都为 arm64 就交换平台切片。iOS 不编译桌面 CLI 或 Linux 离线维护模块。

## Swift 与 C ABI 接入

1. 产品使用严格头生成器核对 Rust ABI 与生成的 C 头，Swift 从 C module 导入，不手写重复符号声明。
2. 产品构建保持 `panic=unwind`；`panic=abort` 会被拒绝。可展开 panic 由 guard 转成状态码，输入有效性仍由调用方保证。
3. 结果在原存储位置读取和释放，不复制拥有字节所有权的结果后分别释放。完整初始化、释放、长度和句柄规则见[移动 FFI 契约](../mobile-ffi.md)。
4. 设备与模拟器分别验证打开、正常调用、错误、取消、关闭及重新打开；ABI revision 与产品业务身份分别核对。

## 沙箱路径与故障检查

产品应传入应用容器中的绝对物理路径，已有父目录必须可用。Apple 实现用内核的 `O_NOFOLLOW_ANY` 在单次查找中拒绝路径组件的符号链接，避免逐级打开应用沙箱之外的祖先目录。

- 容器路径失败：检查产品取得的目录、物理路径、当前应用权限与最终私有目录 `0700` 权限。
- 链接或加载失败：核对实机/模拟器切片、C module、生成头和产品实际链接库版本。
- 签名、Keychain 或 entitlement 错误：按产品指南处理；它们不属于公共库的 Rust 编译检查。
- macOS 沙箱回归可按 [macOS 指南](macos.md#私有路径与原生验证)运行，但 iOS 的实际应用容器仍需设备执行证据。

应用构建与安装请用 [xszc iOS 指南](https://github.com/isarmg/xszc/blob/main/docs/platforms/ios.md)或 [xcoc iOS 指南](https://github.com/isarmg/xcoc/blob/main/docs/platforms/ios.md)。产品决定最低 iOS 版本与签名要求。

[公共开发检查](../development.md) · [选择其他平台](../README.md#选择接入平台)
