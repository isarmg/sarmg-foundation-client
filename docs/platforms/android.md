# Android：JNI 与原生库接入

正式库目标为 `aarch64-linux-android`。xcsc 不生成 APK，也不定义应用最低 Android 版本、签名或 UI；这些由实际移动产品管理。先完成[依赖和产品清单](../getting-started.md)，选择 `mobile-client` profile；JNI 接入启用 `jni`，它会包含 `mobile-ffi`。

## 检查 Android 目标

准备 Rust `1.99.0`、Python 3，以及产品构建需要的 Android SDK/NDK。在 xcsc 仓库根目录运行：

```sh
rustup target add --toolchain 1.99.0 aarch64-linux-android
cargo +1.99.0 check --locked -p xcsc --all-features --lib --target aarch64-linux-android
```

这条检查使用 Android target API，但不会链接产品的 JNI `.so`、打包 APK 或运行设备。产品按自己的 NDK、cargo-ndk、Gradle 和 ABI 配置构建动态库。Android 不编译桌面 `xcsc::cli` 或 Linux 离线维护模块。

## JNI 宿主验证

在配置好 Java 17 JVM 的开发主机另执行以下专项测试；该用例默认 ignored，必须显式运行：

```sh
cargo +1.99.0 test --locked -p xcsc --features jni \
  native_jvm_keeps_unicode_budgets_pending_exceptions_and_public_errors \
  -- --ignored --nocapture
```

测试覆盖调用帧、UTF-16/Unicode、字节预算、待处理异常和公开错误。结果表示真实宿主 JVM 验证通过；Android 的 ART、应用沙箱和库加载仍在产品模拟器/真机测试中验证。

## 集成顺序与排障

1. Kotlin 宿主先检查运行时 ABI revision，再发起业务调用；同时检查 Java 异常，不能将 JNI 哨兵值当成功。
2. JNI 导出通过公共 guard 借用 `jni::Env`。所有权、长度和错误映射统一按[移动 FFI 契约](../mobile-ffi.md)执行。
3. 应用传入自身私有目录的绝对物理路径。Android 祖先目录可能只允许搜索、不允许列目录；公共实现已按该沙箱条件处理，不需要读取 `/data` 的目录内容。
4. 动态库加载失败时核对设备 ABI、产品打包的 `.so`、当前导出名及版本；不要用宿主 JVM 测试替代设备库加载测试。
5. 在目标设备验证打开、正常请求、取消、关闭和重开，并保留脱敏错误及实际运行平台。

应用安装和签名请用 [xszc Android 指南](https://github.com/isarmg/xszc/blob/main/docs/platforms/android.md)或 [xcoc Android 指南](https://github.com/isarmg/xcoc/blob/main/docs/platforms/android.md)。共享 Rust 检查见[开发指南](../development.md)。

[能力配置](../configuration.md) · [选择其他平台](../README.md#选择接入平台)
