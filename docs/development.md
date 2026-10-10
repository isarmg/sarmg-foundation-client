# 构建与测试

准备 Rust `1.99.0`、Python 3 和目标操作系统的原生 C/C++ 编译工具链。在仓库根目录运行：

```sh
python3 scripts/check-xcsc.py
python3 -m unittest discover -s tools/tests -v
cargo fmt --all -- --check
cargo test --locked -p xcsc --all-targets --all-features
cargo clippy --locked -p xcsc --all-targets --all-features -- -D warnings
cargo doc --locked --all-features --no-deps
```

Python 检查产品来源、能力和绑定生成；Rust 测试覆盖当前主机上的公共机制；API 文档写入 `target/doc/xcsc/`。Linux 的 `--all-features` 包含离线 SQLite，其他平台保持各自模块边界。

## 选择专项验证

| 改动 | 补充验证 |
|---|---|
| 私有文件、ACL、锁、服务管理 | 在 Linux、Windows 和 macOS 对应原生 CI 执行 |
| C ABI/JNI、句柄、字符串 | 真实 C/JVM 及产品 Android/iOS 测试 |
| 能力清单或消费检查 | Python 工具测试和一个实际消费者的检查 |
| 产品协议适配器 | 在产品仓库验证协议与业务状态 |

真实 Java 17 JVM 测试单独启用：

```sh
cargo test --locked -p xcsc --features jni   native_jvm_keeps_unicode_budgets_pending_exceptions_and_public_errors   -- --ignored --nocapture
```

移动目标检查：

```sh
rustup target add aarch64-linux-android aarch64-apple-ios-sim
cargo check --locked -p xcsc --all-features --lib --target aarch64-linux-android
cargo check --locked -p xcsc --all-features --lib --target aarch64-apple-ios-sim
```

交叉检查确认可编译，原生文件权限、设备运行与安装仍在对应平台测试。macOS 文件测试使用物理临时路径，如 `TMPDIR=/private/tmp`，以符合不跟随符号链接的路径规则。

## 发布和产品更新

更新公共 API 时，同步调整对应文档、能力清单及受影响的测试。产品依赖升级时更新精确版本、完整 revision 和锁文件，再执行消费检查与产品测试。源码归档和标签验证见[发布来源](split-origin.md)；原生调用审查见[参考索引](reference/README.md)。
