# xcsc 文档

xcsc 是编译进桌面、移动和离线工具的 Rust 公共库。接入从一个依赖和一份能力清单开始，安装、配对与服务运行由具体产品提供。

## 接入和使用

- [开始接入](getting-started.md)：选择功能、声明产品清单、运行第一个示例
- [配置能力](configuration.md)：Cargo features、目标平台、清单字段与资源上限
- [使用公共模块](usage.md)：身份、私有文件、投递和移动宿主的接入顺序
- [排查问题](troubleshooting.md)：依赖检查、文件权限、队列和 FFI 错误

## 开发和查阅

- [构建与测试](development.md)：本地验证、原生平台测试和提交前检查
- [模块与平台](monolithic-client.md)：公开模块及编译条件
- [专题参考](reference/README.md)：存储、凭据、进程、FFI 和架构细节
- [发布来源](split-origin.md)与 [1.0.0 发布说明](releases/1.0.0.md)

使用成品客户端时，请查看对应产品的安装文档：[xsoc](https://github.com/isarmg/xsoc/blob/main/docs/platform-setup.md)、[xscc](https://github.com/isarmg/xscc/blob/main/docs/platform-setup.md)、[xcoc](https://github.com/isarmg/xcoc/blob/main/docs/platform-setup.md)、[xszc](https://github.com/isarmg/xszc/blob/main/docs/platform-setup.md)。

代码采用 [Apache License 2.0](../LICENSE)。
