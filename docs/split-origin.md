# 拆分来源

2026-09-05 按项目所有者要求，从原 Foundation 工作区拆分为独立 Client 仓库。
原仓库更名为 `sarmg-foundation-server`，保留原 Git 历史及未提交工作；本仓单独初始化 Git，未复制原仓库 `.git`。

`sarmg-client-runtime`、`sarmg-mobile-ffi`、客户端 Profile、Spool/FFI 规范和 Header 工具由原工作区迁入。
文件安全、错误类型、HTTP、秘密类型和密钥封装根据客户端需要提取为独立命名的 Client 包，携带原 Apache-2.0 许可证与测试。
提取对象是当时的工作区，包含尚未提交的改造；不能用原 `v0.5.0` tag 冒充这些文件的完整发布来源。

两个仓库分别维护当前行为；任何影响通用安全机制的修复，都应检查是否同时影响另一侧并分别验收。
本记录不是跨版本兼容承诺，也不是不可变制品发布记录。
