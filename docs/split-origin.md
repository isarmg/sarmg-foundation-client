# 仓库与发布来源

xcsc 是独立构建、测试和发布的 Client 基础仓库。
源码包版本来自根 `Cargo.toml` 的 `package.version`；发布流程核对
Git tag、当前提交与干净工作树，并从该提交生成带校验和的源码归档。

消费者同时固定精确 crate 版本和完整 Git revision。发布记录位于 `docs/releases/`，
当前 API、Profile 与边界以本仓库源码和现行文档为准。

xcsc 独立维护通用客户端安全机制，修复需在本仓库验证并发布；
产品接入和业务验收由各自仓库负责。
