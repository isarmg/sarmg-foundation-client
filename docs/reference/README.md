# xcsc 专题参考

这些文档供实现和排查具体模块时查阅。首次接入请从[开始接入](../getting-started.md)阅读。

## 运行与存储

- [身份和隔离](../client-identity.md)
- [凭据事务与并发](../credential-transactions.md)
- [持久化队列、重试和会话](../client-spool.md)
- [有界子进程](../bounded-process.md)
- [文件句柄、原子发布和锁](../filesystem-handles.md)
- [Windows ACL 和服务身份](../windows-private-state.md)
- [移动 C/JNI ABI](../mobile-ffi.md)

## 结构与审查

- [公开模块和平台](../monolithic-client.md)
- [公共库与产品职责](../xcsc-boundary.md)
- [本机 Web 与服务端 Web](../client-web.md)
- [当前 unsafe 审查](../unsafe-audit.md)
- [0.10.0 逐函数审查记录](../unsafe-review-0.10.0.md)
- [仓库和发布来源](../split-origin.md)
- [1.0.0 发布说明](../releases/1.0.0.md)

审查中的历史测试数量对应其记录的源码；当前验证按[构建与测试](../development.md)执行。
