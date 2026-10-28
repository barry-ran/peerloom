# SDK 基础模块

本文说明 `src/device-sdk` 中的 `device-protocol` 和 `device-core`。真实传输适配见[原生传输模块](原生传输模块.md)；本文只描述协议与队列积木，不替代上层 SDK 和各平台验收。Rust 1.99.1，workspace 锁文件入库；协议与队列子模块本身不依赖网络运行时；device-core 新增身份与信令依赖见[SDK身份与信令模块](SDK身份与信令模块.md)。

```mermaid
flowchart LR
    Protocol[协议枚举 错误码 状态转换] --> Core[单一拥有者有界发送队列]
    Core --> Facade[已实现的身份 信令与 webrtc-rs facade]
```

协议模块提供会话状态、路径/通道/溢出类型与稳定错误码，中英展示文案分离。终态不可恢复，WSS 断开不自动等于会话关闭；这不是 REST/WSS 编解码器。

`SendQueue` 显式接收单调 `Instant`，配置消息数、payload 字节数、单消息大小、TTL 和溢出策略。默认工程值为 256 条、1 MiB payload、64 KiB 单条、30 秒 TTL，默认 `fail`。这些不是吞吐 SLA，也不是整个进程内存上限；队列元数据和分配器有额外开销。

可靠消息与低延迟消息可选丢旧/丢新，并返回丢弃结果；可靠字节流拒绝这两类策略，任何排队字节过期都会终止并清空队列。这些是队列本身的语义；实际 stream.v1 封包、传输背压和连接恢复分别由[原生传输模块](原生传输模块.md)及[SDK身份与信令模块](SDK身份与信令模块.md)实现，不能由纯队列测试推定网络验收通过。

入队获得字节所有权；成功只表示本地排队。超大消息不得驱逐既有数据，算术与时钟回退均显式检查。关闭幂等且不可逆。单次成功返回过期数，累计 `expired_messages_total()` 即便随后入队失败也保留清理统计，采用饱和计数防回绕。

队列没有内部锁或回调，上层并发需要 actor/锁串行化。客户端取消与可注入存储在身份模块单独实现；上层已实现 DeviceSdk facade、[C ABI](C语言接口模块.md)、[Android Kotlin](Android封装模块.md)和[Apple Swift](../bindings/ios/Apple封装说明.md)绑定，以及[平台安全存储](存储模块.md)。Windows/Linux 使用原生 Rust/C 接口；这些实现不等于所有平台生产签名、真机与长期运行场景已验收，具体边界见各模块。

当前 19 项测试覆盖状态转换矩阵、中英错误码、FIFO、大小与条数上限、TTL、三种溢出、可靠流终止、关闭、时钟、算术和循环记账；fmt、严格 clippy、release 构建通过。运行 `make check`，不可用这些基础测试替代 P2P/TURN 和授权端到端验收。
