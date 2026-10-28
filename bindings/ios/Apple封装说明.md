# Apple 原生封装

## 当前状态与交付边界

本目录提供 iOS 15+/macOS 12+ 的 Swift 源码封装、Keychain 存储、XCTest、独立 XCFramework 构建与验证入口。**Apple 原生门禁已在精确提交 `2db4a06d9748cd0fa127b5c0f7c4306e68855d6e` 实际通过，仍不是正式发布的 Apple SDK。** [真实运行](https://github.com/barry-ran/peerloom/actions/runs/40682077497) 包含五 slice XCFramework、macOS XCTest 10 项、Rust TLS 2 项、iOS Simulator XCTest 8 项及 unsigned device build；新提交仍需重新满足门禁。macOS 使用下文的隔离 DEBUG 文件 Keychain，iOS 使用 Xcode 生成的 Simulator 应用宿主；不能据此宣称生产签名 DP Keychain 宿主或真机已验证。 验证分支可开放 macOS/iOS C create，但必须在该同一版本通过原生门禁后才能晋升；主分支不能仅凭 Linux 检查通过开放。

封装只消费 `src/device-sdk/device-ffi/include/device_sdk.h`，不复制 Rust 内部布局或维护第二套手写 C 声明。生成的 XCFramework 复制这份规范头，并校验 SHA-256 一致；Swift package 链接其 `CPeerloom` 模块。已实现多连接、可靠消息/低延迟消息/字节流的 typed 通道与 reset 包装；默认 1 个会话、1 个活动通道，可各配置至 32，累计通道创建预算默认 8、最高 128。新增通道与暂停执行器安全回归尚须当前提交的 Xcode 原生门禁，不能沿用上述旧提交证明。硬件标识、独立 Agent、业务界面不在此封装内。

Swift package 要求 Swift 6.0 或更高编译器，保持 Swift 5 语言模式及 iOS 15/macOS 12 最低系统；不依赖仅新系统才有的 AsyncIterator 隔离协议 witness。固定 Xcode 16.4 提供相应编译器，最低系统声明不等于已在每个旧系统版本实测。

## 结构与线程

```mermaid
flowchart LR
    App[Swift 业务任务] --> API[PeerloomSDK async API]
    API --> NativeQueue[独立 native 调度队列]
    NativeQueue --> ABI[唯一 C ABI]
    ABI --> Callback[串行回调 立即复制借用字节]
    Callback --> Completions[请求终态映射 最多32]
    Callback --> Events[有界事件 单消费者]
    Events --> Gate[同步consumePayload重验父子有效性]
    Gate --> App
    Callback --> StoreQueue[独立 Keychain IO队列 最多8请求]
    StoreQueue --> Lock[跨进程flock]
    Lock --> Keychain[单项原子CAS与tombstone]
```

- `open` 在后台创建原生线程和存储适配；所有 `SecItem*`、文件锁与存储 IO 在专用后台队列。直接在主线程调用存储适配会拒绝，不弹解锁 UI。
- C event/payload 指针只在 callback 中借用；Swift 复制后才排队，回调不等待下一个回调或 Keychain。
- 最多 32 个已接受且尚未消费终态的 Swift 操作；completion 可以早于 C submit 返回，因此调用与 request 登记在同一锁内完成，回调在登记后查找。字节流 `read` 将调用者 isolation 显式传至 core，恢复后再检查 child gate；检查至返回之间没有新的 await，信用也不在 C callback 时提前释放。结果只报告固定错误码，不把凭证写入错误文本。
- 普通事件与消息分别最多 32 个，已经从 `next()` 取出但未消费的事件仍占用额度；事件副本共享单次消费状态与同一额度，消费或最后释放后归还。宿主不消费导致溢出时停止实例，不静默丢可靠消息后继续假装健康。`PeerloomEvents` 只支持一个并发 `next()`。
- `next()` 仅预先过滤失效事件，不能保证旧 AsyncIterator 的返回值不会再次排队到调用者 actor。事件字节保持私有，应用须在实际使用处同步调用一次 `consumePayload()`；它重新检查 Ready/Message 的父连接或通道 gate，过期、关闭或 shutdown 则抛错，不交付字节。`incomingChannel(from:)` 会消费 CHANNEL_READY 的元数据，不要先消费同一事件。只读查询不续租；同步消费成功后的再次排队/保存属于业务自己的字节所有权，SDK 不能追回已交付数据。
- 取消只请求取消尚未执行的操作。运行中的注册/轮换可能已提交，不能伪称远端回滚；等待真实终态。注册调用方须保留原注册输入和幂等键，当前没有跨进程崩溃的 mutation journal。

## 关闭与 context 生命周期

```mermaid
stateDiagram-v2
    [*] --> Created
    Created --> Running: open成功
    Running --> Stopping: close/永久失败/宿主队列溢出
    Stopping --> NativeFinal: 结算操作与最终C回调
    NativeFinal --> Quiescent: 宿主存储任务完成且native state=2
    Quiescent --> Released: dp_sdk_release返回OK
    Released --> [*]: 释放保留的Swift context
```

context 以 `Unmanaged.passRetained` 保留，只有 C runtime/callback 静止、宿主存储任务结束且 `release` 成功后才释放。`close()` 等待此边界；取消等待或 Swift 外层对象析构不会提前销毁 context。析构仅启动安全关闭，调用方仍应显式 `await close()`。自动停止同样进入清理。回调或系统调用永久卡住时不提供强杀线程或固定时限释放承诺。

C 库代码在成功 release 前必须保持加载。所有已经接受的普通操作会得到实际终态；连接关闭一旦接受就不可取消。后台存储在 native shutdown 期间仍处理已发请求，超时/取消允许完整旧 snapshot 或完整新 snapshot，绝不通过局部写入模拟成功。

## Keychain CAS 与访问控制

默认使用数据保护 Keychain：macOS 显式设置 `kSecUseDataProtectionKeychain`，iOS 使用系统唯一实现。凭证采用 `WhenUnlockedThisDeviceOnly`、不参与 iCloud 同步；`LAContext.interactionNotAllowed` 禁止隐式认证 UI。锁定、缺 entitlement、不可用或损坏都失败关闭，**不当作空存储、不回落 UserDefaults/明文文件**。Apple 对可访问类别的说明明确此类别只在解锁时访问，且不迁移到新设备。[可访问类别](https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly)、[禁止认证交互](https://developer.apple.com/documentation/localauthentication/lacontext/interactionnotallowed)

- scope 为 Rust 规范化的服务器 origin + application UUID；账户名只保存其 SHA-256。完整 snapshot（format、scope、revision、identity 或 null）放在一个 generic-password 项中；revision 同时放入 `kSecAttrGeneric` 作为条件更新依据。
- `save/delete` 都检查期望 revision，成功严格增加 1；delete 保存 identity=null 的 tombstone，不删除 revision。溢出拒绝，不重置为零。
- 锁文件位于当前应用支持目录的 0700 子目录，文件 0600、`O_NOFOLLOW`、要求普通单硬链文件；`flock` 有 2 秒尝试期限。共享 access group 必须显式提供所有参与进程一致的 app-group 锁目录；SDK 不猜 Team ID 或申请额外 entitlement。
- 持有跨进程锁后读当前 snapshot，再使用 `SecItemAdd` 唯一约束或带旧 revision 条件的 `SecItemUpdate` 一次更新数据与 revision。即使误配成不同锁目录，Keychain 条件更新也不能让两个旧 revision 写入都成功。Apple 说明 update 以查询属性匹配并原子修改所选项；这些行为仍由真实并发测试验证。[SecItemUpdate](https://developer.apple.com/documentation/security/secitemupdate(_:_:))、[Apple SecItem 注意事项](https://developer.apple.com/forums/thread/724013)
- 锁文件只协调提交，不含凭证。Swift String/Data 的内存副本不提供可验证的零化保证；本实现不声称密钥始终位于 Secure Enclave。

macOS 的数据保护 Keychain 依赖宿主用户登录上下文和获授权的签名 entitlement，不适用于任意无用户会话 daemon。测试专用 DEBUG/SPI 初始化器指向独立文件 Keychain，**不会修改默认/登录 Keychain 或全局搜索列表**；它用于可重复的 CAS、锁定和跨进程测试，不冒充生产 DP Keychain 的 entitlement 验证。[Apple TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)

iOS 卸载后 Keychain 可能保留；本封装不会依据一个丢失的普通文件擅自清除已有 Keychain 身份，也不承诺检测卸载重装。重启/升级读取原 snapshot；存储真正丢失后需要新的受控注册。宿主直接调用存储 delete 并不撤销服务端凭证。当前 Swift `resetIdentity(expectedDeviceID:retry:)` 通过 C ABI 关闭旧权限并写入 CAS tombstone，成功后还需显式新注册；不转移旧授权，也不等于服务端吊销旧设备。新增 reset 包装需通过当前原生门禁。

## 接入

`Examples/最小接入.swift` 演示开关生命周期。正常运行使用 HTTPS/WSS 与系统信任链，不存在跳过证书验证选项；`developmentLoopback` 默认 false，只供明确开发 IP 回环例外。首装注册 grant 来自有权客户后端，不可内嵌长期管理 key。

```swift
let config = PeerloomConfiguration(origin: "https://signal.example.com/", applicationID: appID)
let sdk = try await PeerloomSDK.open(configuration: config)
let deviceID = try await sdk.start() // 已有身份；首装显式传 registration + 保留的 idempotencyKey
// connect completion != connected；等待 Ready。incoming 必须由业务明确决定 accept。
try await sdk.close()
```

后台/锁屏时平台可能挂起应用或拒绝 Keychain；本封装不保证后台常驻连接。WSS 重连不会延长旧授权，平台暂停后的租约边界和真机锁屏行为仍需单独验收。

## 原生构建与验收门禁

脚本固定 Xcode **16.4 / 16F6**、Rust **1.99.1**；官方 `macos-15` arm64 runner 镜像列出该 Xcode 路径。runner 镜像仍滚动更新，构建记录实际 ImageVersion 与 SDK 版本，不能称不可变运行环境。[GitHub runner 官方清单](https://github.com/actions/runner-images/blob/main/images/macos/macos-15-arm64-Readme.md)

```sh
export DEVELOPER_DIR=/Applications/Xcode_16.4.app/Contents/Developer
export PEERLOOM_REPO_ROOT="$PWD"
export PEERLOOM_APPLE_OUTPUT="$PWD/dist/apple-validation" # 必须不存在
# 由受控CI预先安装固定Rust和五个Apple targets；脚本不自动下载大工具链。
bindings/ios/scripts/build-xcframework.sh
bindings/ios/scripts/test-native.sh
```

XCFramework 包含独立的 iOS device arm64、iOS simulator arm64+x86_64、macOS arm64+x86_64 分片，只在同一平台内用 lipo，绝不把 device/simulator arm64 混在一个 fat archive。Swift 源码 package 与原生 `CPeerloom.xcframework` 一同交付，设备构建不等于真机运行。遵循 [Apple XCFramework 指南](https://developer.apple.com/documentation/xcode/creating-a-multi-platform-binary-framework-bundle)。

验收必须实际执行：macOS Swift/XCTest、独立临时 Keychain 锁定失败和两进程 CAS、真实 C create/load/shutdown、宿主排队后过期重验、宿主事件溢出、macOS Rust 系统 TLS 负向，以及 Swift macOS/iOS 两次真实自签握手拒绝（服务器侧计数，绝不安装信任根）；iOS 18.5 模拟器 XCTest/DP Keychain；unsigned iOS device build 与三类 XCFramework 结构。真机签名/安装、真机锁屏、后台暂停、生产 entitlement、完整双端 Swift 通信尚不能仅由这些门禁替代。

iOS 测试使用 `SimulatorHost` 中的空应用宿主和显式 XCTest target，直接引用原有 `KeychainTests.swift` / `NativeCoreTests.swift`，保留原 8 项并加入 typed 通道、延后消费/信用及暂停 actor 回归，当前共 12 项。裸 SwiftPM 测试由 Xcode `xctest` agent 托管，实际返回 `errSecMissingEntitlement` 时不能归咎为锁文件失败或改用明文存储。标准 `TEST_HOST` 将测试注入本次构建的应用 executable。[Apple TEST_HOST 定义](https://developer.apple.com/documentation/xcode/build-settings-reference)、[Keychain entitlement 错误](https://developer.apple.com/documentation/security/errsecmissingentitlement)

此夹具仅支持 `iphonesimulator`，使用本地 ad-hoc Simulator 签名；不设置虚构 Team ID、不导入证书、不请求 provisioning profile。Keychain group 由 Xcode 展开标准 `$(AppIdentifierPrefix)$(PRODUCT_BUNDLE_IDENTIFIER)`，门禁检查实际 xctestrun 宿主及 Xcode 生成的 `.xcent`；Simulator entitlement 也可能被放入 Mach-O，而非代码签名，因此只看 `codesign` 不能冒充完整权限验收。应用宿主只是测试容器，没有业务 UI。该宿主已在上述精确提交中通过真实 CI；新增测试仍须当前门禁确认，不能外推为真机或生产 macOS DP 签名权限通过。

为尽快定位模拟器问题，CI 先构建独立单 arm64 Simulator 诊断包并执行相同 12 项测试；此产物不是发布 XCFramework。诊断通过后仍须完成全部五 slice 构建与全部原生门禁，失败不会跳过检查晋级。

Linux 可运行 `python3 bindings/ios/scripts/test-static.py`，只覆盖打包平台/头一致性与脚本拒绝伪构建。既有 Swift/Keychain/Xcode 用例已有上述真实证据；当前 macOS 严格 14 项及 iOS 12 项等新增组合仍标**待当前原生 CI 验证**。产物保留项目 MIT；第三方按自身许可，已有 notice/SBOM 的缺项及非法律清关状态继续保留。
