# Peerloom Android

当前是待原生 CI 验证的候选封装，不是已验收的 Android 发布版。

详见 [Android 封装模块](../../docs/Android封装模块.md)。已有 Android SDK/NDK 的 Linux 构建机可运行：

```bash
./gradlew :library:assembleRelease :library:assembleDebugAndroidTest :sample:assembleDebug
```

配置需 HTTPS origin/application ID；先异步 `PeerloomSdk.create`，再 `start` 或 `register`。显式异步 `close` 完成前不能释放宿主回调依赖的资源。示例不内嵌凭证，不会自动连接生产环境。

安装身份契约使用 ABI 2：注册 JSON 为 `installation_tag`（非安全公钥），安装身份只有 `device_id` 与 `device_credential`，无到期时间或自动刷新。注册 grant、会话租约和 TURN 凭据仍保留各自 TTL。

Keystore 密钥、加密文件和锁保留原位置，密文格式版本升级为 2。旧格式或含旧字段的身份明确失败，不作空安装或自动迁移。AES-GCM、原子替换、CAS、tombstone 与工作线程要求不变；必须使用配套 ABI 2 原生库。
