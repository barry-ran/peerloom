# Peerloom Android

当前是待原生 CI 验证的候选封装，不是已验收的 Android 发布版。

详见 [Android 封装模块](../../docs/Android封装模块.md)。已有 Android SDK/NDK 的 Linux 构建机可运行：

```bash
./gradlew :library:assembleRelease :library:assembleDebugAndroidTest :sample:assembleDebug
```

配置需 HTTPS origin/application ID；先异步 `PeerloomSdk.create`，再 `start` 或 `register`。显式异步 `close` 完成前不能释放宿主回调依赖的资源。示例不内嵌凭证，不会自动连接生产环境。
