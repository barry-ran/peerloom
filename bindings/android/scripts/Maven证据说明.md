# Maven 依赖证据采集

该任务只采集已经解析的 Maven 两种配置：releaseRuntimeClasspath 与 debugAndroidTestRuntimeClasspath。它不替代 Cargo/原生依赖清单，也不是法律清关或精确 AAR 链接证明。

在 `library/build.gradle.kts` 增加：

```kotlin
apply(from = rootProject.file("scripts/maven-evidence.gradle"))
```

正常固定版本构建结束后执行（不重新升级依赖；采集阶段强制离线）：

```sh
./gradlew --no-daemon --offline :library:collectMavenEvidence
python3 scripts/collect-maven-evidence.py \
  --input build/maven-evidence-input.json \
  --output "$(realpath -m ../../dist/android/maven-evidence)"
```

输出目录必须不存在。返回 0 表示已收集、仍待法律审查；2 表示缺失原文或 POM，必须保留 incomplete 报告；1 表示采集输入或安全校验失败，不可当作可用证据。后续受控补证需要明确每个组件的上游来源、不可变版本、原文 SHA256 与独立审阅，不接受单凭 SPDX 名称或许可证 URL 自动补齐，也不联网抓取 POM 中任意地址。

证据保留各配置直接/传递依赖关系、原始 AAR/JAR SHA256、POM 原文与 SHA256、未经改写的包内 LICENSE/NOTICE、CycloneDX 1.6 组件清单。缺少 LICENSE/COPYING 原文时，即使存在 NOTICE 或 POM 声明也保持 incomplete。POM 的许可证声明不等同法律分类，父 POM 继承未自动解释。AAR 内嵌 classes.jar 的许可证未递归采集，外层无许可证时仍明确缺失。

Gradle 使用固定 8.13 的公开 [ArtifactResolutionQuery/POM API](https://docs.gradle.org/8.13/javadoc/org/gradle/api/artifacts/query/ArtifactResolutionQuery.html)，仅查询已解析组件，离线缺 POM 时记录缺失，不执行依赖代码。输入清单含本机 cache 路径，仅供本机检查，禁止作为发布产物；最终报告不包含绝对缓存路径。

本地 Python 安全夹具测试覆盖原文、配置范围、hash 篡改、路径越界、symlink、XML entity、ZIP traversal、缺原文与缺 POM。当前环境没有 Gradle 8.13/Android 缓存，真实 Gradle task 尚待精确候选 CI 验证；不能将 Python 测试作为实际 Maven 全量采集成功。
