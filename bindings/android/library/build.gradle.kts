plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

val sdkRoot = rootProject.projectDir.resolve("../../src/device-sdk").canonicalFile
val rustTarget = rootProject.layout.buildDirectory.dir("rust-target").get().asFile
val lock = sdkRoot.resolve("Cargo.lock").readText()
val verifierVersion =
    Regex("""name = "rustls-platform-verifier-android"\s+version = "([^"]+)"\s""")
        .find(lock)
        ?.groupValues
        ?.get(1) ?: error("Android verifier absent in Cargo.lock")

check(verifierVersion == "0.2.0") { "Review verifier Maven/native migration before changing pin" }

val buildRust by
    tasks.registering(Exec::class) {
        inputs.files(
            fileTree(sdkRoot) {
                include("**/*.rs", "**/Cargo.toml", "Cargo.lock")
                exclude("target/**")
            }
        )
        // The workspace patch lives outside sdkRoot; changes must invalidate native archives.
        inputs.files(fileTree(rootProject.projectDir.resolve("../../third_party/rust/nix-0.31.3")))
        inputs.files(fileTree(rootProject.projectDir.resolve("../../third_party/rust/rtc-0.21.1")))
        outputs.files(
            rustTarget.resolve("aarch64-linux-android/release/libdevice_ffi.a"),
            rustTarget.resolve("x86_64-linux-android/release/libdevice_ffi.a"),
        )
        commandLine("python3", rootProject.file("scripts/build-rust.py"), sdkRoot, rustTarget)
    }
val testTls = rootProject.layout.buildDirectory.dir("test-tls").get().asFile
val generateTestTls by
    tasks.registering(Exec::class) {
        inputs.file(rootProject.file("scripts/generate-test-tls.sh"))
        outputs.dir(testTls)
        commandLine("bash", rootProject.file("scripts/generate-test-tls.sh"), testTls)
    }

android {
    namespace = "io.peerloom.sdk"
    testNamespace = "io.peerloom.sdk.test"
    sourceSets.getByName("androidTest") {
        res.srcDir(testTls.resolve("res"))
        assets.srcDir(testTls.resolve("assets"))
    }
    compileSdk = 36
    ndkVersion = "29.0.14206865"
    defaultConfig {
        minSdk = 24
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
        externalNativeBuild {
            cmake {
                arguments +=
                    listOf(
                        "-DPEERLOOM_SDK_ROOT=${sdkRoot.path}",
                        "-DPEERLOOM_RUST_TARGET_DIR=${rustTarget.path}",
                        "-DANDROID_STL=c++_static",
                    )
                cppFlags += listOf("-std=c++17", "-Wall", "-Wextra", "-Werror")
            }
        }
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    packaging { jniLibs { useLegacyPackaging = false } }
    publishing { singleVariant("release") { withSourcesJar() } }
}

tasks.configureEach {
    if (name.contains("AndroidTest")) {
        dependsOn(generateTestTls)
    }
    if (name.startsWith("configureCMake") || name.startsWith("buildCMake") || name == "preBuild") {
        dependsOn(buildRust)
    }
}

dependencies {
    implementation("org.rustls:rustls-platform-verifier:$verifierVersion")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test:core:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("junit:junit:4.13.2")
}
