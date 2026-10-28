pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        exclusiveContent {
            forRepository {
                maven {
                    url =
                        uri(
                            "https://raw.githubusercontent.com/rustls/rustls-platform-verifier/maven-archive/android-release-support/maven/"
                        )
                }
            }
            filter { includeGroup("org.rustls") }
        }
    }
}

rootProject.name = "peerloom-android"

include(":library", ":sample")
