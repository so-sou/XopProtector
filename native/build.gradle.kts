plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.yqsh.protector"
    compileSdk = 34

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")

        externalNativeBuild {
            cmake {
                cppFlags += listOf("-std=c++20", "-fvisibility=hidden")
                val llvmObf = (project.findProperty("protector.llvmObf") as String?)
                    ?.equals("true", ignoreCase = true) == true
                val llvmObfVm = (project.findProperty("protector.llvmObfVm") as String?)
                    ?.equals("true", ignoreCase = true) == true
                val srcObf = (project.findProperty("protector.srcObf") as String?)
                    ?.equals("false", ignoreCase = true) != true
                val args = mutableListOf(
                    "-DANDROID_STL=c++_shared",
                    "-DDOBBY_GENERATE_SHARED=OFF",
                    "-DDOBBY_DEBUG=OFF",
                    "-DPROTECTOR_LLVM_OBF=${if (llvmObf) "ON" else "OFF"}",
                    "-DPROTECTOR_LLVM_OBF_VM=${if (llvmObfVm) "ON" else "OFF"}",
                    "-DPROTECTOR_SRC_OBF=${if (srcObf) "ON" else "OFF"}"
                )
                val obfFlags = project.findProperty("protector.llvmObfFlags") as String?
                if (!obfFlags.isNullOrBlank()) {
                    // Pass as CMake list using ';' separators (Gradle property uses ',').
                    args += "-DPROTECTOR_LLVM_OBF_FLAGS=${obfFlags.replace(',', ';')}"
                }
                arguments(*args.toTypedArray())
                abiFilters += listOf("armeabi-v7a", "arm64-v8a")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isJniDebuggable = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
            // Prefab already pulls shadowhook into the app; avoid duplicating from CMake link output
            excludes += setOf("**/libshadowhook.so", "**/libshadowhook_nothing.so")
        }
    }

    buildFeatures {
        prefab = true
    }
}

dependencies {
    implementation("androidx.annotation:annotation:1.7.1")
    // Required by bytehook on arm/arm64 (dl init/fini monitor)
    implementation("com.bytedance.android:shadowhook:1.1.1")
}
