plugins {
    id("com.android.application") version "8.2.2" apply false
    id("com.android.library") version "8.2.2" apply false
    id("org.jetbrains.kotlin.android") version "1.9.22" apply false
}

import java.nio.file.Files
import java.nio.file.StandardCopyOption

tasks.register("exportShellFiles") {
    group = "protector"
    description = "Export shell classes.dex and .so into executable/shell-files"
    dependsOn(":native:assembleRelease")

    doLast {
        val outRoot = rootProject.file("executable/shell-files")
        val dexOut = File(outRoot, "dex")
        val libsOut = File(outRoot, "libs")
        dexOut.mkdirs()
        // Wipe libs so stale ABIs (x86 leftovers) cannot be packed.
        if (libsOut.exists()) libsOut.deleteRecursively()
        libsOut.mkdirs()
        // Drop legacy "lib/" so packer never picks a stale copy over "libs/".
        File(outRoot, "lib").takeIf { it.exists() }?.deleteRecursively()

        fun findJar(): File? {
            val root = rootProject.file("native/build/intermediates")
            if (!root.exists()) return null
            return root.walkTopDown()
                .filter { it.isFile && it.name == "classes.jar" && it.path.contains("release") }
                .maxByOrNull { it.lastModified() }
        }

        val jar = findJar() ?: throw GradleException("native classes.jar not found. Build :native first.")

        val sdkDir = run {
            val lp = rootProject.file("local.properties")
            var dir: String? = null
            if (lp.exists()) {
                lp.readLines().forEach {
                    if (it.startsWith("sdk.dir=")) {
                        dir = it.substringAfter("=").replace("\\:", ":").replace("\\\\", "\\")
                    }
                }
            }
            dir ?: System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT")
        } ?: throw GradleException("Android SDK not found")

        val buildTools = File(sdkDir, "build-tools").listFiles()?.filter { it.isDirectory }?.maxByOrNull { it.name }
            ?: throw GradleException("build-tools not found")
        val d8 = if (System.getProperty("os.name").lowercase().contains("windows")) {
            File(buildTools, "d8.bat")
        } else {
            File(buildTools, "d8")
        }

        val tmpDexDir = File(outRoot, "tmp-dex")
        if (tmpDexDir.exists()) tmpDexDir.deleteRecursively()
        tmpDexDir.mkdirs()

        exec {
            commandLine(d8.absolutePath, "--output", tmpDexDir.absolutePath, jar.absolutePath)
        }
        val produced = tmpDexDir.listFiles()?.firstOrNull { it.name.endsWith(".dex") }
            ?: throw GradleException("d8 did not produce dex")
        Files.copy(produced.toPath(), File(dexOut, "classes.dex").toPath(), StandardCopyOption.REPLACE_EXISTING)
        tmpDexDir.deleteRecursively()
        println("Exported shell dex -> ${File(dexOut, "classes.dex").absolutePath}")

        fun findLibRoot(): File? {
            val root = rootProject.file("native/build/intermediates")
            if (!root.exists()) return null
            // Prefer stripped release libs (much smaller); fall back to merged.
            val stripped = root.walkTopDown()
                .filter {
                    it.isDirectory && it.name == "lib" &&
                            it.path.contains("stripped_native_libs") &&
                            it.path.contains("release")
                }
                .firstOrNull()
            if (stripped != null) return stripped
            val merged = root.walkTopDown()
                .filter {
                    it.isDirectory && it.name == "lib" &&
                            it.path.contains("merged_native_libs") &&
                            it.path.contains("release")
                }
                .firstOrNull()
            if (merged != null) {
                println("WARNING: stripped_native_libs not found; using merged_native_libs (larger)")
            }
            return merged
        }
        val libRoot = findLibRoot() ?: throw GradleException("native libs not found")
        println("Exporting shell libs from ${libRoot.absolutePath}")
        libRoot.listFiles()?.filter { it.isDirectory }?.forEach { abiDir ->
            val dst = File(libsOut, abiDir.name)
            dst.mkdirs()
            abiDir.listFiles()?.filter { it.name.endsWith(".so") }?.forEach { so ->
                Files.copy(so.toPath(), File(dst, so.name).toPath(), StandardCopyOption.REPLACE_EXISTING)
                println("Exported ${abiDir.name}/${so.name} (${so.length()} bytes)")
            }
        }

        // libprotector.so NEEDED libshadowhook.so, but :native packaging excludes it
        // (prefab supplies it for app modules). Packer must still embed it for third-party APKs.
        fun findShadowhookSo(abi: String): File? {
            fun score(f: File): Int {
                val p = f.path
                return when {
                    p.contains("stripped_native_libs") -> 5
                    p.contains("RelWithDebInfo") || p.contains("${File.separator}release${File.separator}") -> 3
                    p.contains("${File.separator}Release${File.separator}") -> 3
                    p.contains("Debug") || p.contains("${File.separator}debug${File.separator}") -> 1
                    else -> 2
                }
            }
            fun searchUnder(dir: File): File? {
                if (!dir.exists()) return null
                return dir.walkTopDown()
                    .filter {
                        it.isFile && it.name == "libshadowhook.so" &&
                                it.path.contains("${File.separator}$abi${File.separator}")
                    }
                    .maxWithOrNull(compareBy<File> { score(it) }.thenBy { it.lastModified() })
            }
            // Prefer stripped demo / native packaging outputs first.
            searchUnder(rootProject.file("demo/build/intermediates/stripped_native_libs"))
                ?.let { return it }
            searchUnder(rootProject.file("native/build/intermediates/stripped_native_libs"))
                ?.let { return it }
            val cxx = rootProject.file("native/build/intermediates/cxx")
            if (cxx.exists()) {
                cxx.walkTopDown()
                    .filter {
                        it.isFile && it.name == "libshadowhook.so" &&
                                it.path.contains("${File.separator}obj${File.separator}$abi")
                    }
                    .maxWithOrNull(compareBy<File> { score(it) }.thenBy { it.lastModified() })
                    ?.let { return it }
            }
            searchUnder(rootProject.file("demo/build/intermediates/merged_native_libs"))
                ?.let { return it }
            return null
        }
        libsOut.listFiles()?.filter { it.isDirectory }?.forEach { abiDir ->
            val dest = File(abiDir, "libshadowhook.so")
            if (dest.exists()) return@forEach
            val src = findShadowhookSo(abiDir.name)
            if (src == null) {
                // bytehook only links shadowhook on arm/arm64; x86/x86_64 must still export.
                val arm = abiDir.name == "armeabi-v7a" || abiDir.name == "arm64-v8a"
                if (arm) {
                    throw GradleException(
                        "libshadowhook.so not found for ${abiDir.name}. Build :native first."
                    )
                }
                println("Skip libshadowhook.so for ${abiDir.name} (not linked on this ABI)")
                return@forEach
            }
            Files.copy(src.toPath(), dest.toPath(), StandardCopyOption.REPLACE_EXISTING)
            println("Exported ${abiDir.name}/libshadowhook.so (from ${src.absolutePath})")
        }
    }
}

tasks.register("protectDemo") {
    group = "protector"
    description = "Build demo, export shell, pack+sign protected APK (debug keystore + channel)"
    dependsOn(":demo:assembleRelease", "exportShellFiles", ":packer:jar")
    doLast {
        val demoApk = fileTree("demo/build/outputs/apk/release") { include("*.apk") }.files.firstOrNull()
            ?: throw GradleException("demo release apk not found")
        val packerJar = rootProject.file("packer/build/libs").listFiles()
            ?.filter { it.name.startsWith("protector-packer") && it.name.endsWith(".jar") }
            ?.maxByOrNull { it.lastModified() }
            ?: throw GradleException("packer jar not found")
        println("Using packer jar: ${packerJar.name}")
        val outApk = rootProject.file("executable/demo-protected.apk")
        outApk.parentFile.mkdirs()
        val debugKs = file("${System.getProperty("user.home")}/.android/debug.keystore")
        if (!debugKs.isFile) {
            throw GradleException("debug keystore not found: ${debugKs.absolutePath}")
        }
        exec {
            commandLine(
                "java", "-jar", packerJar.absolutePath,
                demoApk.absolutePath,
                "-o", outApk.absolutePath,
                "--shell-dir", rootProject.file("executable/shell-files").absolutePath,
                // Only Business: DexPool trampoline rewrite must not touch Activity/Application
                // bodies that were hollowed to return stubs (causes VerifyError on Android 14+).
                "--hollow-prefix", "Lcom/yqsh/protectordemo/Business;",
                "--true-vmp-prefix", "Lcom/yqsh/protectordemo/Business;",
                "--protect-so",
                // Assets encrypt / res-protect / NetGuard temporarily off (code kept; demo no longer requires them).
                "--no-encrypt-assets",
                "--no-res-protect",
                "--keystore", debugKs.absolutePath,
                "--alias", "androiddebugkey",
                "--storepass", "android",
                "--keypass", "android"
            )
        }
        println("Protected demo APK -> ${outApk.absolutePath}")
    }
}
