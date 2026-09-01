package com.yqsh.protectordemo

import com.yqsh.protector.shell.JniBridge

/**
 * Thin wrappers around the shell JNI. Call only after [isProtectorPacked] is true
 * so ART never loads this class (and thus libprotector) on unpacked builds.
 */
internal object ProtectorShell {
    fun nativeVersion(): String = JniBridge.nativeVersion()

    fun ensureBusinessSo(soBasename: String) {
        JniBridge.ensureBusinessSo(soBasename)
    }
}
