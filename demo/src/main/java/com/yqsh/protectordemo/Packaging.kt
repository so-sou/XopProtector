package com.yqsh.protectordemo

import android.content.Context

/**
 * Packed APKs ship [assets/protector/config.json] from the packer.
 * Unpacked Studio builds must not touch [com.yqsh.protector.shell.JniBridge]
 * (loading plaintext libprotector.so RC4-scrambles .bitcode → SIGILL).
 */
fun Context.isProtectorPacked(): Boolean {
    return try {
        assets.open("protector/config.json").close()
        true
    } catch (_: Exception) {
        false
    }
}
