package com.yqsh.protectordemo

import android.app.Application
import android.util.Log
import com.yqsh.protector.shell.JniBridge

/**
 * Real application used before packing / restored after shell init.
 */
class DemoApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "DemoApplication.onCreate native=" + safeNativeVersion())
    }

    private fun safeNativeVersion(): String {
        return try {
            JniBridge.nativeVersion()
        } catch (t: Throwable) {
            "unavailable: ${t.message}"
        }
    }

    companion object {
        private const val TAG = "protector.DemoApp"
    }
}
