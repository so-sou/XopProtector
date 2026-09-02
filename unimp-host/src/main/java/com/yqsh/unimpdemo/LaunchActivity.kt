package com.yqsh.unimpdemo

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import io.dcloud.feature.sdk.DCUniMPSDK
import io.dcloud.feature.sdk.Interface.IUniMP
import io.dcloud.feature.unimp.config.IUniMPReleaseCallBack
import io.dcloud.feature.unimp.config.UniMPOpenConfiguration
import io.dcloud.feature.unimp.config.UniMPReleaseConfiguration
import java.io.File
import java.io.FileOutputStream

/**
 * Host entry: opens uni mini-program for XopProtector white-screen regression.
 *
 * Preference order:
 * 1) `__UNI__XOPDEMO` assets/apps (exported www) or assets wgt + [releaseWgtToRunPath]
 * 2) `__UNI__F743940` sample shipped from DCloud SDK DEMO (smoke)
 */
class LaunchActivity : Activity() {
    private var current: IUniMP? = null
    private var opening = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_launch)

        val status = findViewById<TextView>(R.id.statusText)
        val openBtn = findViewById<Button>(R.id.btnOpen)
        val appid = resolveAppId()
        status.text = buildString {
            appendLine("SDK: UniMP 5.14")
            appendLine("appid: $appid")
            appendLine("XOPDEMO assets: ${hasAssetApp(APPID_XOP)}")
            appendLine("XOPDEMO wgt: ${hasAssetWgt(APPID_XOP)}")
            appendLine("Sample F743940: ${hasAssetApp(APPID_SAMPLE)}")
            appendLine()
            appendLine("Filter logcat: XOP-DEMO WeexCore spinWaitPeer")
        }

        openBtn.setOnClickListener {
            UnimpDemoApp.whenSdkReady { openSelected(appid) }
        }

        // Wait for DCUniMPSDK pre-init (avoids early Weex framework.js races).
        UnimpDemoApp.whenSdkReady { openSelected(appid) }
    }

    private fun openSelected(appid: String) {
        if (opening) return
        opening = true
        when {
            hasAssetApp(appid) || DCUniMPSDK.getInstance().isExistsApp(appid) -> {
                openUniMp(appid)
                opening = false
            }
            hasAssetWgt(appid) -> releaseAssetWgtThenOpen(appid)
            else -> {
                Log.e(TAG, "[XOP-DEMO] no assets/wgt for $appid")
                Toast.makeText(this, "missing resources for $appid", Toast.LENGTH_LONG).show()
                opening = false
            }
        }
    }

    private fun releaseAssetWgtThenOpen(appid: String) {
        try {
            val wgtFile = copyAssetWgtToCache(appid)
            Log.i(TAG, "[XOP-DEMO] releaseWgtToRunPath appid=$appid path=${wgtFile.absolutePath}")
            val cfg = UniMPReleaseConfiguration().apply {
                wgtPath = wgtFile.absolutePath
            }
            DCUniMPSDK.getInstance().releaseWgtToRunPath(
                appid,
                cfg,
                IUniMPReleaseCallBack { code, args ->
                    runOnUiThread {
                        opening = false
                        if (code == 1) {
                            Log.i(TAG, "[XOP-DEMO] releaseWgt ok code=$code")
                            openUniMp(appid)
                        } else {
                            Log.e(TAG, "[XOP-DEMO] releaseWgt failed code=$code args=$args")
                            Toast.makeText(this, "releaseWgt failed: $code", Toast.LENGTH_LONG).show()
                        }
                    }
                },
            )
        } catch (t: Throwable) {
            opening = false
            Log.e(TAG, "[XOP-DEMO] releaseWgt exception", t)
            Toast.makeText(this, "releaseWgt error: ${t.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun copyAssetWgtToCache(appid: String): File {
        val out = File(cacheDir, "$appid.wgt")
        assets.open(assetWgtPath(appid)).use { input ->
            FileOutputStream(out).use { output -> input.copyTo(output) }
        }
        return out
    }

    private fun openUniMp(appid: String) {
        try {
            Log.i(TAG, "[XOP-DEMO] openUniMP appid=$appid")
            val cfg = UniMPOpenConfiguration()
            val uniMP = DCUniMPSDK.getInstance().openUniMP(this, appid, cfg)
            current = uniMP
            Toast.makeText(this, "opened $appid", Toast.LENGTH_SHORT).show()
        } catch (t: Throwable) {
            Log.e(TAG, "[XOP-DEMO] openUniMP failed", t)
            Toast.makeText(this, "open failed: ${t.message}", Toast.LENGTH_LONG).show()
        }
    }

    private fun resolveAppId(): String {
        return when {
            hasAssetApp(APPID_XOP) || hasAssetWgt(APPID_XOP) ||
                DCUniMPSDK.getInstance().isExistsApp(APPID_XOP) -> APPID_XOP
            hasAssetApp(APPID_SAMPLE) || DCUniMPSDK.getInstance().isExistsApp(APPID_SAMPLE) -> APPID_SAMPLE
            else -> APPID_SAMPLE
        }
    }

    private fun hasAssetApp(appid: String): Boolean {
        // AssetManager.list() may return empty array (not null) for missing paths —
        // require a real marker file under www/.
        if (assetExists("apps/$appid/www/manifest.json") ||
            assetExists("apps/$appid/www/app-config-service.js")
        ) {
            return true
        }
        val released = File(filesDir, "apps/$appid/www")
        return released.isDirectory && (released.list()?.isNotEmpty() == true)
    }

    private fun hasAssetWgt(appid: String): Boolean = assetExists(assetWgtPath(appid))

    private fun assetWgtPath(appid: String): String = "$appid.wgt"

    private fun assetExists(path: String): Boolean {
        return try {
            assets.open(path).use { true }
        } catch (_: Throwable) {
            false
        }
    }

    companion object {
        private const val TAG = "unimp.XopDemo"
        const val APPID_XOP = "__UNI__XOPDEMO"
        const val APPID_SAMPLE = "__UNI__F743940"
    }
}
