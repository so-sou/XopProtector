package com.yqsh.unimpdemo

import android.app.Application
import android.content.Context
import android.util.Log
import androidx.multidex.MultiDex
import io.dcloud.feature.sdk.DCSDKInitConfig
import io.dcloud.feature.sdk.DCUniMPSDK
import io.dcloud.feature.sdk.Interface.IOnUniMPEventCallBack
import io.dcloud.feature.sdk.MenuActionSheetItem
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean

class UnimpDemoApp : Application() {
    override fun attachBaseContext(base: Context) {
        MultiDex.install(base)
        super.attachBaseContext(base)
    }

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "[XOP-DEMO] Application.onCreate")

        val sheetItems = listOf(
            MenuActionSheetItem("关于", "about"),
            MenuActionSheetItem("当前页面", "current_page"),
        )
        val config = DCSDKInitConfig.Builder()
            .setCapsule(true)
            .setMenuDefFontSize("16px")
            .setMenuDefFontColor("#333333")
            .setMenuDefFontWeight("normal")
            .setMenuActionSheetItems(sheetItems)
            .setEnableBackground(true)
            .setUniMPFromRecents(true)
            .build()

        DCUniMPSDK.getInstance().setOnUniMPEventCallBack(
            IOnUniMPEventCallBack { appid, event, data, callback ->
                if (event == "xop-probe") {
                    Log.i(TAG, "[XOP-DEMO] page-show from native-event appid=$appid data=$data")
                    // Also emit a flat page-show line for verify scripts.
                    val page = extractPage(data)
                    if (page != null) {
                        Log.i(TAG, "[XOP-DEMO] page-show:$page")
                    } else if (data?.toString()?.contains("launch") == true) {
                        Log.i(TAG, "[XOP-DEMO] onLaunch (native-event) $data")
                    }
                } else {
                    Log.i(TAG, "[XOP-DEMO] uniMP event=$event appid=$appid data=$data")
                }
                try {
                    callback?.invoke("ok")
                } catch (_: Throwable) {
                }
            },
        )

        DCUniMPSDK.getInstance().initialize(this, config) { ok ->
            Log.i(TAG, "[XOP-DEMO] DCUniMPSDK onInitFinished=$ok")
            markSdkReady(ok || DCUniMPSDK.getInstance().isInitialize)
        }
    }

    companion object {
        private const val TAG = "unimp.XopDemo"

        private val ready = AtomicBoolean(false)
        private val waiters = CopyOnWriteArrayList<() -> Unit>()

        fun whenSdkReady(block: () -> Unit) {
            if (ready.get() || DCUniMPSDK.getInstance().isInitialize) {
                ready.set(true)
                block()
                return
            }
            waiters.add(block)
        }

        private fun markSdkReady(ok: Boolean) {
            if (!ok) {
                Log.w(TAG, "[XOP-DEMO] SDK init not ready yet (child proc or race)")
            }
            ready.set(true)
            val pending = waiters.toList()
            waiters.clear()
            pending.forEach {
                runCatching { it() }.onFailure { t ->
                    Log.e(TAG, "[XOP-DEMO] whenSdkReady callback failed", t)
                }
            }
        }

        private fun extractPage(data: Any?): String? {
            if (data == null) return null
            return try {
                when (data) {
                    is Map<*, *> -> data["page"]?.toString()
                    is org.json.JSONObject -> data.optString("page", null)
                    else -> {
                        val m = Regex("""page[=:]?\s*([a-z0-9_-]+)""", RegexOption.IGNORE_CASE)
                            .find(data.toString())
                        m?.groupValues?.getOrNull(1)
                    }
                }
            } catch (_: Throwable) {
                null
            }
        }
    }
}
