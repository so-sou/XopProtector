package com.yqsh.protectordemo

import android.os.Bundle
import android.util.Log
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val tv = TextView(this)
        tv.textSize = 16f
        tv.setPadding(48, 48, 48, 48)
        try {
            Business.stamp = 1
            val secret = Business.secret()
            val sum = Business.add(40, 2)
            val score = Business.licenseScore(7, 11)
            val inv = Business.invokeProbe(20, 1)
            val field = Business.fieldProbe(41)
            val arr = Business.arrayProbe(10)
            val caught = Business.catchProbe(0)
            val okPath = Business.catchProbe(5)
            val so = Business.soProbe(40, 2)
            val f = Business.floatProbe(2.0f, 3.0f)
            val d = Business.doubleProbe(8.0, 2.0)
            val fcmp = Business.floatCmpProbe(1.0f, 2.0f)
            val sync = Business.syncProbe(20)
            val lsh = Business.longShiftProbe(8L, 2)
            val fcast = Business.floatCastProbe(Float.NaN)
            val asset = com.yqsh.protector.shell.ProtectorAssets.readString(this, "secret.txt").trim()
            val netOk = com.yqsh.protector.shell.NetGuard.isInstalled()
                    && com.yqsh.protector.shell.NetGuard.isDetectProxyEnabled()
                    && com.yqsh.protector.shell.NetGuard.pinCount() >= 1
                    && !com.yqsh.protector.shell.NetGuard.wasProxyDetected()
            val channel = com.yqsh.protector.shell.ChannelReader.getChannel(this)

            var expectScore = (7 + 11) * 3
            if (expectScore < 0) expectScore *= -1
            // R8 may fold array-length to +2 for IntArray(2)
            val expectArr = 10 + 3 + 2
            // (8<<2) | (8>>>2) = 32 | 2 = 34
            val ok = secret == "protector-ok-42"
                    && sum == 42
                    && score == expectScore
                    && inv == 42
                    && field == 42
                    && arr == expectArr
                    && caught == -7
                    && okPath == 10
                    && so == 42
                    && f == 7.5f
                    && d == 3.75
                    && fcmp == -1
                    && sync == 82
                    && lsh == 34L
                    && fcast == 0
                    && asset == "protector-asset-ok"
                    && netOk
                    && channel == "demo"
            val status = if (ok) getString(R.string.status_pass) else getString(R.string.status_fail)
            val msg = "secret=$secret add=$sum score=$score inv=$inv field=$field arr=$arr " +
                    "catch=$caught/$okPath so=$so f=$f d=$d fcmp=$fcmp sync=$sync lsh=$lsh fcast=$fcast " +
                    "asset=$asset " +
                    "net=installed/${com.yqsh.protector.shell.NetGuard.pinCount()}/proxy=${com.yqsh.protector.shell.NetGuard.wasProxyDetected()} " +
                    "channel=$channel status=$status"
            tv.text = msg.replace(' ', '\n')
            Log.i("protector-demo", msg)
        } catch (t: Throwable) {
            tv.text = getString(R.string.status_error, t.message ?: "")
            Log.e("protector-demo", "business failed", t)
        }
        setContentView(tv)
    }
}
