package com.yqsh.protector.shell;

import androidx.annotation.Keep;

@Keep
public final class JniBridge {
    static {
        System.loadLibrary("protector");
    }

    private JniBridge() {
    }

    /** Initialize runtime with extracted protector directory absolute path. */
    public static native void initApp(String protectorDir);

    /** ApplicationInfo.nativeLibraryDir — used to resolve basename loadLibrary paths. */
    public static native void setNativeLibraryDir(String nativeLibraryDir);

    /**
     * Enable JunkClass integrity checks after the application ClassLoader and
     * DexMerger are ready. Must not run earlier (false hang on incomplete multidex).
     */
    public static native void enableJunkVerify();

    /**
     * P1: parallel-restore hollow methods into extracted {@code classes*.dex}
     * under the protector cache dir before ART maps them.
     */
    public static native void prepatchExtractedDexes(String protectorDir);

    /** Read original Application class name from config. */
    public static native String readApplicationName();

    /** Native version / probe for debug. */
    public static native String nativeVersion();

    /** Verify APK signing certificate SHA-256 against config.app_sign_sha256. */
    public static native void verifySignature(android.content.Context context);

    /** Java→Native heartbeat.  Call periodically (~5 s).  If calls stop
     *  for > 15 s the native risk thread will kill the process. */
    public static native void heartbeat();

    /**
     * True when rasp_action=Degrade and a detector fired.
     * Apps can refuse high-risk operations without killing the process.
     */
    public static native boolean isEnvironmentDegraded();

    /**
     * Drain pending threat events as a JSON array
     * (e.g. [{"ts":...,"reason":"frida_port","rasp_action":2}, ...]).
     * Cleared after read. Also mirrored to {@code threats.log} under the
     * protector cache dir. Plug HTTP upload on the Java side if needed.
     */
    public static native String drainThreatReports();

    /**
     * Decrypt a business SO {@code .text} by basename (e.g. {@code libdemo_biz.so})
     * after {@code System.loadLibrary}. Complements dlopen hooks when the linker
     * bypasses hooked symbols. Throws {@link IllegalStateException} if the SO is
     * key-tracked but still encrypted after decrypt.
     */
    public static native void ensureBusinessSo(String soBasename);

    /**
     * After {@link DexMerger#merge}, schedule decrypt of already-mapped business
     * SOs on a background thread (must not race ART while mapping DEX).
     */
    public static native void finishBusinessSoDecrypt();

    /**
     * Decrypt a PAS1 asset blob ({@code PAS1 || AES-GCM}). Prefer
     * {@link ProtectorAssets#open(android.content.Context, String)}.
     */
    public static native byte[] decryptAssetBlob(byte[] pas1Blob);

    /**
     * Report a threat reason through the native RASP gate ({@code handle_risk}).
     * Honours {@code rasp_action}: Alert / Degrade / Block.
     */
    public static native void reportThreat(String reason);
}
