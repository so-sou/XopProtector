package com.yqsh.protector.shell;

import androidx.annotation.Keep;

/**
 * JNI entry for TRUE_VMP (PVM2) methods. DEX trampolines call
 * {@link #interpret(int, int, Object[])} instead of holding real Dalvik bodies.
 */
@Keep
public final class VmBridge {
    static {
        // libprotector may already be loaded by JniBridge; load is idempotent.
        System.loadLibrary("protector");
    }

    private VmBridge() {
    }

    /**
     * @param dexIndex  code.bin dex ordinal (0-based)
     * @param methodIdx method_ids index captured at pack time
     * @param args      boxed static parameters
     * @return boxed result (null for void)
     */
    public static native Object interpret(int dexIndex, int methodIdx, Object[] args);
}
