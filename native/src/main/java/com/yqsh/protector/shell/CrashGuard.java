package com.yqsh.protector.shell;

import android.util.Log;

import androidx.annotation.Keep;

/**
 * Phase 5 — chain {@link Thread.UncaughtExceptionHandler} without replacing the
 * app's handler. Reports a soft threat then delegates.
 */
@Keep
public final class CrashGuard {
    private static final String TAG = "protector.CrashGuard";
    private static volatile boolean installed;

    private CrashGuard() {
    }

    public static void install() {
        if (installed) {
            return;
        }
        installed = true;
        final Thread.UncaughtExceptionHandler prev = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
            try {
                String name = e != null ? e.getClass().getSimpleName() : "Throwable";
                JniBridge.reportThreat("uncaught_" + sanitize(name));
            } catch (Throwable ignored) {
            }
            if (prev != null) {
                prev.uncaughtException(t, e);
            } else {
                Log.e(TAG, "uncaught", e);
            }
        });
    }

    private static String sanitize(String s) {
        if (s == null || s.isEmpty()) {
            return "unknown";
        }
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '_') {
                sb.append(c);
            } else {
                sb.append('_');
            }
        }
        return sb.toString();
    }
}
