package com.yqsh.protector.shell;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.util.Log;

import androidx.annotation.Keep;

import java.io.File;
import java.lang.reflect.Field;

/**
 * Point native lib search at protector {@code so_plain} so encrypted business SOs
 * resolve to materialized plaintext.
 * <p>
 * {@link ApplicationInfo#nativeLibraryDir} is redirected to {@code so_plain} so
 * path-sensitive native code sees keyed SOs under the app's lib dir. Keyed
 * {@code dlopen} still prefers L1/L2 extract-path equivalence (see
 * {@code docs/so-load-contract.md}).
 * <p>
 * Non-keyed deps in {@code so_plain} are <b>symlinks</b> to the packaged extract
 * (native {@code copy_plain_deps}) — same inode as {@code /data/app/.../lib},
 * avoiding dual {@code libc++_shared} / GLES mappings that broke large OSG SOs.
 * <p>
 * ClassLoader still prepends {@code so_plain} so basename {@code loadLibrary}
 * finds plaintext when dlopen hooks fail; packaged extract remains a fallback
 * for excluded / unkeyed libs.
 * <p>
 * APK-agnostic — no customer package names.
 */
@Keep
final class NativeLibDirRedirect {
    private static final String TAG = "protector.SoDir";

    private NativeLibDirRedirect() {
    }

    static void apply(Context context, File protectorDir) {
        if (context == null || protectorDir == null) return;
        ApplicationInfo ai = context.getApplicationInfo();
        File plain = apply(ai, protectorDir);
        if (plain == null) return;
        try {
            Object loadedApk = getField(context, "mPackageInfo");
            if (loadedApk == null) {
                loadedApk = getField(context.getApplicationContext(), "mPackageInfo");
            }
            bindLoadedApkPlain(loadedApk, plain.getAbsolutePath());
            patchClassLoader(context.getClassLoader(), plain.getAbsolutePath());
        } catch (Throwable t) {
            Log.w(TAG, "LoadedApk bind skipped", t);
        }
    }

    /**
     * Used from AppComponentFactory before a Context exists.
     * Callers must {@code setNativeLibraryDir(packaged)} <b>before</b> this so
     * native materialize still reads ciphertext from the extract dir.
     * @return {@code so_plain} dir if usable, else null
     */
    static File apply(ApplicationInfo ai, File protectorDir) {
        if (ai == null || protectorDir == null) return null;
        File plain = new File(protectorDir, "so_plain");
        if (!plain.isDirectory()) {
            return null; // protect-so off or no keyed SOs
        }
        String original = ai.nativeLibraryDir;
        if (original == null || original.isEmpty()) return plain;
        String plainPath = plain.getAbsolutePath();
        if (plainPath.equals(original)) {
            return plain;
        }
        ai.nativeLibraryDir = plainPath;
        Log.i(TAG, "nativeLibraryDir -> so_plain: " + plainPath
                + " (packaged was " + original + ")");
        return plain;
    }

    /**
     * Prepend {@code so_plain} on the ClassLoader native lib path so keyed
     * basename loads resolve plaintext before packaged ciphertext.
     */
    static void patchClassLoader(ClassLoader cl, String plainDir) {
        patchClassLoader(cl, plainDir, null);
    }

    static void patchClassLoader(ClassLoader cl, String plainDir, String packagedDir) {
        if (cl == null || plainDir == null || plainDir.isEmpty()) return;
        try {
            Object pathList = getField(cl, "pathList");
            if (pathList == null) return;
            Object dirsObj = getField(pathList, "nativeLibraryDirectories");
            if (dirsObj instanceof java.util.List) {
                @SuppressWarnings("unchecked")
                java.util.List<File> dirs = (java.util.List<File>) dirsObj;
                File plain = new File(plainDir);
                dirs.remove(plain);
                dirs.add(0, plain);
                // Packaged extract as fallback (excluded / non-keyed SOs still live there).
                // GLES stubs must not be loaded from there after system GLES is bound —
                // native copy_plain_deps never plants GLES in so_plain.
                if (packagedDir != null && !packagedDir.isEmpty()) {
                    File packaged = new File(packagedDir);
                    dirs.remove(packaged);
                    if (dirs.size() <= 1) {
                        dirs.add(packaged);
                    } else {
                        dirs.add(1, packaged);
                    }
                }
            }
            try {
                java.lang.reflect.Method makePathElements = pathList.getClass()
                        .getDeclaredMethod("makePathElements", java.util.List.class);
                makePathElements.setAccessible(true);
                @SuppressWarnings("unchecked")
                java.util.List<File> dirs = (java.util.List<File>) getField(pathList, "nativeLibraryDirectories");
                Object elements = makePathElements.invoke(null, dirs);
                setField(pathList, "nativeLibraryPathElements", elements);
            } catch (NoSuchMethodException e) {
                // Older API: makePathElements(List, File, List) for dex — skip
            }
            Log.i(TAG, "ClassLoader native lib path: so_plain first; plain=" + plainDir);
        } catch (Throwable t) {
            Log.w(TAG, "patchClassLoader failed", t);
        }
    }

    /** Bind LoadedApk native lib dir to so_plain (matches ApplicationInfo). */
    private static void bindLoadedApkPlain(Object loadedApk, String plainPath) {
        if (loadedApk == null || plainPath == null) return;
        Object appInfo = getField(loadedApk, "mApplicationInfo");
        if (appInfo instanceof ApplicationInfo) {
            ((ApplicationInfo) appInfo).nativeLibraryDir = plainPath;
        }
        setField(loadedApk, "mNativeLibraryDir", plainPath);
    }

    private static Object getField(Object obj, String name) {
        if (obj == null) return null;
        Class<?> c = obj.getClass();
        while (c != null) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(obj);
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            } catch (Throwable t) {
                return null;
            }
        }
        return null;
    }

    private static void setField(Object obj, String name, Object value) {
        Class<?> c = obj.getClass();
        while (c != null) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                f.set(obj, value);
                return;
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            } catch (Throwable ignored) {
                return;
            }
        }
    }
}
