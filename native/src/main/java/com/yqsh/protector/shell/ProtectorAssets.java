package com.yqsh.protector.shell;

import android.content.Context;
import android.content.res.AssetManager;

import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Phase 2A — read business assets encrypted by {@code --encrypt-assets}.
 * Ciphertext lives at {@code assets/protector/aenc/&lt;relpath&gt;} (PAS1).
 */
@Keep
public final class ProtectorAssets {
    private static final String AENC_PREFIX = "protector/aenc/";

    private ProtectorAssets() {
    }

    /** Open decrypted asset as a stream. */
    @NonNull
    public static InputStream open(@NonNull Context context, @NonNull String relativePath)
            throws IOException {
        return new ByteArrayInputStream(readBytes(context, relativePath));
    }

    /** Read entire decrypted asset. */
    @NonNull
    public static byte[] readBytes(@NonNull Context context, @NonNull String relativePath)
            throws IOException {
        String path = normalize(relativePath);
        AssetManager am = context.getAssets();
        try (InputStream in = am.open(AENC_PREFIX + path)) {
            byte[] enc = readAll(in);
            byte[] plain = JniBridge.decryptAssetBlob(enc);
            if (plain == null) {
                throw new IOException("decryptAssetBlob returned null for " + path);
            }
            return plain;
        } catch (IllegalStateException e) {
            throw new IOException("PAS1 decrypt failed for " + path, e);
        }
    }

    /** UTF-8 convenience. */
    @NonNull
    public static String readString(@NonNull Context context, @NonNull String relativePath)
            throws IOException {
        return readString(context, relativePath, StandardCharsets.UTF_8);
    }

    @NonNull
    public static String readString(@NonNull Context context, @NonNull String relativePath,
                                    @NonNull Charset charset) throws IOException {
        return new String(readBytes(context, relativePath), charset);
    }

    /**
     * True when {@code protector/aenc/&lt;path&gt;} exists (encrypted).
     * Does not prove decrypt will succeed.
     */
    public static boolean exists(@NonNull Context context, @NonNull String relativePath) {
        String path = normalize(relativePath);
        try (InputStream in = context.getAssets().open(AENC_PREFIX + path)) {
            return in != null;
        } catch (IOException e) {
            return false;
        }
    }

    @NonNull
    private static String normalize(@Nullable String relativePath) {
        if (relativePath == null || relativePath.isEmpty()) {
            throw new IllegalArgumentException("empty asset path");
        }
        String p = relativePath.replace('\\', '/');
        while (p.startsWith("/")) {
            p = p.substring(1);
        }
        if (p.startsWith("assets/")) {
            p = p.substring("assets/".length());
        }
        if (p.startsWith(AENC_PREFIX)) {
            p = p.substring(AENC_PREFIX.length());
        }
        if (p.contains("..")) {
            throw new IllegalArgumentException("invalid asset path: " + relativePath);
        }
        return p;
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) >= 0) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }
}
