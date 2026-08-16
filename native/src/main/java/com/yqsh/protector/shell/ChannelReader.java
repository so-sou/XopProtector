package com.yqsh.protector.shell;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.util.Log;

import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Phase 6 — read multi-channel id from APK Signing Block (Walle-compatible ID {@code 0x71777777}).
 */
@Keep
public final class ChannelReader {
    private static final String TAG = "protector.Channel";
    /** Same as Meituan Walle {@code APK_CHANNEL_BLOCK_ID}. */
    public static final int CHANNEL_BLOCK_ID = 0x71777777;

    private static final int APK_SIG_BLOCK_MIN_SIZE = 32;
    private static final long APK_SIG_BLOCK_MAGIC_HI = 0x3234206b636f6c42L;
    private static final long APK_SIG_BLOCK_MAGIC_LO = 0x20676953204b5041L;
    private static final int ZIP_EOCD_REC_MIN_SIZE = 22;
    private static final int ZIP_EOCD_REC_SIG = 0x06054b50;
    private static final int UINT16_MAX_VALUE = 0xffff;
    private static final int ZIP_EOCD_COMMENT_LENGTH_OFFSET = 20;

    private ChannelReader() {
    }

    /** Channel from the installed APK, or {@code null} if unmarked / unreadable. */
    @Nullable
    public static String getChannel(@NonNull Context context) {
        try {
            ApplicationInfo ai = context.getApplicationInfo();
            if (ai == null || ai.sourceDir == null) {
                return null;
            }
            return getChannel(new File(ai.sourceDir));
        } catch (Throwable t) {
            Log.w(TAG, "getChannel failed", t);
            return null;
        }
    }

    @Nullable
    public static String getChannel(@NonNull File apk) {
        try {
            byte[] raw = readRaw(apk);
            if (raw == null || raw.length == 0) {
                return null;
            }
            String s = new String(raw, StandardCharsets.UTF_8).trim();
            if (s.startsWith("{")) {
                String ch = extractJsonString(s, "channel");
                return ch != null ? ch : s;
            }
            return s;
        } catch (Throwable t) {
            Log.w(TAG, "getChannel(" + apk + ") failed", t);
            return null;
        }
    }

    @Nullable
    public static String getRaw(@NonNull File apk) {
        try {
            byte[] raw = readRaw(apk);
            return raw == null ? null : new String(raw, StandardCharsets.UTF_8);
        } catch (Throwable t) {
            Log.w(TAG, "getRaw failed", t);
            return null;
        }
    }

    @Nullable
    private static byte[] readRaw(File apk) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(apk, "r")) {
            ByteBuffer block = findApkSigningBlock(raf);
            Map<Integer, ByteBuffer> idValues = findIdValues(block);
            ByteBuffer payload = idValues.get(CHANNEL_BLOCK_ID);
            if (payload == null) {
                return null;
            }
            byte[] out = new byte[payload.remaining()];
            payload.get(out);
            return out;
        }
    }

    private static ByteBuffer findApkSigningBlock(RandomAccessFile apk) throws IOException {
        long centralDirOffset = findCentralDirOffset(apk);
        if (centralDirOffset < APK_SIG_BLOCK_MIN_SIZE) {
            throw new IOException("APK too small for signing block");
        }
        apk.seek(centralDirOffset - 24);
        ByteBuffer footer = ByteBuffer.allocate(24);
        footer.order(ByteOrder.LITTLE_ENDIAN);
        apk.readFully(footer.array());
        if (footer.getLong(8) != APK_SIG_BLOCK_MAGIC_LO
                || footer.getLong(16) != APK_SIG_BLOCK_MAGIC_HI) {
            throw new IOException("No APK Signing Block");
        }
        long blockSizeInFooter = footer.getLong(0);
        if (blockSizeInFooter < footer.capacity() || blockSizeInFooter > Integer.MAX_VALUE - 8) {
            throw new IOException("bad signing block size");
        }
        long totalSize = blockSizeInFooter + 8;
        long blockOffset = centralDirOffset - totalSize;
        if (blockOffset < 0) {
            throw new IOException("signing block offset negative");
        }
        apk.seek(blockOffset);
        ByteBuffer block = ByteBuffer.allocate((int) totalSize);
        block.order(ByteOrder.LITTLE_ENDIAN);
        apk.readFully(block.array());
        if (block.getLong(0) != blockSizeInFooter) {
            throw new IOException("signing block size mismatch");
        }
        return block;
    }

    private static Map<Integer, ByteBuffer> findIdValues(ByteBuffer apkSigningBlock) {
        int pairsEnd = apkSigningBlock.capacity() - 24;
        ByteBuffer pairs = slice(apkSigningBlock, 8, pairsEnd - 8);
        Map<Integer, ByteBuffer> idValues = new LinkedHashMap<>();
        while (pairs.remaining() >= 8) {
            long lenLong = pairs.getLong();
            if (lenLong < 4 || lenLong > Integer.MAX_VALUE) {
                throw new IllegalArgumentException("bad pair length");
            }
            int len = (int) lenLong;
            if (pairs.remaining() < len) {
                throw new IllegalArgumentException("pair overflow");
            }
            int id = pairs.getInt();
            int valueLen = len - 4;
            ByteBuffer value = slice(pairs, pairs.position(), valueLen);
            pairs.position(pairs.position() + valueLen);
            idValues.put(id, value);
        }
        return idValues;
    }

    private static long findCentralDirOffset(RandomAccessFile apk) throws IOException {
        long fileSize = apk.length();
        if (fileSize < ZIP_EOCD_REC_MIN_SIZE) {
            throw new IOException("APK too small");
        }
        long maxCommentLength = Math.min(UINT16_MAX_VALUE, fileSize - ZIP_EOCD_REC_MIN_SIZE);
        byte[] eocd = new byte[ZIP_EOCD_REC_MIN_SIZE];
        for (long commentLength = 0; commentLength <= maxCommentLength; commentLength++) {
            long eocdPos = fileSize - ZIP_EOCD_REC_MIN_SIZE - commentLength;
            apk.seek(eocdPos);
            apk.readFully(eocd);
            ByteBuffer bb = ByteBuffer.wrap(eocd).order(ByteOrder.LITTLE_ENDIAN);
            if (bb.getInt(0) != ZIP_EOCD_REC_SIG) {
                continue;
            }
            int actualComment = bb.getShort(ZIP_EOCD_COMMENT_LENGTH_OFFSET) & 0xffff;
            if (actualComment != commentLength) {
                continue;
            }
            return bb.getInt(16) & 0xffffffffL;
        }
        throw new IOException("EOCD not found");
    }

    private static ByteBuffer slice(ByteBuffer source, int position, int length) {
        ByteBuffer dup = source.duplicate();
        dup.order(ByteOrder.LITTLE_ENDIAN);
        dup.position(position);
        dup.limit(position + length);
        return dup.slice().order(ByteOrder.LITTLE_ENDIAN);
    }

    static String extractJsonString(String json, String key) {
        String needle = "\"" + key + "\"";
        int i = json.indexOf(needle);
        if (i < 0) {
            return null;
        }
        int colon = json.indexOf(':', i + needle.length());
        if (colon < 0) {
            return null;
        }
        int q1 = json.indexOf('"', colon + 1);
        if (q1 < 0) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (int p = q1 + 1; p < json.length(); p++) {
            char c = json.charAt(p);
            if (c == '\\' && p + 1 < json.length()) {
                sb.append(json.charAt(++p));
                continue;
            }
            if (c == '"') {
                return sb.toString();
            }
            sb.append(c);
        }
        return null;
    }
}
