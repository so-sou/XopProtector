package com.yqsh.protector.shell;

/**
 * Lightweight string de-obfuscation (rolling XOR, Phase 4).
 * Not crypto — defeats trivial {@code strings} / fixed-key scans.
 * Must stay in sync with native {@code OBSC_ROLL} / {@code unobsc}.
 */
public final class StrEnc {
    private static final int KEY = 0x5A;
    private static final int PRIME = 0x1B;

    private StrEnc() {
    }

    static int roll(int i) {
        return (KEY ^ ((i * PRIME) & 0xff)) & 0xff;
    }

    /** Decode bytes that were encoded with {@link #e(String)}. */
    public static String d(byte[] enc) {
        if (enc == null || enc.length == 0) return "";
        char[] out = new char[enc.length];
        for (int i = 0; i < enc.length; i++) {
            out[i] = (char) ((enc[i] & 0xff) ^ roll(i));
        }
        return new String(out);
    }

    /** Encode a plaintext string for embedding as a byte[] literal. */
    public static byte[] e(String plain) {
        if (plain == null) return new byte[0];
        byte[] out = new byte[plain.length()];
        for (int i = 0; i < plain.length(); i++) {
            out[i] = (byte) (plain.charAt(i) ^ roll(i));
        }
        return out;
    }

    /** C string literal form: {@code "\\xab\\xcd..."}. */
    public static String toCLiteral(String plain) {
        byte[] enc = e(plain);
        StringBuilder sb = new StringBuilder(enc.length * 4 + 2);
        sb.append('"');
        for (byte b : enc) {
            sb.append(String.format("\\x%02x", b & 0xff));
        }
        sb.append('"');
        return sb.toString();
    }

    /** Java byte[] initializer: {@code {(byte)0xab, ...}}. */
    public static String toJavaBytes(String plain) {
        byte[] enc = e(plain);
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        for (int i = 0; i < enc.length; i++) {
            if (i > 0) sb.append(", ");
            int v = enc[i] & 0xff;
            if (v > 127) {
                sb.append(String.format("(byte)0x%02x", v));
            } else {
                sb.append(String.format("0x%02x", v));
            }
        }
        sb.append('}');
        return sb.toString();
    }
}
