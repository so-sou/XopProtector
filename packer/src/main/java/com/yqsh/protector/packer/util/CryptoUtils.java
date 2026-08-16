package com.yqsh.protector.packer.util;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Crypto helpers shared by packer and matching native crypto/aes.*.
 * AES-128-GCM for code.bin method bodies; AES-128-CTR (zero IV) for SO sections.
 */
public final class CryptoUtils {
    public static final int AES_KEY_LEN = 16;
    public static final int GCM_NONCE_LEN = 12;
    public static final int GCM_TAG_LEN = 16;

    private CryptoUtils() {
    }

    /**
     * AES-128-GCM encrypt. Returns {@code nonce(12) || ciphertext || tag(16)}.
     */
    public static byte[] aesGcmEncrypt(byte[] key, byte[] plain) throws Exception {
        if (key == null || key.length != AES_KEY_LEN || plain == null) {
            throw new IllegalArgumentException("invalid AES-GCM args");
        }
        byte[] nonce = new byte[GCM_NONCE_LEN];
        new SecureRandom().nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(GCM_TAG_LEN * 8, nonce));
        byte[] ctAndTag = cipher.doFinal(plain);
        byte[] out = new byte[GCM_NONCE_LEN + ctAndTag.length];
        System.arraycopy(nonce, 0, out, 0, GCM_NONCE_LEN);
        System.arraycopy(ctAndTag, 0, out, GCM_NONCE_LEN, ctAndTag.length);
        return out;
    }

    /**
     * AES-128-CTR with all-zero IV (size-preserving). Same key+IV on decrypt.
     */
    public static byte[] aesCtrCrypt(byte[] key, byte[] data) throws Exception {
        if (key == null || key.length != AES_KEY_LEN || data == null) {
            throw new IllegalArgumentException("invalid AES-CTR args");
        }
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new IvParameterSpec(new byte[16]));
        return cipher.doFinal(data);
    }

    /** RC4 matching FreeBSD/native rc4.c (SO .bitcode size-preserving encrypt). */
    public static byte[] rc4Crypt(byte[] key, byte[] in) {
        if (key == null || key.length == 0 || in == null) {
            return null;
        }
        byte[] perm = new byte[256];
        for (int i = 0; i < 256; i++) {
            perm[i] = (byte) i;
        }
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + (perm[i] & 0xff) + (key[i % key.length] & 0xff)) & 0xff;
            byte tmp = perm[i];
            perm[i] = perm[j];
            perm[j] = tmp;
        }
        byte[] out = new byte[in.length];
        int i = 0;
        j = 0;
        for (int n = 0; n < in.length; n++) {
            i = (i + 1) & 0xff;
            j = (j + (perm[i] & 0xff)) & 0xff;
            byte tmp = perm[i];
            perm[i] = perm[j];
            perm[j] = tmp;
            int k = ((perm[i] & 0xff) + (perm[j] & 0xff)) & 0xff;
            out[n] = (byte) (in[n] ^ perm[k]);
        }
        return out;
    }

    public static String toHex(byte[] data) {
        if (data == null) return "";
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
