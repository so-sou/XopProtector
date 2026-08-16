package com.yqsh.protector.packer;

import com.yqsh.protector.packer.elf.ReadElf;
import com.yqsh.protector.packer.util.CryptoUtils;

import java.io.File;
import java.io.RandomAccessFile;
import java.util.List;

/**
 * Encrypts .bitcode in libprotector.so with RC4 (size-preserving) and writes
 * AES keys into PROTECTOR_UNKNOWN_DATA / PROTECTOR_INSN_KEY / PROTECTOR_DEX_KEY
 * (XOR-padded). Method bodies use AES-GCM; dexes.zip uses PDX1+AES-GCM.
 */
public final class SoSectionEncryptor {
    // Must match SECTION_NAME_BITCODE in protector_macro.h
    private static final String BITCODE = ".bitcode";
    private static final String KEY_SYMBOL = "PROTECTOR_UNKNOWN_DATA";
    private static final String INSN_KEY_SYMBOL = "PROTECTOR_INSN_KEY";
    private static final String DEX_KEY_SYMBOL = "PROTECTOR_DEX_KEY";
    private static final String HMAC_KEY_SYMBOL = "PROTECTOR_HMAC_KEY";
    private static final String ASSETS_KEY_SYMBOL = "PROTECTOR_ASSETS_KEY";

    // XOR pads — must match C++ kKeyPadUnknown / kKeyPadInsn / KEY_PAD_DEX / KEY_PAD_HMAC / KEY_PAD_ASSETS.
    private static final byte[] KEY_PAD_UNKNOWN = {
        (byte)0x3b, 0x7c, 0x19, 0x5e, (byte)0xa2, (byte)0xdf, 0x48, 0x31,
        0x6c, (byte)0x85, (byte)0xea, 0x27, 0x54, (byte)0x9b, 0x0f, (byte)0xd6
    };
    private static final byte[] KEY_PAD_INSN = {
        (byte)0xc7, 0x2a, 0x5f, (byte)0x98, 0x1d, 0x63, (byte)0xae, 0x34,
        (byte)0xf8, 0x41, 0x0b, 0x76, (byte)0xd9, 0x52, (byte)0x8c, (byte)0xe3
    };
    /** Must match load_dex_key_from_so pad in engine.cpp. */
    public static final byte[] KEY_PAD_DEX = {
        (byte)0xa1, 0x5c, 0x2e, 0x79, 0x04, (byte)0xb8, 0x6d, 0x3f,
        (byte)0xc2, 0x17, (byte)0x8a, 0x50, (byte)0xe6, 0x3b, (byte)0x91, 0x4d
    };
    /** Must match load_hmac_key pad in engine.cpp. */
    public static final byte[] KEY_PAD_HMAC = {
        0x5a, (byte)0xe1, 0x2c, (byte)0x97, 0x44, (byte)0xb8, 0x0f, 0x6d,
        (byte)0x83, 0x1a, (byte)0xf5, 0x60, 0x2e, (byte)0xc9, 0x47, (byte)0xd3,
        0x19, 0x7b, (byte)0xa4, 0x58, (byte)0xe6, 0x0d, (byte)0x92, 0x3f,
        (byte)0xc1, 0x56, (byte)0x8a, 0x24, (byte)0xf0, 0x6b, 0x35, (byte)0xde
    };
    /** Must match load_assets_key_from_so pad in engine.cpp. */
    public static final byte[] KEY_PAD_ASSETS = {
        0x4e, (byte)0xb3, 0x17, (byte)0x8c, 0x2a, 0x61, (byte)0xd5, 0x09,
        (byte)0xf0, 0x3c, (byte)0x7a, (byte)0xa8, 0x15, (byte)0xce, 0x56, (byte)0x92
    };

    private SoSectionEncryptor() {
    }

    /** XOR key with pad so raw ELF symbol doesn't expose plaintext key. */
    private static byte[] xorBytes(byte[] a, byte[] b) {
        byte[] r = new byte[a.length];
        for (int i = 0; i < a.length; i++) r[i] = (byte)(a[i] ^ b[i]);
        return r;
    }

    public static void encrypt(File soFile, byte[] soAesKey, byte[] insnAesKey) throws Exception {
        encrypt(soFile, soAesKey, insnAesKey, null, null, null);
    }

    public static void encrypt(File soFile, byte[] soAesKey, byte[] insnAesKey, byte[] dexAesKey)
            throws Exception {
        encrypt(soFile, soAesKey, insnAesKey, dexAesKey, null, null);
    }

    public static void encrypt(File soFile, byte[] soAesKey, byte[] insnAesKey, byte[] dexAesKey,
                               byte[] hmacKey) throws Exception {
        encrypt(soFile, soAesKey, insnAesKey, dexAesKey, hmacKey, null);
    }

    public static void encrypt(File soFile, byte[] soAesKey, byte[] insnAesKey, byte[] dexAesKey,
                               byte[] hmacKey, byte[] assetsAesKey) throws Exception {
        if (soFile == null || !soFile.isFile() || soAesKey == null || soAesKey.length != 16) {
            throw new IllegalArgumentException("invalid so or SO AES key");
        }
        if (insnAesKey == null || insnAesKey.length != 16) {
            throw new IllegalArgumentException("invalid insn AES key");
        }
        encryptBitcode(soFile, soAesKey);
        writeKeySymbol(soFile, KEY_SYMBOL, xorBytes(soAesKey, KEY_PAD_UNKNOWN));
        writeKeySymbol(soFile, INSN_KEY_SYMBOL, xorBytes(insnAesKey, KEY_PAD_INSN));
        if (dexAesKey != null) {
            if (dexAesKey.length != 16) {
                throw new IllegalArgumentException("invalid dex AES key");
            }
            writeKeySymbol(soFile, DEX_KEY_SYMBOL, xorBytes(dexAesKey, KEY_PAD_DEX));
        }
        if (hmacKey != null) {
            if (hmacKey.length != 32) {
                throw new IllegalArgumentException("invalid HMAC key");
            }
            writeKeySymbol(soFile, HMAC_KEY_SYMBOL, xorBytes(hmacKey, KEY_PAD_HMAC));
        }
        if (assetsAesKey != null) {
            if (assetsAesKey.length != 16) {
                throw new IllegalArgumentException("invalid assets AES key");
            }
            writeKeySymbol(soFile, ASSETS_KEY_SYMBOL, xorBytes(assetsAesKey, KEY_PAD_ASSETS));
        }
    }

    private static void encryptBitcode(File soFile, byte[] aesKey) throws Exception {
        try (ReadElf readElf = new ReadElf(soFile)) {
            List<ReadElf.SectionHeader> headers = readElf.getSectionHeaders();
            for (ReadElf.SectionHeader sh : headers) {
                if (!BITCODE.equals(sh.getName())) continue;
                long offset = sh.getOffset();
                int size = (int) sh.getSize();
                if (size <= 0) {
                    throw new IllegalStateException("empty .bitcode in " + soFile.getName());
                }
                byte[] plain = readAt(soFile, offset, size);
                byte[] enc = CryptoUtils.rc4Crypt(aesKey, plain);
                if (enc == null || enc.length != plain.length) {
                    throw new IllegalStateException("RC4 encrypt .bitcode failed");
                }
                writeAt(soFile, offset, enc);
                System.out.println("Encrypted .bitcode (RC4) in " + soFile.getName()
                        + " offset=0x" + Long.toHexString(offset) + " size=" + size);
                return;
            }
        }
        throw new IllegalStateException("no .bitcode section in " + soFile.getName());
    }

    private static void writeKeySymbol(File soFile, String symbolName, byte[] key) throws Exception {
        try (ReadElf readElf = new ReadElf(soFile)) {
            ReadElf.Symbol symbol = readElf.getDynamicSymbol(symbolName);
            if (symbol == null) {
                throw new IllegalStateException("symbol " + symbolName + " not found in " + soFile.getName());
            }
            int shndx = symbol.shndx;
            List<ReadElf.SectionHeader> headers = readElf.getSectionHeaders();
            if (shndx < 0 || shndx >= headers.size()) {
                throw new IllegalStateException("bad shndx for " + symbolName);
            }
            ReadElf.SectionHeader sectionHeader = headers.get(shndx);
            long symbolDataOffset = sectionHeader.getOffset() + symbol.value - sectionHeader.getAddr();
            writeAt(soFile, symbolDataOffset, key);
            System.out.println("Wrote " + symbolName + " at 0x" + Long.toHexString(symbolDataOffset)
                    + " in " + soFile.getName());
        }
    }

    private static byte[] readAt(File file, long offset, int len) throws Exception {
        byte[] buf = new byte[len];
        try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
            raf.seek(offset);
            raf.readFully(buf);
        }
        return buf;
    }

    private static void writeAt(File file, long offset, byte[] data) throws Exception {
        try (RandomAccessFile raf = new RandomAccessFile(file, "rw")) {
            raf.seek(offset);
            raf.write(data);
        }
    }
}
