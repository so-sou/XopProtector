package com.yqsh.protector.packer;

import com.yqsh.protector.packer.util.CryptoUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Phase 2A — encrypt app {@code assets/**} (excluding {@code assets/protector/**}).
 * Ciphertext layout: {@code assets/protector/aenc/<relpath>} = {@code PAS1 || AES-GCM}.
 * Index: {@code assets/protector/assets.map} (one relative path per line).
 */
public final class AssetsEncryptor {
    public static final String AENC_DIR = "protector/aenc";
    public static final String MAP_NAME = "assets.map";
    /** Magic: Protector ASset v1 */
    public static final byte[] MAGIC = {'P', 'A', 'S', '1'};

    /** Media that typically needs AssetManager.openFd — skip by default. */
    private static final String[] SKIP_EXT = {
            ".mp3", ".mp4", ".m4a", ".ogg", ".wav", ".aac", ".flac",
            ".webm", ".mkv", ".3gp", ".ts"
    };

    private AssetsEncryptor() {
    }

    public static final class Result {
        public final int encrypted;
        public final int skipped;
        public final List<String> paths;

        Result(int encrypted, int skipped, List<String> paths) {
            this.encrypted = encrypted;
            this.skipped = skipped;
            this.paths = paths;
        }
    }

    /**
     * Encrypt business assets under {@code unpack/assets}. Returns null if nothing encrypted.
     */
    public static Result encryptAll(File unpackRoot, byte[] assetsAesKey) throws Exception {
        if (assetsAesKey == null || assetsAesKey.length != 16) {
            throw new IllegalArgumentException("invalid assets AES key");
        }
        File assetsRoot = new File(unpackRoot, "assets");
        if (!assetsRoot.isDirectory()) {
            return new Result(0, 0, List.of());
        }

        List<Path> files;
        try (Stream<Path> walk = Files.walk(assetsRoot.toPath())) {
            files = walk.filter(Files::isRegularFile)
                    .sorted(Comparator.comparing(Path::toString))
                    .collect(Collectors.toList());
        }

        // Count work items (exclude already under protector/).
        int workTotal = 0;
        for (Path abs : files) {
            String rel = assetsRoot.toPath().relativize(abs).toString().replace('\\', '/');
            if (rel.startsWith("protector/") || rel.equals("protector")) {
                continue;
            }
            workTotal++;
        }
        ProgressMilestones prog = new ProgressMilestones("assets encrypt", workTotal);

        File aencRoot = new File(assetsRoot, AENC_DIR.replace('/', File.separatorChar));
        List<String> encryptedPaths = new ArrayList<>();
        int skipped = 0;

        for (Path abs : files) {
            String rel = assetsRoot.toPath().relativize(abs).toString().replace('\\', '/');
            if (rel.startsWith("protector/") || rel.equals("protector")) {
                continue;
            }
            // AGP may place baseline profiles under assets/dexopt — leave for ART.
            if (rel.startsWith("dexopt/") || rel.equals("dexopt")) {
                skipped++;
                prog.tick();
                continue;
            }
            if (shouldSkip(rel)) {
                skipped++;
                prog.tick();
                continue;
            }
            byte[] plain = Files.readAllBytes(abs);
            byte[] gcm = CryptoUtils.aesGcmEncrypt(assetsAesKey, plain);
            byte[] out = new byte[MAGIC.length + gcm.length];
            System.arraycopy(MAGIC, 0, out, 0, MAGIC.length);
            System.arraycopy(gcm, 0, out, MAGIC.length, gcm.length);

            File dest = new File(aencRoot, rel.replace('/', File.separatorChar));
            File parent = dest.getParentFile();
            if (parent != null && !parent.exists() && !parent.mkdirs()) {
                throw new IOException("cannot mkdir " + parent);
            }
            Files.write(dest.toPath(), out);
            Files.delete(abs);
            encryptedPaths.add(rel);
            prog.tick();
        }
        prog.finish();

        pruneEmptyDirs(assetsRoot);

        File protectorDir = new File(assetsRoot, "protector");
        if (!protectorDir.exists() && !protectorDir.mkdirs()) {
            throw new IOException("cannot mkdir " + protectorDir);
        }
        File mapFile = new File(protectorDir, MAP_NAME);
        StringBuilder map = new StringBuilder();
        map.append("# protector assets.map v1\n");
        for (String p : encryptedPaths) {
            map.append(p).append('\n');
        }
        Files.writeString(mapFile.toPath(), map.toString(), StandardCharsets.UTF_8);

        return new Result(encryptedPaths.size(), skipped, encryptedPaths);
    }

    private static boolean shouldSkip(String relPath) {
        String lower = relPath.toLowerCase(Locale.US);
        for (String ext : SKIP_EXT) {
            if (lower.endsWith(ext)) return true;
        }
        return false;
    }

    private static void pruneEmptyDirs(File dir) {
        File[] kids = dir.listFiles();
        if (kids == null) return;
        for (File k : kids) {
            if (k.isDirectory()) {
                pruneEmptyDirs(k);
                File[] remain = k.listFiles();
                if (remain != null && remain.length == 0) {
                    //noinspection ResultOfMethodCallIgnored
                    k.delete();
                }
            }
        }
    }
}
