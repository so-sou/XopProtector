package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Files;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BusinessSoUniAppSkipIntegrationTest {

    @TempDir
    File temp;

    @Test
    void protectAllSkipsUniAppRuntimeBasenames() throws Exception {
        File abi = new File(temp, "arm64-v8a");
        assertTrue(abi.mkdirs());
        for (String name : new String[] {
                "libweexjsb.so",
                "libweexjst.so",
                "libweexjss.so",
                "libweexcore.so",
                "libimagepipeline.so",
                "libdcblur.so"
        }) {
            Files.write(new File(abi, name).toPath(), new byte[] {0x7f, 'E', 'L', 'F'});
        }

        BusinessSoProtector.Options opts = new BusinessSoProtector.Options();
        opts.mode = BusinessSoProtector.Mode.SAFE;
        BusinessSoProtector.ProtectResult result = BusinessSoProtector.protectAll(temp, opts);

        long uniSkipped = result.skippedPolicy.stream()
                .filter(d -> "uniapp/runtime".equals(d.reason))
                .count();
        assertEquals(6, uniSkipped);
    }
}
