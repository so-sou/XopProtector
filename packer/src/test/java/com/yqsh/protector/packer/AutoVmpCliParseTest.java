package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class AutoVmpCliParseTest {

    @Test
    void conflictingPaymentFlagsThrow() {
        assertThrows(IllegalArgumentException.class, () ->
                PackerMain.parseArgs(new String[]{
                        "in.apk",
                        "--payment-auto-vmp",
                        "--no-payment-auto-vmp"
                }));
    }

    @Test
    void industryNoAutoPreservesModes() throws Exception {
        ProtectOptions o = PackerMain.parseArgs(new String[]{
                "in.apk",
                "--profile", "industry",
                "--no-industry-auto-vmp"
        });
        assertEquals(ProtectPolicy.Profile.INDUSTRY, o.profile);
        assertEquals(ProtectOptions.AutoVmpMode.UNSET, o.paymentAutoVmp);
        assertEquals(ProtectOptions.AutoVmpMode.OFF, o.industryAutoVmp);
        AutoVmpPolicy.Resolved r = AutoVmpPolicy.resolve(
                o.paymentAutoVmp, o.industryAutoVmp, o.profile);
        assertEquals(true, r.paymentEffective);
        assertEquals(false, r.industryEffective);
    }

    @Test
    void aggregateOverriddenByPaired() throws Exception {
        ProtectOptions o = PackerMain.parseArgs(new String[]{
                "in.apk",
                "--auto-true-vmp", "off",
                "--industry-auto-vmp"
        });
        assertEquals(ProtectOptions.AutoVmpMode.OFF, o.paymentAutoVmp);
        assertEquals(ProtectOptions.AutoVmpMode.ON, o.industryAutoVmp);
    }
}
