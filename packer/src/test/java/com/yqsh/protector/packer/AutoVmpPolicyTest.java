package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class AutoVmpPolicyTest {

    @Test
    void industryProfileUnsetEnablesIndustryAuto() {
        AutoVmpPolicy.Resolved r = AutoVmpPolicy.resolve(
                ProtectOptions.AutoVmpMode.UNSET,
                ProtectOptions.AutoVmpMode.UNSET,
                ProtectPolicy.Profile.INDUSTRY);
        assertTrue(r.paymentEffective);
        assertTrue(r.industryEffective);
        assertFalse(r.paymentFromCli);
        assertFalse(r.industryFromCli);
    }

    @Test
    void balancedUnsetDisablesIndustryAuto() {
        AutoVmpPolicy.Resolved r = AutoVmpPolicy.resolve(
                ProtectOptions.AutoVmpMode.UNSET,
                ProtectOptions.AutoVmpMode.UNSET,
                ProtectPolicy.Profile.BALANCED);
        assertTrue(r.paymentEffective);
        assertFalse(r.industryEffective);
    }

    @Test
    void industryProfileCanDisableIndustryAuto() {
        AutoVmpPolicy.Resolved r = AutoVmpPolicy.resolve(
                ProtectOptions.AutoVmpMode.UNSET,
                ProtectOptions.AutoVmpMode.OFF,
                ProtectPolicy.Profile.INDUSTRY);
        assertTrue(r.paymentEffective);
        assertFalse(r.industryEffective);
        assertTrue(r.industryFromCli);
    }

    @Test
    void balancedCanEnableIndustryAuto() {
        AutoVmpPolicy.Resolved r = AutoVmpPolicy.resolve(
                ProtectOptions.AutoVmpMode.UNSET,
                ProtectOptions.AutoVmpMode.ON,
                ProtectPolicy.Profile.BALANCED);
        assertTrue(r.paymentEffective);
        assertTrue(r.industryEffective);
        assertTrue(r.industryFromCli);
    }

    @Test
    void paymentCanBeForcedOff() {
        AutoVmpPolicy.Resolved r = AutoVmpPolicy.resolve(
                ProtectOptions.AutoVmpMode.OFF,
                ProtectOptions.AutoVmpMode.UNSET,
                ProtectPolicy.Profile.INDUSTRY);
        assertFalse(r.paymentEffective);
        assertTrue(r.industryEffective);
        assertTrue(r.paymentFromCli);
    }

    @Test
    void conflictingPairedFlagsFail() {
        ProtectOptions.AutoVmpMode cur = ProtectOptions.AutoVmpMode.ON;
        assertThrows(IllegalArgumentException.class, () ->
                AutoVmpPolicy.applyPairedFlag(cur, ProtectOptions.AutoVmpMode.OFF, "payment"));
    }

    @Test
    void aggregateBothAndOff() {
        ProtectOptions.AutoVmpMode[] both = AutoVmpPolicy.fromAggregate("both");
        assertEquals(ProtectOptions.AutoVmpMode.ON, both[0]);
        assertEquals(ProtectOptions.AutoVmpMode.ON, both[1]);
        ProtectOptions.AutoVmpMode[] off = AutoVmpPolicy.fromAggregate("off");
        assertEquals(ProtectOptions.AutoVmpMode.OFF, off[0]);
        assertEquals(ProtectOptions.AutoVmpMode.OFF, off[1]);
    }

    @Test
    void policyLineFormat() {
        AutoVmpPolicy.Resolved r = AutoVmpPolicy.resolve(
                ProtectOptions.AutoVmpMode.OFF,
                ProtectOptions.AutoVmpMode.UNSET,
                ProtectPolicy.Profile.INDUSTRY);
        String line = AutoVmpPolicy.formatPolicyLine(
                r, ProtectPolicy.Profile.INDUSTRY, 2, "Lcom/zhd/mech/himc/");
        assertEquals(
                "True-VMP policy: payment=off industry=on prefixes=2"
                        + " industry_scope=Lcom/zhd/mech/himc/"
                        + " (profile=industry, payment_src=cli, industry_src=default)",
                line);
        assertTrue(AutoVmpPolicy.formatPolicyLine(r, ProtectPolicy.Profile.INDUSTRY, 0, null)
                .contains("industry_scope=none"));
    }

    @Test
    void shouldTrueVmpRespectsAxesAndPrefix() {
        String pay = "Lcom/alipay/sdk/app/PayTask;";
        String lic = "Lcom/zhd/ts/license/LicenseChecker;";
        String other = "Lcom/zhd/ui/MainActivity;";
        String app = "Lcom/zhd/ts/";

        // Payment is not app-scoped.
        assertTrue(AutoVmpPolicy.shouldTrueVmp(pay, true, false, List.of(), app));
        assertFalse(AutoVmpPolicy.shouldTrueVmp(pay, false, true, List.of(), app));
        // Industry requires app package + tokens.
        assertTrue(AutoVmpPolicy.shouldTrueVmp(lic, false, true, List.of(), app));
        assertFalse(AutoVmpPolicy.shouldTrueVmp(lic, false, true, List.of(), "Lcom/other/"));
        assertFalse(AutoVmpPolicy.shouldTrueVmp(lic, true, false, List.of(), app));
        // Manual prefix bypasses industry scope.
        assertTrue(AutoVmpPolicy.shouldTrueVmp(
                other, false, false, List.of("Lcom/zhd/ui/"), null));
        assertFalse(AutoVmpPolicy.shouldTrueVmp(other, false, false, List.of(), app));
        // Third-party under industry axis stays out even with tokens in the name.
        assertFalse(AutoVmpPolicy.shouldTrueVmp(
                "Lnet/lingala/zip4j/crypto/AesCipherUtil;",
                false, true, List.of(), app));
    }
}
