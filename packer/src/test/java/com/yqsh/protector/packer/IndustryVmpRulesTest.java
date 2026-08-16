package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class IndustryVmpRulesTest {

    @Test
    void matchesLicensePathAndActivateName() {
        // Token-only (no scope) — used by unit tests / diagnostics.
        assertTrue(IndustryVmpRules.matches("Lcom/zhd/ts/license/LicenseChecker;"));
        assertTrue(IndustryVmpRules.matches("Lcom/zhd/app/LicenseManager;"));
        assertTrue(IndustryVmpRules.matches("Lcom/foo/util/ActivateHelper;"));
        assertTrue(IndustryVmpRules.matches("Lcom/foo/ChecksumUtil;"));
    }

    @Test
    void scopedMatchesOnlyUnderAppPackage() {
        String app = "Lcom/zhd/mech/himc/";
        assertTrue(IndustryVmpRules.matches(
                "Lcom/zhd/mech/himc/license/LicenseChecker;", app));
        assertTrue(IndustryVmpRules.matches(
                "Lcom/zhd/mech/himc/util/TkEncryptUtil;", app));
        // Sibling vendor packages are outside Manifest applicationId.
        assertFalse(IndustryVmpRules.matches(
                "Lcom/zhd/ts/license/LicenseChecker;", app));
        // Third-party crypto-named classes must not match.
        assertFalse(IndustryVmpRules.matches(
                "Lnet/lingala/zip4j/crypto/AESDecrypter;", app));
        assertFalse(IndustryVmpRules.matches(
                "Lnet/lingala/zip4j/crypto/AesCipherUtil;", app));
        assertFalse(IndustryVmpRules.matches(
                "Lorg/litepal/util/cipher/CipherUtil;", app));
        assertFalse(IndustryVmpRules.matches(
                "Lcom/thoughtworks/xstream/converters/extended/ActivationDataFlavorConverter;",
                app));
    }

    @Test
    void emptyAppPrefixNeverMatches() {
        assertFalse(IndustryVmpRules.matches(
                "Lcom/zhd/mech/himc/license/LicenseChecker;", null));
        assertFalse(IndustryVmpRules.matches(
                "Lcom/zhd/mech/himc/license/LicenseChecker;", ""));
    }

    @Test
    void skipsSdkAndComponents() {
        assertFalse(IndustryVmpRules.matches("Lcom/amazonaws/crypto/Crypto;"));
        assertFalse(IndustryVmpRules.matches("Lorg/spongycastle/crypto/Cipher;"));
        // Android component skip (Activity suffix / framework)
        assertFalse(IndustryVmpRules.matches("Lcom/zhd/ts/license/LicenseActivity;"));
        assertFalse(IndustryVmpRules.matches(
                "Lcom/zhd/ts/license/LicenseActivity;", "Lcom/zhd/ts/"));
    }
}
