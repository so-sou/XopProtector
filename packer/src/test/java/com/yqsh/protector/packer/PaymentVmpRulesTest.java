package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class PaymentVmpRulesTest {

    @Test
    void matchesAlipayAndWxapiSegment() {
        assertTrue(PaymentVmpRules.matches("Lcom/alipay/sdk/app/PayTask;"));
        assertTrue(PaymentVmpRules.matches("Lcom/foo/wxapi/WXPayHelper;"));
    }

    @Test
    void rejectsWxApiClassNameWithoutSegment() {
        assertFalse(PaymentVmpRules.matches(
                "Lcom/tencent/mm/opensdk/openapi/BaseWXApiImplV10;"));
    }
}
