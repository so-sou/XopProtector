package com.yqsh.protector.packer;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import org.junit.jupiter.api.Test;

class ProtectPolicyDcloudSkipTest {

    @Test
    void balancedDoesNotHollowDcloudOrBusiness() {
        ProtectPolicy p = new ProtectPolicy(ProtectPolicy.Profile.BALANCED, Collections.emptyList());
        assertFalse(p.shouldHollow("Lio/dcloud/uts/UTSKeyIterable;"));
        assertFalse(p.shouldHollow("Lcom/taobao/weex/WXSDKEngine;"));
        assertFalse(p.shouldHollow("Lcom/yqsh/unimpdemo/LaunchActivity;"));
    }

    @Test
    void aggressiveSkipsDcloudAndWeexPrefixes() {
        ProtectPolicy p = new ProtectPolicy(ProtectPolicy.Profile.AGGRESSIVE, Collections.emptyList());
        assertFalse(p.shouldHollow("Lio/dcloud/uts/UTSKeyIterable;"));
        assertFalse(p.shouldHollow("Lio/dcloud/feature/sdk/DCUniMPSDK;"));
        assertFalse(p.shouldHollow("Lcom/taobao/weex/WXSDKEngine;"));
        assertTrue(p.shouldHollow("Lcom/yqsh/unimpdemo/BizHelper;"));
    }
}
