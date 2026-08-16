package com.yqsh.protector.packer;

import java.util.Locale;

/**
 * Commercial auto True-VMP markers — no customer package names required.
 * Matches Dalvik type descriptors for well-known payment SDK / callback tokens.
 *
 * <ul>
 *   <li>{@code alipay} — Alipay SDK types (e.g. {@code Lcom/alipay/...})</li>
 *   <li>{@code /wxapi/} — WeChat callback package segment only (e.g. {@code .../wxapi/WXPayEntryActivity;}),
 *       not OpenSDK class names like {@code WXApiImpl} which also contain the letters wxapi</li>
 * </ul>
 */
public final class PaymentVmpRules {

    private PaymentVmpRules() {
    }

    /**
     * @param typeDescriptor e.g. {@code Lcom/alipay/sdk/app/PayTask;}
     *                       or {@code Lcom/foo/wxapi/WXPayEntryActivity;}
     */
    public static boolean matches(String typeDescriptor) {
        if (typeDescriptor == null || typeDescriptor.length() < 3) {
            return false;
        }
        // Never True-VMP Android components: DexPool rewrite of their host DEX has
        // broken sibling classes (annotation/type resolve failures → “数据异常”).
        if (ProtectPolicy.isAndroidComponent(typeDescriptor)) {
            return false;
        }
        String lower = typeDescriptor.toLowerCase(Locale.US);
        if (lower.contains("alipay")) {
            return true;
        }
        // Package segment only — avoids Lcom/tencent/mm/opensdk/openapi/BaseWXApiImplV10;
        return lower.contains("/wxapi/");
    }
}
