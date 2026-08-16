package com.yqsh.protector.shell;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.ProxyInfo;
import android.util.Log;

import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.X509TrustManager;

/**
 * Phase 3 — optional HTTPS certificate pinning helpers + proxy/VPN heuristics.
 * Config: {@code assets/protector/netguard.json} (copied to protector cache).
 * <p>
 * App signing check ({@link JniBridge#verifySignature}) is <em>not</em> HTTPS pinning.
 */
@Keep
public final class NetGuard {
    private static final String TAG = "protector.NetGuard";
    private static final String CONFIG_NAME = "netguard.json";

    private static final AtomicBoolean installed = new AtomicBoolean(false);
    private static volatile boolean detectProxy;
    private static volatile boolean detectVpn;
    private static volatile boolean proxyHit;
    private static final Set<String> pinSha256 =
            Collections.synchronizedSet(new LinkedHashSet<>());

    private NetGuard() {
    }

    /** Load config and run an initial proxy/VPN scan. Safe to call multiple times. */
    public static void install(@NonNull Context context) {
        if (!installed.compareAndSet(false, true)) {
            return;
        }
        try {
            loadConfig(context);
            if (detectProxy || detectVpn) {
                String hit = scanProxy(context.getApplicationContext());
                if (hit != null) {
                    proxyHit = true;
                    Log.w(TAG, "network threat: " + hit);
                    JniBridge.reportThreat(hit);
                }
            }
            Log.i(TAG, "installed detect_proxy=" + detectProxy
                    + " detect_vpn=" + detectVpn
                    + " pins=" + pinSha256.size());
        } catch (Throwable t) {
            Log.e(TAG, "install failed", t);
            installed.set(false);
        }
    }

    public static boolean isInstalled() {
        return installed.get();
    }

    public static boolean isDetectProxyEnabled() {
        return detectProxy;
    }

    public static int pinCount() {
        return pinSha256.size();
    }

    /** True after a proxy/VPN hit was recorded during {@link #install} or {@link #rescan}. */
    public static boolean wasProxyDetected() {
        return proxyHit;
    }

    /** Re-run proxy/VPN heuristics (e.g. before sensitive network I/O). */
    @Nullable
    public static String rescan(@NonNull Context context) {
        if (!detectProxy && !detectVpn) {
            return null;
        }
        String hit = scanProxy(context.getApplicationContext());
        if (hit != null) {
            proxyHit = true;
            JniBridge.reportThreat(hit);
        }
        return hit;
    }

    /**
     * Verify leaf certificate SHA-256 (hex) is in the pin set.
     * Empty pin set → always true (pinning disabled).
     */
    public static boolean isPinTrusted(@Nullable X509Certificate leaf) {
        if (pinSha256.isEmpty()) {
            return true;
        }
        if (leaf == null) {
            return false;
        }
        try {
            String hex = sha256Hex(leaf.getEncoded());
            return hex != null && pinSha256.contains(hex);
        } catch (CertificateEncodingException e) {
            return false;
        }
    }

    /**
     * Wrap a base TrustManager: after default trust, enforce pin set when non-empty.
     * Pin mismatch → {@link JniBridge#reportThreat(String)} then throw.
     */
    @NonNull
    public static X509TrustManager wrappingTrustManager(@NonNull X509TrustManager base) {
        return new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType)
                    throws java.security.cert.CertificateException {
                base.checkClientTrusted(chain, authType);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType)
                    throws java.security.cert.CertificateException {
                base.checkServerTrusted(chain, authType);
                if (pinSha256.isEmpty()) {
                    return;
                }
                if (chain == null || chain.length == 0) {
                    JniBridge.reportThreat("ssl_pin_empty_chain");
                    throw new java.security.cert.CertificateException("empty cert chain");
                }
                String hex = sha256Hex(chain[0].getEncoded());
                if (hex == null || !pinSha256.contains(hex)) {
                    JniBridge.reportThreat("ssl_pin_mismatch");
                    throw new java.security.cert.CertificateException("certificate pin mismatch");
                }
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return base.getAcceptedIssuers();
            }
        };
    }

    /** SHA-256 hex of DER-encoded bytes (lowercase). */
    @Nullable
    public static String sha256Hex(@Nullable byte[] der) {
        if (der == null) {
            return null;
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest(der);
            StringBuilder sb = new StringBuilder(dig.length * 2);
            for (byte b : dig) {
                sb.append(String.format(Locale.US, "%02x", b & 0xff));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    private static void loadConfig(Context context) throws Exception {
        detectProxy = false;
        detectVpn = false;
        pinSha256.clear();
        String json = readConfigText(context);
        if (json == null || json.isEmpty()) {
            return;
        }
        JSONObject o = new JSONObject(json);
        detectProxy = o.optBoolean("detect_proxy", false);
        detectVpn = o.optBoolean("detect_vpn", detectProxy);
        JSONArray pins = o.optJSONArray("pin_sha256");
        if (pins != null) {
            for (int i = 0; i < pins.length(); i++) {
                String p = normalizeHex(pins.optString(i, ""));
                if (p.length() == 64) {
                    pinSha256.add(p);
                }
            }
        }
    }

    @Nullable
    private static String readConfigText(Context context) {
        try {
            File cache = new File(context.getCodeCacheDir(), "protector");
            File f = new File(cache, CONFIG_NAME);
            if (f.isFile() && f.length() > 0) {
                return readFile(f);
            }
        } catch (Exception ignored) {
        }
        try (InputStream in = context.getAssets().open("protector/" + CONFIG_NAME)) {
            return readStream(in);
        } catch (Exception e) {
            return null;
        }
    }

    private static String readFile(File f) throws Exception {
        try (InputStream in = new FileInputStream(f)) {
            return readStream(in);
        }
    }

    private static String readStream(InputStream in) throws Exception {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append('\n');
            }
        }
        return sb.toString();
    }

    @Nullable
    private static String scanProxy(Context context) {
        if (detectProxy) {
            String host = System.getProperty("http.proxyHost");
            if (notBlank(host)) {
                return "http_proxy";
            }
            host = System.getProperty("https.proxyHost");
            if (notBlank(host)) {
                return "https_proxy";
            }
            host = System.getProperty("socksProxyHost");
            if (notBlank(host)) {
                return "socks_proxy";
            }
            try {
                ConnectivityManager cm = (ConnectivityManager)
                        context.getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm != null) {
                    ProxyInfo proxy = cm.getDefaultProxy();
                    if (proxy != null && notBlank(proxy.getHost())) {
                        return "system_proxy";
                    }
                }
            } catch (Throwable ignored) {
            }
        }
        if (detectVpn) {
            try {
                ConnectivityManager cm = (ConnectivityManager)
                        context.getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm != null) {
                    Network[] networks = cm.getAllNetworks();
                    if (networks != null) {
                        for (Network n : networks) {
                            NetworkCapabilities caps = cm.getNetworkCapabilities(n);
                            if (caps != null
                                    && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                                return "vpn_transport";
                            }
                        }
                    }
                }
            } catch (Throwable ignored) {
            }
        }
        return null;
    }

    private static boolean notBlank(String s) {
        return s != null && !s.trim().isEmpty();
    }

    private static String normalizeHex(String s) {
        if (s == null) {
            return "";
        }
        String t = s.trim().toLowerCase(Locale.US);
        if (t.startsWith("sha256/")) {
            t = t.substring(7);
        }
        StringBuilder sb = new StringBuilder(t.length());
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
