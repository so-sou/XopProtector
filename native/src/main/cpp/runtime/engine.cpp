#include "runtime/engine.h"
#include "common/log.h"
#include "common/runtime_state.h"
#include "common/protector_macro.h"
#include "codeitem/multi_dex_code.h"
#include "crypto/sha256.h"
#include "crypto/dex_asset.h"
#include "hook/hooks.h"
#include "risk/risk.h"
#include "report/threat_report.h"
#include "so/business_so.h"
#include "vm/pvm2_interp.h"

#include <android/api-level.h>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <mutex>
#include <cctype>
#include <atomic>
#include <dirent.h>

#include "json.hpp"

namespace protector::runtime {

static JavaVM* g_vm = nullptr;
/** False until Java enables checks after ClassLoader + DexMerger are ready. */
static std::atomic_bool g_junk_verify_enabled{false};

static std::string read_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return {};
    std::ostringstream oss;
    oss << ifs.rdbuf();
    return oss.str();
}

static bool file_exists(const std::string& path) {
    struct stat st{};
    return stat(path.c_str(), &st) == 0 && st.st_size > 0;
}

/** Previous launch left .prepatched + classes*.dex — skip dexes.zip decrypt. */
static bool has_warm_dex_cache(const std::string& dir) {
    if (!file_exists(dir + "/.prepatched")) return false;
    DIR* d = opendir(dir.c_str());
    if (d == nullptr) return false;
    bool found = false;
    while (dirent* ent = readdir(d)) {
        const char* n = ent->d_name;
        if (n == nullptr) continue;
        size_t len = strlen(n);
        if (len > 4 && strncmp(n, "classes", 7) == 0 && strcmp(n + len - 4, ".dex") == 0) {
            std::string path = dir + "/" + n;
            if (file_exists(path)) {
                found = true;
                break;
            }
        }
    }
    closedir(d);
    return found;
}

static bool insn_key_non_zero() {
    for (int i = 0; i < 16; i++) {
        if (PROTECTOR_INSN_KEY[i] != 0) return true;
    }
    return false;
}

PROTECTOR_ENCRYPT static void load_insn_key_from_so(ShellConfig& cfg) {
    if (!insn_key_non_zero()) return;
    // XOR pad defined inside the function body → placed in .bitcode (encrypted).
    // Must match SoSectionEncryptor.KEY_PAD_INSN exactly.
    // clang-format off
    const uint8_t pad[16] = {
        0xc7, 0x2a, 0x5f, 0x98, 0x1d, 0x63, 0xae, 0x34,
        0xf8, 0x41, 0x0b, 0x76, 0xd9, 0x52, 0x8c, 0xe3
    };
    // clang-format on
    uint8_t decoded[16];
    for (int i = 0; i < 16; i++) {
        decoded[i] = PROTECTOR_INSN_KEY[i] ^ pad[i];
    }
    cfg.insns_aes_key.assign(decoded, decoded + 16);
    memset(decoded, 0, sizeof(decoded));
    PLOGI("loaded insns AES key from SO symbol (de-obfuscated)");
}

static bool dex_key_non_zero() {
    for (int i = 0; i < 16; i++) {
        if (PROTECTOR_DEX_KEY[i] != 0) return true;
    }
    return false;
}

PROTECTOR_ENCRYPT static void load_dex_key_from_so(ShellConfig& cfg) {
    if (!dex_key_non_zero()) return;
    // Must match SoSectionEncryptor.KEY_PAD_DEX exactly.
    // clang-format off
    const uint8_t pad[16] = {
        0xa1, 0x5c, 0x2e, 0x79, 0x04, 0xb8, 0x6d, 0x3f,
        0xc2, 0x17, 0x8a, 0x50, 0xe6, 0x3b, 0x91, 0x4d
    };
    // clang-format on
    uint8_t decoded[16];
    for (int i = 0; i < 16; i++) {
        decoded[i] = PROTECTOR_DEX_KEY[i] ^ pad[i];
    }
    cfg.dex_aes_key.assign(decoded, decoded + 16);
    memset(decoded, 0, sizeof(decoded));
    PLOGI("loaded dexes.zip AES key from SO symbol");
}

static bool assets_key_non_zero() {
    for (int i = 0; i < 16; i++) {
        if (PROTECTOR_ASSETS_KEY[i] != 0) return true;
    }
    return false;
}

PROTECTOR_ENCRYPT static void load_assets_key_from_so(ShellConfig& cfg) {
    if (!assets_key_non_zero()) return;
    // Must match SoSectionEncryptor.KEY_PAD_ASSETS exactly.
    // clang-format off
    const uint8_t pad[16] = {
        0x4e, 0xb3, 0x17, 0x8c, 0x2a, 0x61, 0xd5, 0x09,
        0xf0, 0x3c, 0x7a, 0xa8, 0x15, 0xce, 0x56, 0x92
    };
    // clang-format on
    uint8_t decoded[16];
    for (int i = 0; i < 16; i++) {
        decoded[i] = PROTECTOR_ASSETS_KEY[i] ^ pad[i];
    }
    cfg.assets_aes_key.assign(decoded, decoded + 16);
    memset(decoded, 0, sizeof(decoded));
    PLOGI("loaded assets AES key from SO symbol");
}

/** Verify HMAC-SHA256 over config payload (everything before "_hmac").
 *  Uses a constant-time hex compare to avoid timing side-channels.
 *  On mismatch calls crash_exit() — clean exit, hard to trace. */
PROTECTOR_ENCRYPT static void load_hmac_key(uint8_t out[PROTECTOR_HMAC_KEY_SIZE]) {
    // Must match SoSectionEncryptor.KEY_PAD_HMAC exactly. Lives in .bitcode.
    // clang-format off
    const uint8_t pad[PROTECTOR_HMAC_KEY_SIZE] = {
        0x5a, 0xe1, 0x2c, 0x97, 0x44, 0xb8, 0x0f, 0x6d,
        0x83, 0x1a, 0xf5, 0x60, 0x2e, 0xc9, 0x47, 0xd3,
        0x19, 0x7b, 0xa4, 0x58, 0xe6, 0x0d, 0x92, 0x3f,
        0xc1, 0x56, 0x8a, 0x24, 0xf0, 0x6b, 0x35, 0xde
    };
    // clang-format on
    for (int i = 0; i < PROTECTOR_HMAC_KEY_SIZE; i++) {
        out[i] = PROTECTOR_HMAC_KEY[i] ^ pad[i];
    }
}

static void verify_config_hmac(const std::string& json_text) {
    // Locate the _hmac field injected by the packer.
    auto hmac_key_pos = json_text.find("\"_hmac\"");
    if (hmac_key_pos == std::string::npos) {
        PLOGE("config.json missing _hmac field");
        protector::risk::crash_exit();
        return;
    }

    // Payload is everything before the comma that separates _hmac.
    size_t payload_end = hmac_key_pos;
    while (payload_end > 0 &&
           (json_text[payload_end - 1] == ',' || json_text[payload_end - 1] == ' ')) {
        payload_end--;
    }
    std::string payload = json_text.substr(0, payload_end);

    // Extract expected HMAC hex value.
    auto colon = json_text.find(':', hmac_key_pos);
    auto val_start = json_text.find('"', colon + 1);
    auto val_end = json_text.find('"', val_start + 1);
    if (colon == std::string::npos || val_start == std::string::npos
            || val_end == std::string::npos || val_end <= val_start) {
        PLOGE("config.json _hmac malformed");
        protector::risk::crash_exit();
        return;
    }
    std::string expected_hex = json_text.substr(val_start + 1, val_end - val_start - 1);
    if (expected_hex.size() != 64) {
        PLOGE("config.json _hmac wrong length");
        protector::risk::crash_exit();
        return;
    }

    uint8_t hmac_key[PROTECTOR_HMAC_KEY_SIZE];
    load_hmac_key(hmac_key);

    // Compute HMAC-SHA256.
    uint8_t mac[32];
    protector::crypto::hmac_sha256(hmac_key, PROTECTOR_HMAC_KEY_SIZE,
                                   payload.data(), payload.size(), mac);
    memset(hmac_key, 0, sizeof(hmac_key));

    // Constant-time hex comparison.
    static const char kHex[] = "0123456789abcdef";
    int diff = 0;
    for (int i = 0; i < 32; i++) {
        diff |= (kHex[mac[i] >> 4] ^ expected_hex[static_cast<size_t>(i * 2)]);
        diff |= (kHex[mac[i] & 0xf] ^ expected_hex[static_cast<size_t>(i * 2 + 1)]);
    }

    if (diff != 0) {
        PLOGE("config.json HMAC mismatch — config was tampered");
        protector::risk::crash_exit();
    }
}

static void parse_config_json(const std::string& json_text) {
    auto& cfg = runtime_state().config;
    if (json_text.empty()) {
        PLOGW("config.json empty");
        return;
    }
    // Verify integrity before trusting any config value.
    verify_config_hmac(json_text);
    try {
        auto j = nlohmann::json::parse(json_text);
        if (j.contains("application_name") && j["application_name"].is_string()) {
            cfg.application_name = j["application_name"].get<std::string>();
        }
        if (j.contains("insns_xor_key") && j["insns_xor_key"].is_number_integer()) {
            cfg.insns_xor_key = j["insns_xor_key"].get<uint32_t>();
        }
        // Prefer SO-embedded AES key; reject plaintext key-in-config fallback.
        if (j.contains("risk_flags") && j["risk_flags"].is_number_integer()) {
            cfg.risk_flags.store(j["risk_flags"].get<int>(), std::memory_order_relaxed);
        }
        if (j.contains("rasp_action") && j["rasp_action"].is_number_integer()) {
            int action = j["rasp_action"].get<int>();
            if (action < 0 || action > 2) action = static_cast<int>(RaspAction::Block);
            cfg.rasp_action.store(action, std::memory_order_relaxed);
        }
        if (j.contains("app_sign_sha256") && j["app_sign_sha256"].is_string()) {
            cfg.app_sign_sha256 = j["app_sign_sha256"].get<std::string>();
        }
        if (j.contains("protect_so")) {
            if (j["protect_so"].is_boolean()) {
                cfg.protect_so = j["protect_so"].get<bool>();
            } else if (j["protect_so"].is_number_integer()) {
                cfg.protect_so = j["protect_so"].get<int>() != 0;
            }
        }
        if (j.contains("encrypt_assets")) {
            if (j["encrypt_assets"].is_boolean()) {
                cfg.encrypt_assets = j["encrypt_assets"].get<bool>();
            } else if (j["encrypt_assets"].is_number_integer()) {
                cfg.encrypt_assets = j["encrypt_assets"].get<int>() != 0;
            }
        }
        // Missing so_decrypt_mode → Eager (old APKs / unsigned configs).
        cfg.so_decrypt_mode = SoDecryptMode::Eager;
        if (j.contains("so_decrypt_mode") && j["so_decrypt_mode"].is_string()) {
            std::string mode = j["so_decrypt_mode"].get<std::string>();
            for (auto& c : mode) {
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            }
            if (mode == "lazy") {
                cfg.so_decrypt_mode = SoDecryptMode::Lazy;
            } else if (mode != "eager") {
                PLOGW("config so_decrypt_mode='%s' unknown — using eager",
                      j["so_decrypt_mode"].get<std::string>().c_str());
                cfg.so_decrypt_mode = SoDecryptMode::Eager;
            }
        }
        protector::so::set_so_decrypt_mode(cfg.so_decrypt_mode);
        bool report_enabled = true;
        if (j.contains("report_enabled")) {
            if (j["report_enabled"].is_boolean()) {
                report_enabled = j["report_enabled"].get<bool>();
            } else if (j["report_enabled"].is_number_integer()) {
                report_enabled = j["report_enabled"].get<int>() != 0;
            }
        }
        protector::report::set_report_enabled(report_enabled);
        PLOGI("config app=%s xor=0x%x aes=%s dex_aes=%s assets_aes=%s risk_flags=0x%x rasp=%d report=%d protect_so=%d so_decrypt=%s encrypt_assets=%d sign=%s",
              cfg.application_name.c_str(), cfg.insns_xor_key,
              cfg.insns_aes_key.size() == 16 ? "yes" : "no",
              cfg.dex_aes_key.size() == 16 ? "yes" : "no",
              cfg.assets_aes_key.size() == 16 ? "yes" : "no",
              cfg.risk_flags.load(std::memory_order_relaxed),
              cfg.rasp_action.load(std::memory_order_relaxed),
              report_enabled ? 1 : 0,
              cfg.protect_so ? 1 : 0,
              cfg.so_decrypt_mode == SoDecryptMode::Lazy ? "lazy" : "eager",
              cfg.encrypt_assets ? 1 : 0,
              cfg.app_sign_sha256.empty() ? "(none)" : "set");
    } catch (const std::exception& e) {
        PLOGE("config.json parse failed: %s", e.what());
    } catch (...) {
        PLOGE("config.json parse failed");
    }
}

static void junk_code_protect(JNIEnv* env) {
#ifndef DEBUG
    static std::atomic_bool verified{false};
    if (verified.load(std::memory_order_relaxed)) return;

    // Resolve JunkClass WITHOUT initializing it. JNI FindClass runs <clinit>;
    // Class.forName(name, false, cl) does not.
    static constexpr const char kJunkClassJava[] = "com.yqsh.protector.junkcode.JunkClass";

    jobject cl = nullptr;
    // Prefer JniBridge's ClassLoader (available during early ACF bootstrap).
    jclass bridgeCls = env->FindClass("com/yqsh/protector/shell/JniBridge");
    if (bridgeCls != nullptr) {
        jclass classCls = env->GetObjectClass(bridgeCls);
        jmethodID getCl = env->GetMethodID(classCls, "getClassLoader",
                                           "()Ljava/lang/ClassLoader;");
        if (getCl != nullptr) {
            cl = env->CallObjectMethod(bridgeCls, getCl);
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
                cl = nullptr;
            }
        }
    } else {
        env->ExceptionClear();
    }

    // Fallback: Application ClassLoader once ActivityThread has an app.
    if (cl == nullptr) {
        jclass at = env->FindClass("android/app/ActivityThread");
        if (at != nullptr) {
            jmethodID curApp = env->GetStaticMethodID(at, "currentApplication",
                                                      "()Landroid/app/Application;");
            jobject app = (curApp != nullptr)
                    ? env->CallStaticObjectMethod(at, curApp) : nullptr;
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
                app = nullptr;
            }
            if (app != nullptr) {
                jclass ctxClz = env->GetObjectClass(app);
                jmethodID getCl = env->GetMethodID(ctxClz, "getClassLoader",
                                                   "()Ljava/lang/ClassLoader;");
                cl = (getCl != nullptr) ? env->CallObjectMethod(app, getCl) : nullptr;
                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                    cl = nullptr;
                }
            }
        } else {
            env->ExceptionClear();
        }
    }

    jclass klass = nullptr;
    if (cl != nullptr) {
        jclass classCls = env->FindClass("java/lang/Class");
        jmethodID forName = classCls != nullptr
                ? env->GetStaticMethodID(
                        classCls, "forName",
                        "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;")
                : nullptr;
        jstring name = env->NewStringUTF(kJunkClassJava);
        if (forName != nullptr && name != nullptr) {
            klass = reinterpret_cast<jclass>(
                    env->CallStaticObjectMethod(classCls, forName, name, JNI_FALSE, cl));
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
                klass = nullptr;
            }
        }
    }

    if (klass == nullptr) {
        PLOGE("junk class missing");
        protector::risk::crash_hang();  // hang — waste attacker's time on junk tamper
        return;
    }
    env->DeleteLocalRef(klass);
    verified.store(true, std::memory_order_relaxed);
#else
    (void)env;
#endif
}

void maybe_verify_junk_class() {
#ifndef DEBUG
    if (!g_junk_verify_enabled.load(std::memory_order_acquire)) return;
    if (g_vm == nullptr) return;
    if ((rand() & 31) != 0) return;

    // ART callbacks are usually already attached; never Attach/Detach here.
    JNIEnv* env = nullptr;
    if (g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK
        || env == nullptr) {
        return;
    }
    junk_code_protect(env);
#endif
}

void enable_junk_verify(JNIEnv*, jclass) {
#ifndef DEBUG
    g_junk_verify_enabled.store(true, std::memory_order_release);
    PLOGI("junk verify enabled");
#else
    (void)0;
#endif
}

static std::string bytes_to_hex_lower(const uint8_t* data, size_t len) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[(data[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex[data[i] & 0xf];
    }
    return out;
}

static bool hex_equals_ci(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++) {
        if (tolower(static_cast<unsigned char>(a[i]))
            != tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

/** SHA-256 of signing cert via Java MessageDigest (no mbedtls). */
static void verify_app_signature(JNIEnv* env, jobject context, const std::string& expected) {
    if (context == nullptr || expected.empty()) {
        protector::risk::crash_exit();
        return;
    }
    if (env->PushLocalFrame(64) < 0) {
        env->ExceptionClear();
        protector::risk::crash_abort();
        return;
    }

    auto fail = [&]() {
        env->ExceptionClear();
        env->PopLocalFrame(nullptr);
        protector::risk::crash_abort();
    };

    jclass ctxCls = env->GetObjectClass(context);
    if (!ctxCls || env->ExceptionCheck()) {
        fail();
        return;
    }
    jmethodID getPm = env->GetMethodID(ctxCls, "getPackageManager",
                                       "()Landroid/content/pm/PackageManager;");
    jmethodID getPkg = env->GetMethodID(ctxCls, "getPackageName", "()Ljava/lang/String;");
    if (!getPm || !getPkg || env->ExceptionCheck()) {
        fail();
        return;
    }
    jobject pm = env->CallObjectMethod(context, getPm);
    jstring packageName = static_cast<jstring>(env->CallObjectMethod(context, getPkg));
    if (!pm || !packageName || env->ExceptionCheck()) {
        fail();
        return;
    }

    int api = android_get_device_api_level();
    jint flags = (api >= 28) ? 0x08000000 : 0x40; // GET_SIGNING_CERTIFICATES / GET_SIGNATURES

    jclass pmCls = env->GetObjectClass(pm);
    if (!pmCls || env->ExceptionCheck()) {
        fail();
        return;
    }
    jmethodID getPi = env->GetMethodID(pmCls, "getPackageInfo",
            "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    if (!getPi || env->ExceptionCheck()) {
        fail();
        return;
    }
    jobject packageInfo = env->CallObjectMethod(pm, getPi, packageName, flags);
    if (!packageInfo || env->ExceptionCheck()) {
        fail();
        return;
    }

    jbyteArray certBytes = nullptr;
    jclass piCls = env->GetObjectClass(packageInfo);
    if (!piCls || env->ExceptionCheck()) {
        fail();
        return;
    }
    if (api >= 28) {
        jfieldID siField = env->GetFieldID(piCls, "signingInfo",
                                           "Landroid/content/pm/SigningInfo;");
        if (!siField || env->ExceptionCheck()) {
            fail();
            return;
        }
        jobject signingInfo = env->GetObjectField(packageInfo, siField);
        if (!signingInfo || env->ExceptionCheck()) {
            fail();
            return;
        }
        jclass siCls = env->GetObjectClass(signingInfo);
        jmethodID getSigners = env->GetMethodID(siCls, "getApkContentsSigners",
                "()[Landroid/content/pm/Signature;");
        if (!getSigners || env->ExceptionCheck()) {
            fail();
            return;
        }
        auto signatures = static_cast<jobjectArray>(
                env->CallObjectMethod(signingInfo, getSigners));
        if (!signatures || env->ExceptionCheck() || env->GetArrayLength(signatures) == 0) {
            fail();
            return;
        }
        jobject signature = env->GetObjectArrayElement(signatures, 0);
        if (!signature || env->ExceptionCheck()) {
            fail();
            return;
        }
        jclass sigCls = env->GetObjectClass(signature);
        jmethodID toByteArray = env->GetMethodID(sigCls, "toByteArray", "()[B");
        if (!toByteArray || env->ExceptionCheck()) {
            fail();
            return;
        }
        certBytes = static_cast<jbyteArray>(env->CallObjectMethod(signature, toByteArray));
    } else {
        jfieldID sigField = env->GetFieldID(piCls, "signatures",
                                            "[Landroid/content/pm/Signature;");
        if (!sigField || env->ExceptionCheck()) {
            fail();
            return;
        }
        auto signatures = static_cast<jobjectArray>(
                env->GetObjectField(packageInfo, sigField));
        if (!signatures || env->ExceptionCheck() || env->GetArrayLength(signatures) == 0) {
            fail();
            return;
        }
        jobject signature = env->GetObjectArrayElement(signatures, 0);
        if (!signature || env->ExceptionCheck()) {
            fail();
            return;
        }
        jclass sigCls = env->GetObjectClass(signature);
        jmethodID toByteArray = env->GetMethodID(sigCls, "toByteArray", "()[B");
        if (!toByteArray || env->ExceptionCheck()) {
            fail();
            return;
        }
        certBytes = static_cast<jbyteArray>(env->CallObjectMethod(signature, toByteArray));
    }

    if (!certBytes || env->ExceptionCheck()) {
        fail();
        return;
    }

    jclass mdCls = env->FindClass("java/security/MessageDigest");
    if (!mdCls || env->ExceptionCheck()) {
        fail();
        return;
    }
    jmethodID getInstance = env->GetStaticMethodID(mdCls, "getInstance",
            "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    if (!getInstance || env->ExceptionCheck()) {
        fail();
        return;
    }
    jstring alg = env->NewStringUTF("SHA-256");
    jobject md = env->CallStaticObjectMethod(mdCls, getInstance, alg);
    if (!md || env->ExceptionCheck()) {
        fail();
        return;
    }
    jmethodID digest = env->GetMethodID(mdCls, "digest", "([B)[B");
    if (!digest || env->ExceptionCheck()) {
        fail();
        return;
    }
    auto hashArr = static_cast<jbyteArray>(env->CallObjectMethod(md, digest, certBytes));
    if (!hashArr || env->ExceptionCheck()) {
        fail();
        return;
    }

    jsize hashLen = env->GetArrayLength(hashArr);
    if (hashLen != 32) {
        fail();
        return;
    }
    jbyte* hashBytes = env->GetByteArrayElements(hashArr, nullptr);
    if (hashBytes == nullptr) {
        fail();
        return;
    }
    std::string actual = bytes_to_hex_lower(reinterpret_cast<const uint8_t*>(hashBytes), 32);
    env->ReleaseByteArrayElements(hashArr, hashBytes, JNI_ABORT);

    if (!hex_equals_ci(actual, expected)) {
        PLOGW("signature mismatch expected=%s actual=%s", expected.c_str(), actual.c_str());
        env->PopLocalFrame(nullptr);
        protector::risk::crash_abort();  // SIGABRT — APK was repackaged
        return;
    }
    PLOGI("app signature ok");
    env->PopLocalFrame(nullptr);
}

void on_load(JavaVM* vm) {
    g_vm = vm;
    if (runtime_state().sdk_level == 0) {
        runtime_state().sdk_level = android_get_device_api_level();
    }
    PLOGI("protector native on_load, sdk=%d", runtime_state().sdk_level);
}

PROTECTOR_ENCRYPT void init_app(JNIEnv* env, jclass, jstring protector_dir_j) {
    auto& state = runtime_state();
    std::lock_guard<std::mutex> lock(state.mutex);
    if (state.inited.load()) return;

    if (protector_dir_j == nullptr) {
        PLOGE("protectorDir is null");
        return;
    }
    const char* dir_c = env->GetStringUTFChars(protector_dir_j, nullptr);
    if (dir_c == nullptr) {
        PLOGE("GetStringUTFChars failed");
        return;
    }
    std::string dir = dir_c;
    env->ReleaseStringUTFChars(protector_dir_j, dir_c);
    if (dir.empty()) {
        PLOGE("protectorDir empty");
        return;
    }

    state.dexes_zip_path = dir + "/dexes.zip";
    std::string code_path = dir + "/code.bin";
    std::string config_path = dir + "/config.json";
    state.code_bin_path = code_path;
    protector::report::set_report_dir(dir);
    // Keep existing nativeLibraryDir if Java already called setNativeLibraryDir.
    protector::so::set_runtime_dirs(dir, "");

    const bool warm = has_warm_dex_cache(dir);
    if (!file_exists(code_path)) {
        PLOGW("code.bin missing under %s", dir.c_str());
        return;
    }
    if (!warm && !file_exists(state.dexes_zip_path)) {
        PLOGW("dexes.zip missing under %s (no warm cache)", dir.c_str());
        return;
    }
    if (warm) {
        PLOGI("warm cache: skip dexes.zip decrypt");
    }

    load_insn_key_from_so(state.config);
    load_dex_key_from_so(state.config);
    load_assets_key_from_so(state.config);

    if (file_exists(config_path)) {
        parse_config_json(read_file(config_path));
    }

    // Main-path Frida/hook screen before decrypting business assets.
    protector::risk::scan_hooks_and_frida_now();

    if (state.config.insns_aes_key.size() != 16) {
        PLOGE("missing insn AES key");
        protector::risk::crash_exit();
        return;
    }

    // Decrypt PDX1-wrapped dexes.zip and extract classes*.dex in one pass
    // (no plaintext ZIP on disk). Warm starts already have prepatched dexes.
    if (!warm && state.config.dex_aes_key.size() == 16) {
        std::string sokeys_path = dir + "/sokeys.bin";
        if (!protector::so::load_sokeys(sokeys_path, state.config.dex_aes_key.data())) {
            PLOGE("sokeys load failed");
            protector::risk::crash_exit();
            return;
        }
        if (state.config.protect_so && !protector::so::has_sokeys()) {
            // Packer wrote encrypted business SOs; missing/empty keys must not proceed
            // (would SIGILL on encrypted .text). Fail closed before wiping dex AES key.
            PLOGE("protect_so set but sokeys.bin missing or empty — refuse init");
            protector::risk::crash_exit();
            return;
        }
        if (!crypto::decrypt_and_extract_dexes(state.dexes_zip_path,
                                               state.config.dex_aes_key.data(),
                                               dir)) {
            PLOGE("dexes.zip decrypt/extract failed");
            memset(state.config.dex_aes_key.data(), 0, state.config.dex_aes_key.size());
            state.config.dex_aes_key.clear();
            protector::risk::crash_exit();
            return;
        }
        // Dex key only needed once at bootstrap.
        memset(state.config.dex_aes_key.data(), 0, state.config.dex_aes_key.size());
        state.config.dex_aes_key.clear();
        if (protector::so::has_sokeys()) {
            unlink(sokeys_path.c_str());
        }
        // ART may load SOs without going through hooked dlopen — decrypt packaged
        // libs under nativeLibraryDir before any ContentProvider runs.
        protector::so::materialize_decrypted_sos();
    } else if (!warm) {
        PLOGW("no dex AES key — expecting legacy plaintext dexes.zip");
    } else {
        // Warm: still load sokeys so late dlopen of protected SOs can decrypt.
        if (state.config.dex_aes_key.size() == 16) {
            std::string sokeys_path = dir + "/sokeys.bin";
            if (file_exists(sokeys_path)) {
                if (!protector::so::load_sokeys(sokeys_path, state.config.dex_aes_key.data())) {
                    PLOGE("warm sokeys load failed");
                    protector::risk::crash_exit();
                    return;
                }
                if (state.config.protect_so && !protector::so::has_sokeys()) {
                    PLOGE("protect_so set but warm sokeys empty — refuse init");
                    protector::risk::crash_exit();
                    return;
                }
                if (protector::so::has_sokeys()) {
                    unlink(sokeys_path.c_str());
                }
                protector::so::materialize_decrypted_sos();
            } else if (state.config.protect_so) {
                PLOGW("warm: sokeys.bin missing (SO decrypt on dlopen may fail until keys present)");
            }
            memset(state.config.dex_aes_key.data(), 0, state.config.dex_aes_key.size());
            state.config.dex_aes_key.clear();
        } else if (!state.config.dex_aes_key.empty()) {
            memset(state.config.dex_aes_key.data(), 0, state.config.dex_aes_key.size());
            state.config.dex_aes_key.clear();
        }
    }

    // Install ART hooks before parsing/applying code.bin so DefineClass can patch.
    protector::hook::install_hooks();
    protector::so::install_business_so_hooks();
    // decrypt_already_loaded_async is deferred until after DexMerger (Java calls
    // finishBusinessSoDecrypt) so we do not race ART while mapping dexes.
    std::string code_data = read_file(code_path);
    if (code_data.empty()) {
        PLOGE("failed to read code.bin");
        return;
    }
    // Keep code.bin on disk for warm starts (avoids re-copy from APK every launch).
    // Contents are also held in memory for this process.
    for (auto& dex : state.code_map) {
        for (auto& kv : dex.second) {
            delete kv.second;
        }
    }
    state.code_map.clear();

    if (!codeitem::parse(reinterpret_cast<const uint8_t*>(code_data.data()),
                         code_data.size(), state.code_blob, state.code_map)) {
        PLOGE("parse code.bin failed");
        auto* p = reinterpret_cast<volatile char*>(code_data.data());
        for (size_t i = 0; i < code_data.size(); i++) p[i] = 0;
        return;
    }
    // Wipe temporary file buffer; code_blob holds the working copy.
    {
        auto* p = reinterpret_cast<volatile char*>(code_data.data());
        for (size_t i = 0; i < code_data.size(); i++) p[i] = 0;
    }

    if (!protector::vm::prepare_true_vmp_images()) {
        PLOGE("TRUE_VMP prepare failed");
        protector::risk::crash_exit();
        return;
    }

    // If every method is TRUE_VMP (nothing left to DEX-patch), drop insn key now.
    {
        bool pending = false;
        for (const auto& dex : state.code_map) {
            for (const auto& kv : dex.second) {
                if (kv.second != nullptr && !kv.second->patched.load()) {
                    pending = true;
                    break;
                }
            }
            if (pending) break;
        }
        if (!pending && !state.config.insns_aes_key.empty()) {
            memset(state.config.insns_aes_key.data(), 0, state.config.insns_aes_key.size());
            state.config.insns_aes_key.clear();
            memset(state.code_blob.data(), 0, state.code_blob.size());
            state.code_blob.clear();
            state.code_blob.shrink_to_fit();
            PLOGD("wiped insn key after TRUE_VMP-only prepare");
        }
    }

    state.inited.store(true);
    PLOGI("init_app ok, dexes=%s", state.dexes_zip_path.c_str());

    junk_code_protect(env);
    // Second scan after hooks installed — catches late injectors.
    protector::risk::scan_hooks_and_frida_now();
}

void verify_signature(JNIEnv* env, jclass, jobject context) {
    const std::string& expected = runtime_state().config.app_sign_sha256;
    if (expected.empty()) {
        PLOGE("app_sign_sha256 empty — fail closed");
        protector::risk::crash_exit();
        return;
    }
    protector::risk::scan_hooks_and_frida_now();
    verify_app_signature(env, context, expected);
}

jstring read_application_name(JNIEnv* env, jclass) {
    return env->NewStringUTF(runtime_state().config.application_name.c_str());
}

jstring native_version(JNIEnv* env, jclass) {
    return env->NewStringUTF("protector-native/0.6.21");
}

jboolean environment_degraded(JNIEnv*, jclass) {
    return runtime_state().environment_degraded.load(std::memory_order_acquire)
                   ? JNI_TRUE
                   : JNI_FALSE;
}

jstring drain_threat_reports(JNIEnv* env, jclass) {
    std::string json = protector::report::drain_threats_json();
    return env->NewStringUTF(json.c_str());
}

} // namespace protector::runtime
