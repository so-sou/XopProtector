#include "crypto/assets_crypt.h"
#include "crypto/aes.h"
#include "common/log.h"
#include "common/protector_macro.h"
#include "common/runtime_state.h"

#include <cstring>
#include <vector>

namespace protector::assets {

bool decrypt_pas1_blob(const uint8_t* data, size_t len, std::vector<uint8_t>* out) {
    if (out == nullptr) {
        return false;
    }
    out->clear();
    if (data == nullptr || len < 4 + crypto::GCM_NONCE_LEN + crypto::GCM_TAG_LEN) {
        return false;
    }
    if (data[0] != PROTECTOR_ASSET_MAGIC0 || data[1] != PROTECTOR_ASSET_MAGIC1
            || data[2] != PROTECTOR_ASSET_MAGIC2 || data[3] != PROTECTOR_ASSET_MAGIC3) {
        PLOGE("PAS1 bad magic");
        return false;
    }
    auto& key = runtime_state().config.assets_aes_key;
    if (key.size() != 16) {
        PLOGE("PAS1 decrypt: assets key missing");
        return false;
    }
    const uint8_t* enc = data + 4;
    size_t enc_len = len - 4;
    size_t plain_len = enc_len - crypto::GCM_NONCE_LEN - crypto::GCM_TAG_LEN;
    out->resize(plain_len);
    if (!crypto::aes128_gcm_decrypt(key.data(), enc, enc_len, out->data(), plain_len)) {
        PLOGE("PAS1 AES-GCM auth failed");
        out->clear();
        return false;
    }
    return true;
}

jbyteArray decrypt_asset_blob_jni(JNIEnv* env, jclass, jbyteArray blob) {
    if (env == nullptr || blob == nullptr) {
        return nullptr;
    }
    jsize n = env->GetArrayLength(blob);
    if (n <= 0) {
        env->ThrowNew(env->FindClass("java/lang/IllegalStateException"),
                      "PAS1 asset blob empty");
        return nullptr;
    }
    std::vector<uint8_t> raw(static_cast<size_t>(n));
    env->GetByteArrayRegion(blob, 0, n, reinterpret_cast<jbyte*>(raw.data()));
    std::vector<uint8_t> plain;
    if (!decrypt_pas1_blob(raw.data(), raw.size(), &plain)) {
        env->ThrowNew(env->FindClass("java/lang/IllegalStateException"),
                      "PAS1 asset decrypt failed");
        return nullptr;
    }
    jbyteArray out = env->NewByteArray(static_cast<jsize>(plain.size()));
    if (out == nullptr) {
        return nullptr;
    }
    if (!plain.empty()) {
        env->SetByteArrayRegion(out, 0, static_cast<jsize>(plain.size()),
                                reinterpret_cast<const jbyte*>(plain.data()));
    }
    return out;
}

} // namespace protector::assets
