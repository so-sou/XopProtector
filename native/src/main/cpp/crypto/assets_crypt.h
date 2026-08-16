#pragma once

#include <jni.h>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace protector::assets {

/** Decrypt PAS1 || AES-GCM blob into {@code out}. Returns false on failure. */
bool decrypt_pas1_blob(const uint8_t* data, size_t len, std::vector<uint8_t>* out);

/** JNI: decrypt PAS1 blob → byte[]. */
jbyteArray decrypt_asset_blob_jni(JNIEnv* env, jclass clazz, jbyteArray blob);

} // namespace protector::assets
