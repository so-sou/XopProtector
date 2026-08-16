#pragma once

#include <jni.h>
#include <cstdint>

namespace protector::vm {

/**
 * Interpret a prepared TRUE_VMP method.
 * @param args Java Object[] matching static parameters (boxed).
 * @return boxed result, or null for void (caller treats as null).
 */
jobject interpret(JNIEnv* env, int dex_index, uint32_t method_idx, jobjectArray args);

/** Decrypt all FLAG_TRUE_VMP payloads into CodeItem::vm_image after code.bin parse. */
bool prepare_true_vmp_images();

} // namespace protector::vm
