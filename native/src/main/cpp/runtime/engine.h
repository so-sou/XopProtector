#pragma once

#include <jni.h>

namespace protector::runtime {

void on_load(JavaVM* vm);
void init_app(JNIEnv* env, jclass clazz, jstring protector_dir);
jstring read_application_name(JNIEnv* env, jclass clazz);
jstring native_version(JNIEnv* env, jclass clazz);
/** Verify APK signing cert SHA-256 against config; no-op if unset. */
void verify_signature(JNIEnv* env, jclass clazz, jobject context);
/** Occasional JunkClass presence check (uses stored JavaVM). */
void maybe_verify_junk_class();
/** Allow junk checks after ClassLoader + DexMerger are ready. */
void enable_junk_verify(JNIEnv* env, jclass clazz);
/** True after RASP Degrade mode recorded an environment risk. */
jboolean environment_degraded(JNIEnv* env, jclass clazz);
/** Drain in-memory threat events as a JSON array string. */
jstring drain_threat_reports(JNIEnv* env, jclass clazz);

} // namespace protector::runtime
