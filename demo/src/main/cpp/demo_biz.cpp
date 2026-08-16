#include <jni.h>

/**
 * Tiny business SO for --protect-so smoke tests.
 * Keep .text free of dynamic relocs that patch into .text (packer skips those).
 */
extern "C" JNIEXPORT jint JNICALL
Java_com_yqsh_protectordemo_Business_nativeAddRaw(JNIEnv*, jclass, jint a, jint b) {
    return a + b;
}
