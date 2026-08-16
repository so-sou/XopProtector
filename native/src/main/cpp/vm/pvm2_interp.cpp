#include "vm/pvm2_interp.h"
#include "vm/pvm2_format.h"
#include "common/runtime_state.h"
#include "common/log.h"
#include "common/protector_macro.h"
#include "crypto/aes.h"
#include "risk/risk.h"
#include "risk/so_guard.h"

#include <cmath>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace protector::vm {

struct Reg {
    int32_t i = 0;
    int64_t j = 0;
    jobject o = nullptr;
};

struct PendingResult {
    bool valid = false;
    int32_t i = 0;
    int64_t j = 0;
    jobject o = nullptr;
};

static int16_t read_i16(const uint8_t* p) {
    int16_t v;
    memcpy(&v, p, 2);
    return v;
}

static int32_t read_i32(const uint8_t* p) {
    int32_t v;
    memcpy(&v, p, 4);
    return v;
}

static int64_t read_i64(const uint8_t* p) {
    int64_t v;
    memcpy(&v, p, 8);
    return v;
}

static uint16_t read_u16(const uint8_t* p) {
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}

static bool cmp_i32(int cond, int32_t a, int32_t b) {
    switch (cond) {
        case COND_EQ: return a == b;
        case COND_NE: return a != b;
        case COND_LT: return a < b;
        case COND_GE: return a >= b;
        case COND_GT: return a > b;
        case COND_LE: return a <= b;
        default: return false;
    }
}

static bool binop_i32(JNIEnv* env, int op, int32_t a, int32_t b, int32_t* out) {
    switch (op) {
        case BIN_ADD: *out = a + b; return true;
        case BIN_SUB: *out = a - b; return true;
        case BIN_MUL: *out = a * b; return true;
        case BIN_AND: *out = a & b; return true;
        case BIN_OR: *out = a | b; return true;
        case BIN_XOR: *out = a ^ b; return true;
        case BIN_SHL: *out = a << (b & 31); return true;
        case BIN_SHR: *out = a >> (b & 31); return true;
        case BIN_USHR:
            *out = static_cast<int32_t>(static_cast<uint32_t>(a) >> (b & 31));
            return true;
        case BIN_DIV:
            if (b == 0) {
                env->ThrowNew(env->FindClass("java/lang/ArithmeticException"), "/ by zero");
                return false;
            }
            // Dalvik: INT_MIN / -1 == INT_MIN
            if (a == static_cast<int32_t>(0x80000000) && b == -1) {
                *out = a;
                return true;
            }
            *out = a / b;
            return true;
        case BIN_REM:
            if (b == 0) {
                env->ThrowNew(env->FindClass("java/lang/ArithmeticException"), "/ by zero");
                return false;
            }
            if (a == static_cast<int32_t>(0x80000000) && b == -1) {
                *out = 0;
                return true;
            }
            *out = a % b;
            return true;
        default:
            *out = 0;
            return true;
    }
}

static bool binop_i64(JNIEnv* env, int op, int64_t a, int64_t b, int64_t* out) {
    switch (op) {
        case BIN_ADD: *out = a + b; return true;
        case BIN_SUB: *out = a - b; return true;
        case BIN_MUL: *out = a * b; return true;
        case BIN_AND: *out = a & b; return true;
        case BIN_OR: *out = a | b; return true;
        case BIN_XOR: *out = a ^ b; return true;
        case BIN_SHL: *out = a << (b & 63); return true;
        case BIN_SHR: *out = a >> (b & 63); return true;
        case BIN_USHR:
            *out = static_cast<int64_t>(static_cast<uint64_t>(a) >> (b & 63));
            return true;
        case BIN_DIV:
            if (b == 0) {
                env->ThrowNew(env->FindClass("java/lang/ArithmeticException"), "/ by zero");
                return false;
            }
            if (a == std::numeric_limits<int64_t>::min() && b == -1) {
                *out = a;
                return true;
            }
            *out = a / b;
            return true;
        case BIN_REM:
            if (b == 0) {
                env->ThrowNew(env->FindClass("java/lang/ArithmeticException"), "/ by zero");
                return false;
            }
            if (a == std::numeric_limits<int64_t>::min() && b == -1) {
                *out = 0;
                return true;
            }
            *out = a % b;
            return true;
        default:
            *out = 0;
            return true;
    }
}

static float as_float(int32_t bits) {
    float f;
    memcpy(&f, &bits, sizeof(f));
    return f;
}

static int32_t float_bits(float f) {
    int32_t bits;
    memcpy(&bits, &f, sizeof(bits));
    return bits;
}

static double as_double(int64_t bits) {
    double d;
    memcpy(&d, &bits, sizeof(d));
    return d;
}

/** ART/Dalvik float→int: NaN→0, clamp to INT_MIN/MAX. */
static int32_t art_float_to_int(float f) {
    if (std::isnan(f)) {
        return 0;
    }
    if (f >= static_cast<float>(std::numeric_limits<int32_t>::max())) {
        return std::numeric_limits<int32_t>::max();
    }
    if (f <= static_cast<float>(std::numeric_limits<int32_t>::min())) {
        return std::numeric_limits<int32_t>::min();
    }
    return static_cast<int32_t>(f);
}

/** ART/Dalvik float→long: NaN→0, clamp to LONG_MIN/MAX. */
static int64_t art_float_to_long(float f) {
    if (std::isnan(f)) {
        return 0;
    }
    if (f >= static_cast<float>(std::numeric_limits<int64_t>::max())) {
        return std::numeric_limits<int64_t>::max();
    }
    if (f <= static_cast<float>(std::numeric_limits<int64_t>::min())) {
        return std::numeric_limits<int64_t>::min();
    }
    return static_cast<int64_t>(f);
}

static int32_t art_double_to_int(double d) {
    if (std::isnan(d)) {
        return 0;
    }
    if (d >= static_cast<double>(std::numeric_limits<int32_t>::max())) {
        return std::numeric_limits<int32_t>::max();
    }
    if (d <= static_cast<double>(std::numeric_limits<int32_t>::min())) {
        return std::numeric_limits<int32_t>::min();
    }
    return static_cast<int32_t>(d);
}

static int64_t art_double_to_long(double d) {
    if (std::isnan(d)) {
        return 0;
    }
    if (d >= static_cast<double>(std::numeric_limits<int64_t>::max())) {
        return std::numeric_limits<int64_t>::max();
    }
    if (d <= static_cast<double>(std::numeric_limits<int64_t>::min())) {
        return std::numeric_limits<int64_t>::min();
    }
    return static_cast<int64_t>(d);
}

static bool is_shift_binop(int bin) {
    return bin == BIN_SHL || bin == BIN_SHR || bin == BIN_USHR;
}

static int64_t double_bits(double d) {
    int64_t bits;
    memcpy(&bits, &d, sizeof(bits));
    return bits;
}

static float binop_f32(int op, float a, float b) {
    switch (op) {
        case BIN_ADD: return a + b;
        case BIN_SUB: return a - b;
        case BIN_MUL: return a * b;
        case BIN_DIV: return a / b;
        case BIN_REM: return std::fmod(a, b);
        default: return 0.0f;
    }
}

static double binop_f64(int op, double a, double b) {
    switch (op) {
        case BIN_ADD: return a + b;
        case BIN_SUB: return a - b;
        case BIN_MUL: return a * b;
        case BIN_DIV: return a / b;
        case BIN_REM: return std::fmod(a, b);
        default: return 0.0;
    }
}

static int32_t cmp_float(float a, float b, bool nan_gt) {
    if (a == b) return 0;
    if (a < b) return -1;
    if (a > b) return 1;
    return nan_gt ? 1 : -1;
}

static int32_t cmp_double(double a, double b, bool nan_gt) {
    if (a == b) return 0;
    if (a < b) return -1;
    if (a > b) return 1;
    return nan_gt ? 1 : -1;
}

static int32_t cmp_long(int64_t a, int64_t b) {
    if (a == b) return 0;
    return (a < b) ? -1 : 1;
}

static bool apply_unop(int kind, Reg* dst, const Reg& src) {
    switch (kind) {
        case UN_NEG_LONG:
            dst->j = -src.j;
            return true;
        case UN_NEG_FLOAT:
            dst->i = float_bits(-as_float(src.i));
            return true;
        case UN_NEG_DOUBLE:
            dst->j = double_bits(-as_double(src.j));
            return true;
        case UN_NOT_INT:
            dst->i = ~src.i;
            return true;
        case UN_NOT_LONG:
            dst->j = ~src.j;
            return true;
        case UN_INT_TO_LONG:
            dst->j = static_cast<int64_t>(src.i);
            return true;
        case UN_INT_TO_FLOAT:
            dst->i = float_bits(static_cast<float>(src.i));
            return true;
        case UN_INT_TO_DOUBLE:
            dst->j = double_bits(static_cast<double>(src.i));
            return true;
        case UN_LONG_TO_INT:
            dst->i = static_cast<int32_t>(src.j);
            return true;
        case UN_LONG_TO_FLOAT:
            dst->i = float_bits(static_cast<float>(src.j));
            return true;
        case UN_LONG_TO_DOUBLE:
            dst->j = double_bits(static_cast<double>(src.j));
            return true;
        case UN_FLOAT_TO_INT:
            dst->i = art_float_to_int(as_float(src.i));
            return true;
        case UN_FLOAT_TO_LONG:
            dst->j = art_float_to_long(as_float(src.i));
            return true;
        case UN_FLOAT_TO_DOUBLE:
            dst->j = double_bits(static_cast<double>(as_float(src.i)));
            return true;
        case UN_DOUBLE_TO_INT:
            dst->i = art_double_to_int(as_double(src.j));
            return true;
        case UN_DOUBLE_TO_LONG:
            dst->j = art_double_to_long(as_double(src.j));
            return true;
        case UN_DOUBLE_TO_FLOAT:
            dst->i = float_bits(static_cast<float>(as_double(src.j)));
            return true;
        case UN_INT_TO_BYTE:
            dst->i = static_cast<int8_t>(src.i);
            return true;
        case UN_INT_TO_CHAR:
            dst->i = static_cast<uint16_t>(src.i);
            return true;
        case UN_INT_TO_SHORT:
            dst->i = static_cast<int16_t>(src.i);
            return true;
        default:
            return false;
    }
}

static void clear_regs(JNIEnv* env, std::vector<Reg>& regs) {
    for (auto& r : regs) {
        if (r.o != nullptr) {
            env->DeleteLocalRef(r.o);
            r.o = nullptr;
        }
    }
}

static void clear_pending(JNIEnv* env, PendingResult& pending) {
    if (pending.o != nullptr) {
        env->DeleteLocalRef(pending.o);
        pending.o = nullptr;
    }
    pending.valid = false;
}

static std::string descriptor_to_jni(const std::string& desc) {
    if (desc.size() >= 2 && desc[0] == 'L' && desc.back() == ';') {
        return desc.substr(1, desc.size() - 2);
    }
    return desc;
}

static jclass find_class_desc(JNIEnv* env, const std::string& desc) {
    return env->FindClass(descriptor_to_jni(desc).c_str());
}

static bool parse_member_ref(const std::string& s, std::string* owner,
                             std::string* name, std::string* tail) {
    if (owner == nullptr || name == nullptr || tail == nullptr) {
        return false;
    }
    auto arrow = s.find("->");
    if (arrow == std::string::npos) {
        return false;
    }
    *owner = s.substr(0, arrow);
    auto split = s.find_first_of(":(", arrow + 2);
    if (split == std::string::npos) {
        return false;
    }
    *name = s.substr(arrow + 2, split - arrow - 2);
    *tail = s.substr(split);
    return true;
}

static std::vector<char> parse_arg_types(const char* sig) {
    std::vector<char> out;
    if (sig == nullptr || sig[0] != '(') {
        return out;
    }
    const char* p = sig + 1;
    while (*p && *p != ')') {
        if (*p == 'L') {
            while (*p && *p != ';') {
                p++;
            }
            if (*p == ';') {
                p++;
            }
            out.push_back('L');
        } else if (*p == '[') {
            while (*p == '[') {
                p++;
            }
            if (*p == 'L') {
                while (*p && *p != ';') {
                    p++;
                }
                if (*p == ';') {
                    p++;
                }
            } else if (*p != '\0') {
                p++;
            }
            out.push_back('L');
        } else {
            out.push_back(*p++);
        }
    }
    return out;
}

static const char* return_type_of_sig(const char* sig) {
    if (sig == nullptr) {
        return "V";
    }
    const char* p = strchr(sig, ')');
    return (p != nullptr && p[1] != '\0') ? p + 1 : "V";
}

static bool reg_bounds(uint8_t r, size_t reg_count) {
    return r < reg_count;
}

static bool reg_bounds_wide(uint8_t r, size_t reg_count) {
    return r + 1 < reg_count;
}

static jobject box_int(JNIEnv* env, int32_t v) {
    jclass cls = env->FindClass("java/lang/Integer");
    if (!cls) return nullptr;
    jmethodID mid = env->GetStaticMethodID(cls, "valueOf", "(I)Ljava/lang/Integer;");
    if (!mid) return nullptr;
    return env->CallStaticObjectMethod(cls, mid, v);
}

static jobject box_long(JNIEnv* env, int64_t v) {
    jclass cls = env->FindClass("java/lang/Long");
    if (!cls) return nullptr;
    jmethodID mid = env->GetStaticMethodID(cls, "valueOf", "(J)Ljava/lang/Long;");
    if (!mid) return nullptr;
    return env->CallStaticObjectMethod(cls, mid, v);
}

static jobject box_bool(JNIEnv* env, bool v) {
    jclass cls = env->FindClass("java/lang/Boolean");
    if (!cls) return nullptr;
    jmethodID mid = env->GetStaticMethodID(cls, "valueOf", "(Z)Ljava/lang/Boolean;");
    if (!mid) return nullptr;
    return env->CallStaticObjectMethod(cls, mid, v ? JNI_TRUE : JNI_FALSE);
}

static jobject box_float(JNIEnv* env, jfloat v) {
    jclass cls = env->FindClass("java/lang/Float");
    if (!cls) return nullptr;
    jmethodID mid = env->GetStaticMethodID(cls, "valueOf", "(F)Ljava/lang/Float;");
    if (!mid) return nullptr;
    return env->CallStaticObjectMethod(cls, mid, v);
}

static jobject box_double(JNIEnv* env, jdouble v) {
    jclass cls = env->FindClass("java/lang/Double");
    if (!cls) return nullptr;
    jmethodID mid = env->GetStaticMethodID(cls, "valueOf", "(D)Ljava/lang/Double;");
    if (!mid) return nullptr;
    return env->CallStaticObjectMethod(cls, mid, v);
}

static bool unbox_arg(JNIEnv* env, jobject obj, const char* expected, Reg* out) {
    if (expected[0] == 'L' || expected[0] == '[') {
        out->o = obj ? env->NewLocalRef(obj) : nullptr;
        return true;
    }
    if (obj == nullptr) {
        return false;
    }
    switch (expected[0]) {
        case 'I':
        case 'B':
        case 'S':
        case 'C': {
            jclass cls = env->FindClass("java/lang/Integer");
            jmethodID mid = env->GetMethodID(cls, "intValue", "()I");
            out->i = env->CallIntMethod(obj, mid);
            return !env->ExceptionCheck();
        }
        case 'Z': {
            jclass cls = env->FindClass("java/lang/Boolean");
            jmethodID mid = env->GetMethodID(cls, "booleanValue", "()Z");
            out->i = env->CallBooleanMethod(obj, mid) ? 1 : 0;
            return !env->ExceptionCheck();
        }
        case 'J': {
            jclass cls = env->FindClass("java/lang/Long");
            jmethodID mid = env->GetMethodID(cls, "longValue", "()J");
            out->j = env->CallLongMethod(obj, mid);
            return !env->ExceptionCheck();
        }
        case 'F': {
            jclass cls = env->FindClass("java/lang/Float");
            jmethodID mid = env->GetMethodID(cls, "floatValue", "()F");
            jfloat f = env->CallFloatMethod(obj, mid);
            if (env->ExceptionCheck()) return false;
            memcpy(&out->i, &f, sizeof(f));
            return true;
        }
        case 'D': {
            jclass cls = env->FindClass("java/lang/Double");
            jmethodID mid = env->GetMethodID(cls, "doubleValue", "()D");
            jdouble d = env->CallDoubleMethod(obj, mid);
            if (env->ExceptionCheck()) return false;
            memcpy(&out->j, &d, sizeof(d));
            return true;
        }
        default:
            return false;
    }
}

static bool fill_jargs(const char* sig, const uint8_t* arg_regs, uint8_t argc,
                       const std::vector<Reg>& regs, jvalue* jargs, int* logical_argc) {
    std::vector<char> types = parse_arg_types(sig);
    int ti = 0;
    int ri = 0;
    while (ri < argc) {
        if (ti >= static_cast<int>(types.size())) {
            return false;
        }
        char t = types[ti++];
        uint8_t r = arg_regs[ri];
        if (!reg_bounds(r, regs.size())) {
            return false;
        }
        switch (t) {
            case 'Z':
                jargs[ti - 1].z = regs[r].i != 0 ? JNI_TRUE : JNI_FALSE;
                ri += 1;
                break;
            case 'B':
                jargs[ti - 1].b = static_cast<jbyte>(regs[r].i);
                ri += 1;
                break;
            case 'S':
                jargs[ti - 1].s = static_cast<jshort>(regs[r].i);
                ri += 1;
                break;
            case 'C':
                jargs[ti - 1].c = static_cast<jchar>(regs[r].i);
                ri += 1;
                break;
            case 'I':
                jargs[ti - 1].i = regs[r].i;
                ri += 1;
                break;
            case 'F': {
                jfloat f;
                memcpy(&f, &regs[r].i, sizeof(f));
                jargs[ti - 1].f = f;
                ri += 1;
                break;
            }
            case 'J':
                if (!reg_bounds_wide(r, regs.size())) {
                    return false;
                }
                jargs[ti - 1].j = regs[r].j;
                ri += 2;
                break;
            case 'D': {
                if (!reg_bounds_wide(r, regs.size())) {
                    return false;
                }
                jdouble d;
                memcpy(&d, &regs[r].j, sizeof(d));
                jargs[ti - 1].d = d;
                ri += 2;
                break;
            }
            default:
                jargs[ti - 1].l = regs[r].o;
                ri += 1;
                break;
        }
    }
    if (ri != argc || ti != static_cast<int>(types.size())) {
        return false;
    }
    if (logical_argc) {
        *logical_argc = ti;
    }
    return true;
}

static bool invoke_method(JNIEnv* env, uint8_t op, const std::string& desc,
                          const uint8_t* arg_regs, uint8_t argc,
                          const std::vector<Reg>& regs, PendingResult& pending) {
    std::string owner;
    std::string name;
    std::string sig;
    if (!parse_member_ref(desc, &owner, &name, &sig)) {
        return false;
    }
    jclass cls = find_class_desc(env, owner);
    if (cls == nullptr) {
        return false;
    }
    jmethodID mid = (op == OP_INVOKE_STATIC)
            ? env->GetStaticMethodID(cls, name.c_str(), sig.c_str())
            : env->GetMethodID(cls, name.c_str(), sig.c_str());
    if (mid == nullptr) {
        return false;
    }

    const uint8_t* param_regs = arg_regs;
    uint8_t param_regc = argc;
    if (op != OP_INVOKE_STATIC) {
        if (argc == 0) {
            return false;
        }
        param_regs = arg_regs + 1;
        param_regc = static_cast<uint8_t>(argc - 1);
    }
    jvalue args_buf[32];
    std::vector<jvalue> args_vec;
    jvalue* args = args_buf;
    if (param_regc > 32) {
        args_vec.resize(param_regc);
        args = args_vec.data();
    }
    if (!fill_jargs(sig.c_str(), param_regs, param_regc, regs, args, nullptr)) {
        return false;
    }

    const char* ret = return_type_of_sig(sig.c_str());
    clear_pending(env, pending);

    if (op == OP_INVOKE_STATIC) {
        switch (ret[0]) {
            case 'V':
                env->CallStaticVoidMethodA(cls, mid, args);
                return !env->ExceptionCheck();
            case 'Z': {
                jboolean v = env->CallStaticBooleanMethodA(cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.i = v ? 1 : 0;
                return true;
            }
            case 'B': {
                jbyte v = env->CallStaticByteMethodA(cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.i = v;
                return true;
            }
            case 'S': {
                jshort v = env->CallStaticShortMethodA(cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.i = v;
                return true;
            }
            case 'C': {
                jchar v = env->CallStaticCharMethodA(cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.i = v;
                return true;
            }
            case 'I': {
                jint v = env->CallStaticIntMethodA(cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.i = v;
                return true;
            }
            case 'F': {
                jfloat v = env->CallStaticFloatMethodA(cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                memcpy(&pending.i, &v, sizeof(v));
                return true;
            }
            case 'J': {
                jlong v = env->CallStaticLongMethodA(cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.j = v;
                return true;
            }
            case 'D': {
                jdouble v = env->CallStaticDoubleMethodA(cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                memcpy(&pending.j, &v, sizeof(v));
                return true;
            }
            default: {
                jobject v = env->CallStaticObjectMethodA(cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.o = v ? env->NewLocalRef(v) : nullptr;
                return true;
            }
        }
    }

    if (argc == 0) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), "VMP invoke missing receiver");
        return false;
    }
    uint8_t recv = arg_regs[0];
    if (!reg_bounds(recv, regs.size())) {
        return false;
    }
    jobject thiz = regs[recv].o;

    if (op == OP_INVOKE_SUPER) {
        switch (ret[0]) {
            case 'V':
                env->CallNonvirtualVoidMethodA(thiz, cls, mid, args);
                return !env->ExceptionCheck();
            case 'Z': {
                jboolean v = env->CallNonvirtualBooleanMethodA(thiz, cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.i = v ? 1 : 0;
                return true;
            }
            case 'B': {
                jbyte v = env->CallNonvirtualByteMethodA(thiz, cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.i = v;
                return true;
            }
            case 'S': {
                jshort v = env->CallNonvirtualShortMethodA(thiz, cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.i = v;
                return true;
            }
            case 'C': {
                jchar v = env->CallNonvirtualCharMethodA(thiz, cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.i = v;
                return true;
            }
            case 'I': {
                jint v = env->CallNonvirtualIntMethodA(thiz, cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.i = v;
                return true;
            }
            case 'F': {
                jfloat v = env->CallNonvirtualFloatMethodA(thiz, cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                memcpy(&pending.i, &v, sizeof(v));
                return true;
            }
            case 'J': {
                jlong v = env->CallNonvirtualLongMethodA(thiz, cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.j = v;
                return true;
            }
            case 'D': {
                jdouble v = env->CallNonvirtualDoubleMethodA(thiz, cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                memcpy(&pending.j, &v, sizeof(v));
                return true;
            }
            default: {
                jobject v = env->CallNonvirtualObjectMethodA(thiz, cls, mid, args);
                if (env->ExceptionCheck()) return false;
                pending.valid = true;
                pending.o = v ? env->NewLocalRef(v) : nullptr;
                return true;
            }
        }
    }

    switch (ret[0]) {
        case 'V':
            env->CallVoidMethodA(thiz, mid, args);
            return !env->ExceptionCheck();
        case 'Z': {
            jboolean v = env->CallBooleanMethodA(thiz, mid, args);
            if (env->ExceptionCheck()) return false;
            pending.valid = true;
            pending.i = v ? 1 : 0;
            return true;
        }
        case 'B': {
            jbyte v = env->CallByteMethodA(thiz, mid, args);
            if (env->ExceptionCheck()) return false;
            pending.valid = true;
            pending.i = v;
            return true;
        }
        case 'S': {
            jshort v = env->CallShortMethodA(thiz, mid, args);
            if (env->ExceptionCheck()) return false;
            pending.valid = true;
            pending.i = v;
            return true;
        }
        case 'C': {
            jchar v = env->CallCharMethodA(thiz, mid, args);
            if (env->ExceptionCheck()) return false;
            pending.valid = true;
            pending.i = v;
            return true;
        }
        case 'I': {
            jint v = env->CallIntMethodA(thiz, mid, args);
            if (env->ExceptionCheck()) return false;
            pending.valid = true;
            pending.i = v;
            return true;
        }
        case 'F': {
            jfloat v = env->CallFloatMethodA(thiz, mid, args);
            if (env->ExceptionCheck()) return false;
            pending.valid = true;
            memcpy(&pending.i, &v, sizeof(v));
            return true;
        }
        case 'J': {
            jlong v = env->CallLongMethodA(thiz, mid, args);
            if (env->ExceptionCheck()) return false;
            pending.valid = true;
            pending.j = v;
            return true;
        }
        case 'D': {
            jdouble v = env->CallDoubleMethodA(thiz, mid, args);
            if (env->ExceptionCheck()) return false;
            pending.valid = true;
            memcpy(&pending.j, &v, sizeof(v));
            return true;
        }
        default: {
            jobject v = env->CallObjectMethodA(thiz, mid, args);
            if (env->ExceptionCheck()) return false;
            pending.valid = true;
            pending.o = v ? env->NewLocalRef(v) : nullptr;
            return true;
        }
    }
}

static bool get_static_field(JNIEnv* env, const std::string& desc, uint8_t kind, Reg* dst) {
    std::string owner;
    std::string name;
    std::string type;
    if (!parse_member_ref(desc, &owner, &name, &type)) {
        return false;
    }
    if (!type.empty() && type[0] == ':') {
        type = type.substr(1);
    }
    jclass cls = find_class_desc(env, owner);
    if (cls == nullptr) {
        return false;
    }
    jfieldID fid = env->GetStaticFieldID(cls, name.c_str(), type.c_str());
    if (fid == nullptr) {
        return false;
    }
    switch (kind) {
        case KIND_I:
            if (type == "F") {
                jfloat f = env->GetStaticFloatField(cls, fid);
                if (env->ExceptionCheck()) return false;
                memcpy(&dst->i, &f, sizeof(f));
                return true;
            }
            dst->i = env->GetStaticIntField(cls, fid);
            return !env->ExceptionCheck();
        case KIND_J:
            if (type == "D") {
                jdouble d = env->GetStaticDoubleField(cls, fid);
                if (env->ExceptionCheck()) return false;
                memcpy(&dst->j, &d, sizeof(d));
                return true;
            }
            dst->j = env->GetStaticLongField(cls, fid);
            return !env->ExceptionCheck();
        case KIND_Z:
            dst->i = env->GetStaticBooleanField(cls, fid) ? 1 : 0;
            return !env->ExceptionCheck();
        case KIND_B:
            dst->i = env->GetStaticByteField(cls, fid);
            return !env->ExceptionCheck();
        case KIND_S:
            dst->i = env->GetStaticShortField(cls, fid);
            return !env->ExceptionCheck();
        case KIND_C:
            dst->i = env->GetStaticCharField(cls, fid);
            return !env->ExceptionCheck();
        case KIND_L:
            if (dst->o) env->DeleteLocalRef(dst->o);
            dst->o = env->GetStaticObjectField(cls, fid);
            if (dst->o) dst->o = env->NewLocalRef(dst->o);
            return !env->ExceptionCheck();
        default:
            return false;
    }
}

static bool put_static_field(JNIEnv* env, const std::string& desc, uint8_t kind, const Reg& src) {
    std::string owner;
    std::string name;
    std::string type;
    if (!parse_member_ref(desc, &owner, &name, &type)) {
        return false;
    }
    if (!type.empty() && type[0] == ':') {
        type = type.substr(1);
    }
    jclass cls = find_class_desc(env, owner);
    if (cls == nullptr) {
        return false;
    }
    jfieldID fid = env->GetStaticFieldID(cls, name.c_str(), type.c_str());
    if (fid == nullptr) {
        return false;
    }
    switch (kind) {
        case KIND_I:
            if (type == "F") {
                jfloat f;
                memcpy(&f, &src.i, sizeof(f));
                env->SetStaticFloatField(cls, fid, f);
            } else {
                env->SetStaticIntField(cls, fid, src.i);
            }
            return !env->ExceptionCheck();
        case KIND_J:
            if (type == "D") {
                jdouble d;
                memcpy(&d, &src.j, sizeof(d));
                env->SetStaticDoubleField(cls, fid, d);
            } else {
                env->SetStaticLongField(cls, fid, src.j);
            }
            return !env->ExceptionCheck();
        case KIND_Z:
            env->SetStaticBooleanField(cls, fid, src.i != 0 ? JNI_TRUE : JNI_FALSE);
            return !env->ExceptionCheck();
        case KIND_B:
            env->SetStaticByteField(cls, fid, static_cast<jbyte>(src.i));
            return !env->ExceptionCheck();
        case KIND_S:
            env->SetStaticShortField(cls, fid, static_cast<jshort>(src.i));
            return !env->ExceptionCheck();
        case KIND_C:
            env->SetStaticCharField(cls, fid, static_cast<jchar>(src.i));
            return !env->ExceptionCheck();
        case KIND_L:
            env->SetStaticObjectField(cls, fid, src.o);
            return !env->ExceptionCheck();
        default:
            return false;
    }
}

static bool get_instance_field(JNIEnv* env, const std::string& desc, uint8_t kind,
                               jobject obj, Reg* dst) {
    std::string owner;
    std::string name;
    std::string type;
    if (!parse_member_ref(desc, &owner, &name, &type)) {
        return false;
    }
    if (!type.empty() && type[0] == ':') {
        type = type.substr(1);
    }
    jclass cls = find_class_desc(env, owner);
    if (cls == nullptr) {
        return false;
    }
    jfieldID fid = env->GetFieldID(cls, name.c_str(), type.c_str());
    if (fid == nullptr) {
        return false;
    }
    switch (kind) {
        case KIND_I:
            if (type == "F") {
                jfloat f = env->GetFloatField(obj, fid);
                if (env->ExceptionCheck()) return false;
                memcpy(&dst->i, &f, sizeof(f));
                return true;
            }
            dst->i = env->GetIntField(obj, fid);
            return !env->ExceptionCheck();
        case KIND_J:
            if (type == "D") {
                jdouble d = env->GetDoubleField(obj, fid);
                if (env->ExceptionCheck()) return false;
                memcpy(&dst->j, &d, sizeof(d));
                return true;
            }
            dst->j = env->GetLongField(obj, fid);
            return !env->ExceptionCheck();
        case KIND_Z:
            dst->i = env->GetBooleanField(obj, fid) ? 1 : 0;
            return !env->ExceptionCheck();
        case KIND_B:
            dst->i = env->GetByteField(obj, fid);
            return !env->ExceptionCheck();
        case KIND_S:
            dst->i = env->GetShortField(obj, fid);
            return !env->ExceptionCheck();
        case KIND_C:
            dst->i = env->GetCharField(obj, fid);
            return !env->ExceptionCheck();
        case KIND_L:
            if (dst->o) env->DeleteLocalRef(dst->o);
            dst->o = env->GetObjectField(obj, fid);
            if (dst->o) dst->o = env->NewLocalRef(dst->o);
            return !env->ExceptionCheck();
        default:
            return false;
    }
}

static bool put_instance_field(JNIEnv* env, const std::string& desc, uint8_t kind,
                               jobject obj, const Reg& src) {
    std::string owner;
    std::string name;
    std::string type;
    if (!parse_member_ref(desc, &owner, &name, &type)) {
        return false;
    }
    if (!type.empty() && type[0] == ':') {
        type = type.substr(1);
    }
    jclass cls = find_class_desc(env, owner);
    if (cls == nullptr) {
        return false;
    }
    jfieldID fid = env->GetFieldID(cls, name.c_str(), type.c_str());
    if (fid == nullptr) {
        return false;
    }
    switch (kind) {
        case KIND_I:
            if (type == "F") {
                jfloat f;
                memcpy(&f, &src.i, sizeof(f));
                env->SetFloatField(obj, fid, f);
            } else {
                env->SetIntField(obj, fid, src.i);
            }
            return !env->ExceptionCheck();
        case KIND_J:
            if (type == "D") {
                jdouble d;
                memcpy(&d, &src.j, sizeof(d));
                env->SetDoubleField(obj, fid, d);
            } else {
                env->SetLongField(obj, fid, src.j);
            }
            return !env->ExceptionCheck();
        case KIND_Z:
            env->SetBooleanField(obj, fid, src.i != 0 ? JNI_TRUE : JNI_FALSE);
            return !env->ExceptionCheck();
        case KIND_B:
            env->SetByteField(obj, fid, static_cast<jbyte>(src.i));
            return !env->ExceptionCheck();
        case KIND_S:
            env->SetShortField(obj, fid, static_cast<jshort>(src.i));
            return !env->ExceptionCheck();
        case KIND_C:
            env->SetCharField(obj, fid, static_cast<jchar>(src.i));
            return !env->ExceptionCheck();
        case KIND_L:
            env->SetObjectField(obj, fid, src.o);
            return !env->ExceptionCheck();
        default:
            return false;
    }
}

static jobject new_array_for_type(JNIEnv* env, const std::string& type, jsize len) {
    if (type == "[Z") return env->NewBooleanArray(len);
    if (type == "[B") return env->NewByteArray(len);
    if (type == "[S") return env->NewShortArray(len);
    if (type == "[C") return env->NewCharArray(len);
    if (type == "[I") return env->NewIntArray(len);
    if (type == "[J") return env->NewLongArray(len);
    if (type == "[F") return env->NewFloatArray(len);
    if (type == "[D") return env->NewDoubleArray(len);
    jclass elem = find_class_desc(env, type.substr(1));
    if (elem == nullptr) return nullptr;
    return env->NewObjectArray(len, elem, nullptr);
}

static uint8_t kind_of_array_type(const std::string& type) {
    if (type == "[I" || type == "[F") return KIND_I;
    if (type == "[J" || type == "[D") return KIND_J;
    if (type == "[Z") return KIND_Z;
    if (type == "[B") return KIND_B;
    if (type == "[S") return KIND_S;
    if (type == "[C") return KIND_C;
    return KIND_L;
}

static bool aget(JNIEnv* env, jarray arr, int32_t idx, uint8_t kind, Reg* dst) {
    switch (kind) {
        case KIND_I: {
            // Float arrays share Dalvik aget with int — discriminate via runtime type.
            jclass floatArrCls = env->FindClass("[F");
            if (floatArrCls != nullptr && env->IsInstanceOf(arr, floatArrCls)) {
                jfloat v;
                env->GetFloatArrayRegion(static_cast<jfloatArray>(arr), idx, 1, &v);
                if (env->ExceptionCheck()) return false;
                memcpy(&dst->i, &v, sizeof(v));
                return true;
            }
            jint v;
            env->GetIntArrayRegion(static_cast<jintArray>(arr), idx, 1, &v);
            dst->i = v;
            return !env->ExceptionCheck();
        }
        case KIND_J: {
            jclass doubleArrCls = env->FindClass("[D");
            if (doubleArrCls != nullptr && env->IsInstanceOf(arr, doubleArrCls)) {
                jdouble v;
                env->GetDoubleArrayRegion(static_cast<jdoubleArray>(arr), idx, 1, &v);
                if (env->ExceptionCheck()) return false;
                memcpy(&dst->j, &v, sizeof(v));
                return true;
            }
            jlong v;
            env->GetLongArrayRegion(static_cast<jlongArray>(arr), idx, 1, &v);
            dst->j = v;
            return !env->ExceptionCheck();
        }
        case KIND_Z: {
            jbooleanArray a = static_cast<jbooleanArray>(arr);
            jboolean v;
            env->GetBooleanArrayRegion(a, idx, 1, &v);
            dst->i = v ? 1 : 0;
            return !env->ExceptionCheck();
        }
        case KIND_B: {
            jbyteArray a = static_cast<jbyteArray>(arr);
            jbyte v;
            env->GetByteArrayRegion(a, idx, 1, &v);
            dst->i = v;
            return !env->ExceptionCheck();
        }
        case KIND_S: {
            jshortArray a = static_cast<jshortArray>(arr);
            jshort v;
            env->GetShortArrayRegion(a, idx, 1, &v);
            dst->i = v;
            return !env->ExceptionCheck();
        }
        case KIND_C: {
            jcharArray a = static_cast<jcharArray>(arr);
            jchar v;
            env->GetCharArrayRegion(a, idx, 1, &v);
            dst->i = v;
            return !env->ExceptionCheck();
        }
        case KIND_L: {
            jobjectArray a = static_cast<jobjectArray>(arr);
            if (dst->o) env->DeleteLocalRef(dst->o);
            jobject v = env->GetObjectArrayElement(a, idx);
            dst->o = v ? env->NewLocalRef(v) : nullptr;
            if (v) env->DeleteLocalRef(v);
            return !env->ExceptionCheck();
        }
        default:
            return false;
    }
}

static bool aput(JNIEnv* env, jarray arr, int32_t idx, uint8_t kind, const Reg& src) {
    switch (kind) {
        case KIND_I: {
            jclass floatArrCls = env->FindClass("[F");
            if (floatArrCls != nullptr && env->IsInstanceOf(arr, floatArrCls)) {
                jfloat v;
                memcpy(&v, &src.i, sizeof(v));
                env->SetFloatArrayRegion(static_cast<jfloatArray>(arr), idx, 1, &v);
            } else {
                jint v = src.i;
                env->SetIntArrayRegion(static_cast<jintArray>(arr), idx, 1, &v);
            }
            return !env->ExceptionCheck();
        }
        case KIND_J: {
            jclass doubleArrCls = env->FindClass("[D");
            if (doubleArrCls != nullptr && env->IsInstanceOf(arr, doubleArrCls)) {
                jdouble v;
                memcpy(&v, &src.j, sizeof(v));
                env->SetDoubleArrayRegion(static_cast<jdoubleArray>(arr), idx, 1, &v);
            } else {
                jlong v = src.j;
                env->SetLongArrayRegion(static_cast<jlongArray>(arr), idx, 1, &v);
            }
            return !env->ExceptionCheck();
        }
        case KIND_Z: {
            jboolean v = src.i != 0 ? JNI_TRUE : JNI_FALSE;
            env->SetBooleanArrayRegion(static_cast<jbooleanArray>(arr), idx, 1, &v);
            return !env->ExceptionCheck();
        }
        case KIND_B: {
            jbyte v = static_cast<jbyte>(src.i);
            env->SetByteArrayRegion(static_cast<jbyteArray>(arr), idx, 1, &v);
            return !env->ExceptionCheck();
        }
        case KIND_S: {
            jshort v = static_cast<jshort>(src.i);
            env->SetShortArrayRegion(static_cast<jshortArray>(arr), idx, 1, &v);
            return !env->ExceptionCheck();
        }
        case KIND_C: {
            jchar v = static_cast<jchar>(src.i);
            env->SetCharArrayRegion(static_cast<jcharArray>(arr), idx, 1, &v);
            return !env->ExceptionCheck();
        }
        case KIND_L:
            env->SetObjectArrayElement(static_cast<jobjectArray>(arr), idx, src.o);
            return !env->ExceptionCheck();
        default:
            return false;
    }
}

static bool filled_new_array(JNIEnv* env, const std::string& type,
                             const uint8_t* arg_regs, uint8_t argc,
                             const std::vector<Reg>& regs, PendingResult& pending) {
    clear_pending(env, pending);
    jobject arr = new_array_for_type(env, type, argc);
    if (arr == nullptr || env->ExceptionCheck()) {
        return false;
    }
    uint8_t kind = kind_of_array_type(type);
    for (uint8_t i = 0; i < argc; i++) {
        uint8_t r = arg_regs[i];
        if (!reg_bounds(r, regs.size())) {
            env->DeleteLocalRef(arr);
            return false;
        }
        if (kind == KIND_J && !reg_bounds_wide(r, regs.size())) {
            env->DeleteLocalRef(arr);
            return false;
        }
        if (!aput(env, static_cast<jarray>(arr), i, kind, regs[r])) {
            env->DeleteLocalRef(arr);
            return false;
        }
    }
    pending.valid = true;
    pending.o = arr;
    return true;
}

static bool dispatch_exception(JNIEnv* env, const Pvm2Image& img, size_t fault_pc,
                               size_t* pc, jobject* stashed_exception) {
    jthrowable ex = env->ExceptionOccurred();
    if (ex == nullptr) {
        return false;
    }
    // Must clear before FindClass/IsInstanceOf (JNI forbids calls with pending exception).
    jthrowable held = static_cast<jthrowable>(env->NewLocalRef(ex));
    env->ExceptionClear();

    for (const auto& h : img.handlers) {
        if (fault_pc < h.start || fault_pc >= h.end) {
            continue;
        }
        bool match = false;
        if (h.catch_type_idx == PVM2_CATCH_ALL) {
            match = true;
        } else if (h.catch_type_idx < img.types.size()) {
            jclass catch_cls = find_class_desc(env, img.types[h.catch_type_idx]);
            if (catch_cls != nullptr) {
                match = env->IsInstanceOf(held, catch_cls) == JNI_TRUE;
            }
        }
        if (!match) {
            continue;
        }
        if (*stashed_exception != nullptr) {
            env->DeleteLocalRef(*stashed_exception);
        }
        *stashed_exception = env->NewLocalRef(held);
        env->DeleteLocalRef(held);
        *pc = h.handler_pc;
        return true;
    }
    env->Throw(held);
    env->DeleteLocalRef(held);
    return false;
}

PROTECTOR_ENCRYPT bool prepare_true_vmp_images() {
    auto& state = runtime_state();
    if (state.config.insns_aes_key.size() != 16) {
        return false;
    }
    // Bind VMP plaintext exposure to SO integrity.
    risk::so_guard_check();
    if (state.environment_degraded.load(std::memory_order_acquire)
            && state.config.rasp_action.load(std::memory_order_relaxed)
                    == static_cast<int>(RaspAction::Degrade)) {
        PLOGE("TRUE_VMP prepare refused: environment degraded");
        return false;
    }
    for (auto& dex : state.code_map) {
        for (auto& kv : dex.second) {
            CodeItem* item = kv.second;
            if (item == nullptr || (item->flags & FLAG_TRUE_VMP) == 0) {
                continue;
            }
            if (item->insns == nullptr || item->insns_size == 0 || item->plain_insns_size == 0) {
                PLOGE("TRUE_VMP missing payload method=%u", item->method_idx);
                return false;
            }
            item->vm_image.resize(item->plain_insns_size);
            if (!crypto::aes128_gcm_decrypt(state.config.insns_aes_key.data(),
                                            item->insns, item->insns_size,
                                            item->vm_image.data(), item->vm_image.size())) {
                PLOGE("TRUE_VMP decrypt failed method=%u", item->method_idx);
                item->vm_image.clear();
                return false;
            }
            memset(item->insns, 0, item->insns_size);
            item->insns = nullptr;
            item->insns_size = 0;
            item->patched.store(true);
            PLOGI("TRUE_VMP prepared dex=%d method=%u size=%zu",
                  dex.first, item->method_idx, item->vm_image.size());
        }
    }
    return true;
}

PROTECTOR_ENCRYPT static jobject interpret_body(JNIEnv* env, int dex_index, uint32_t method_idx,
                                                 jobjectArray args) {
    auto& state = runtime_state();
    auto dex_it = state.code_map.find(dex_index);
    if (dex_it == state.code_map.end()) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), "VMP bad dex");
        return nullptr;
    }
    auto m_it = dex_it->second.find(method_idx);
    if (m_it == dex_it->second.end() || m_it->second == nullptr) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), "VMP bad method");
        return nullptr;
    }
    CodeItem* item = m_it->second;
    if ((item->flags & FLAG_TRUE_VMP) == 0 || item->vm_image.empty()) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), "VMP not ready");
        return nullptr;
    }

    {
        std::lock_guard<std::mutex> lock(item->parse_mu);
        if (item->parsed_vm == nullptr || !item->parsed_vm->valid) {
            auto parsed = std::make_unique<Pvm2Image>();
            if (!parse_pvm2(item->vm_image.data(), item->vm_image.size(), parsed.get())
                    || !parsed->valid) {
                env->ThrowNew(env->FindClass("java/lang/RuntimeException"), "VMP bad image");
                return nullptr;
            }
            item->parsed_vm = std::move(parsed);
        }
    }
    const Pvm2Image& img = *item->parsed_vm;

    std::vector<Reg> regs(img.reg_count);
    const int arg_count = args ? env->GetArrayLength(args) : 0;
    // v2+ images reserve the last register as compiler scratch for lit lowering.
    const int scratch_reserve = (img.version >= PVM2_VERSION_V2) ? 1 : 0;
    if (static_cast<int>(img.reg_count) < static_cast<int>(img.ins_size) + scratch_reserve) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), "VMP bad frame");
        return nullptr;
    }
    int param_base = static_cast<int>(img.reg_count) - static_cast<int>(img.ins_size) - scratch_reserve;
    if (param_base < 0) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), "VMP bad frame");
        return nullptr;
    }

    // Cache boxed primitive classes (FindClass is relatively expensive per-arg).
    jclass intCls = env->FindClass("java/lang/Integer");
    jclass longCls = env->FindClass("java/lang/Long");
    jclass boolCls = env->FindClass("java/lang/Boolean");
    jclass floatCls = env->FindClass("java/lang/Float");
    jclass doubleCls = env->FindClass("java/lang/Double");
    if (intCls == nullptr || longCls == nullptr || boolCls == nullptr
            || floatCls == nullptr || doubleCls == nullptr) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), "VMP box classes");
        return nullptr;
    }

    int r = param_base;
    for (int i = 0; i < arg_count; i++) {
        if (r >= static_cast<int>(img.reg_count)) {
            clear_regs(env, regs);
            env->ThrowNew(env->FindClass("java/lang/RuntimeException"), "VMP args overflow");
            return nullptr;
        }
        jobject a = env->GetObjectArrayElement(args, i);
        if (a == nullptr) {
            regs[r].o = nullptr;
            r += 1;
            continue;
        }
        if (env->IsInstanceOf(a, intCls)) {
            unbox_arg(env, a, "I", &regs[r]);
            r += 1;
        } else if (env->IsInstanceOf(a, longCls)) {
            unbox_arg(env, a, "J", &regs[r]);
            r += 2;
        } else if (env->IsInstanceOf(a, boolCls)) {
            unbox_arg(env, a, "Z", &regs[r]);
            r += 1;
        } else if (env->IsInstanceOf(a, floatCls)) {
            unbox_arg(env, a, "F", &regs[r]);
            r += 1;
        } else if (env->IsInstanceOf(a, doubleCls)) {
            unbox_arg(env, a, "D", &regs[r]);
            r += 2;
        } else {
            regs[r].o = env->NewLocalRef(a);
            r += 1;
        }
        env->DeleteLocalRef(a);
        if (env->ExceptionCheck()) {
            clear_regs(env, regs);
            return nullptr;
        }
    }

    const uint8_t* code = img.code.data();
    size_t code_size = img.code.size();
    size_t pc = 0;
    size_t fault_pc = 0;
    jobject result = nullptr;
    bool finished = false;
    PendingResult pending;
    jobject stashed_exception = nullptr;

    while (!finished && pc < code_size) {
        fault_pc = pc;
        uint8_t wire = code[pc++];
        uint8_t op = demorph_op(img, wire);
        switch (op) {
            case OP_NOP:
                break;
            case OP_CONST: {
                if (pc + 5 > code_size) goto fail;
                uint8_t dst = code[pc++];
                int32_t imm = read_i32(code + pc);
                pc += 4;
                if (!reg_bounds(dst, regs.size())) goto fail;
                regs[dst].i = imm;
                break;
            }
            case OP_CONST_WIDE: {
                if (pc + 9 > code_size) goto fail;
                uint8_t dst = code[pc++];
                int64_t imm = read_i64(code + pc);
                pc += 8;
                if (!reg_bounds_wide(dst, regs.size())) goto fail;
                regs[dst].j = imm;
                break;
            }
            case OP_CONST_STR: {
                if (pc + 3 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint16_t idx = read_u16(code + pc);
                pc += 2;
                if (!reg_bounds(dst, regs.size()) || idx >= img.strings.size()) goto fail;
                if (regs[dst].o) env->DeleteLocalRef(regs[dst].o);
                regs[dst].o = env->NewStringUTF(img.strings[idx].c_str());
                break;
            }
            case OP_MOVE: {
                if (pc + 2 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint8_t src = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(src, regs.size())) goto fail;
                regs[dst].i = regs[src].i;
                break;
            }
            case OP_MOVE_WIDE: {
                if (pc + 2 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint8_t src = code[pc++];
                if (!reg_bounds_wide(dst, regs.size()) || !reg_bounds_wide(src, regs.size())) goto fail;
                regs[dst].j = regs[src].j;
                break;
            }
            case OP_MOVE_OBJ: {
                if (pc + 2 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint8_t src = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(src, regs.size())) goto fail;
                if (regs[dst].o) env->DeleteLocalRef(regs[dst].o);
                regs[dst].o = regs[src].o ? env->NewLocalRef(regs[src].o) : nullptr;
                break;
            }
            case OP_GOTO: {
                if (pc + 2 > code_size) goto fail;
                int16_t rel = read_i16(code + pc);
                pc += 2;
                pc = static_cast<size_t>(static_cast<ptrdiff_t>(pc) + rel);
                break;
            }
            case OP_IF_CMP: {
                if (pc + 5 > code_size) goto fail;
                uint8_t cond = code[pc++];
                uint8_t a = code[pc++];
                uint8_t b = code[pc++];
                int16_t rel = read_i16(code + pc);
                pc += 2;
                if (!reg_bounds(a, regs.size()) || !reg_bounds(b, regs.size())) goto fail;
                if (cmp_i32(cond, regs[a].i, regs[b].i)) {
                    pc = static_cast<size_t>(static_cast<ptrdiff_t>(pc) + rel);
                }
                break;
            }
            case OP_IF_Z: {
                if (pc + 4 > code_size) goto fail;
                uint8_t cond = code[pc++];
                uint8_t a = code[pc++];
                int16_t rel = read_i16(code + pc);
                pc += 2;
                if (!reg_bounds(a, regs.size())) goto fail;
                if (cmp_i32(cond, regs[a].i, 0)) {
                    pc = static_cast<size_t>(static_cast<ptrdiff_t>(pc) + rel);
                }
                break;
            }
            case OP_RETURN_VOID:
                finished = true;
                result = nullptr;
                break;
            case OP_RETURN: {
                if (pc + 1 > code_size) goto fail;
                uint8_t src = code[pc++];
                if (!reg_bounds(src, regs.size())) goto fail;
                if (img.ret_kind == RET_Z) {
                    result = box_bool(env, regs[src].i != 0);
                } else if (img.ret_kind == RET_F) {
                    jfloat f;
                    memcpy(&f, &regs[src].i, sizeof(f));
                    result = box_float(env, f);
                } else {
                    result = box_int(env, regs[src].i);
                }
                finished = true;
                break;
            }
            case OP_RETURN_WIDE: {
                if (pc + 1 > code_size) goto fail;
                uint8_t src = code[pc++];
                if (!reg_bounds_wide(src, regs.size())) goto fail;
                if (img.ret_kind == RET_D) {
                    jdouble d;
                    memcpy(&d, &regs[src].j, sizeof(d));
                    result = box_double(env, d);
                } else {
                    result = box_long(env, regs[src].j);
                }
                finished = true;
                break;
            }
            case OP_RETURN_OBJ: {
                if (pc + 1 > code_size) goto fail;
                uint8_t src = code[pc++];
                if (!reg_bounds(src, regs.size())) goto fail;
                result = regs[src].o ? env->NewLocalRef(regs[src].o) : nullptr;
                finished = true;
                break;
            }
            case OP_BINOP: {
                if (pc + 4 > code_size) goto fail;
                uint8_t bin = code[pc++];
                uint8_t dst = code[pc++];
                uint8_t b = code[pc++];
                uint8_t c = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(b, regs.size()) ||
                    !reg_bounds(c, regs.size())) {
                    goto fail;
                }
                int32_t out = 0;
                if (!binop_i32(env, bin, regs[b].i, regs[c].i, &out)) {
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_pending(env, pending);
                    clear_regs(env, regs);
                    if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                    return nullptr;
                }
                regs[dst].i = out;
                break;
            }
            case OP_BINOP_2ADDR: {
                if (pc + 3 > code_size) goto fail;
                uint8_t bin = code[pc++];
                uint8_t dst = code[pc++];
                uint8_t src = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(src, regs.size())) goto fail;
                int32_t out = 0;
                if (!binop_i32(env, bin, regs[dst].i, regs[src].i, &out)) {
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_pending(env, pending);
                    clear_regs(env, regs);
                    if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                    return nullptr;
                }
                regs[dst].i = out;
                break;
            }
            case OP_BINOP_WIDE: {
                if (pc + 4 > code_size) goto fail;
                uint8_t bin = code[pc++];
                uint8_t dst = code[pc++];
                uint8_t b = code[pc++];
                uint8_t c = code[pc++];
                // Dalvik shl/shr/ushr-long take a 32-bit shift count (narrow reg).
                const bool shift = is_shift_binop(bin);
                if (!reg_bounds_wide(dst, regs.size()) || !reg_bounds_wide(b, regs.size())) {
                    goto fail;
                }
                if (shift ? !reg_bounds(c, regs.size()) : !reg_bounds_wide(c, regs.size())) {
                    goto fail;
                }
                int64_t out = 0;
                int64_t rhs = shift ? static_cast<int64_t>(regs[c].i) : regs[c].j;
                if (!binop_i64(env, bin, regs[b].j, rhs, &out)) {
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_pending(env, pending);
                    clear_regs(env, regs);
                    if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                    return nullptr;
                }
                regs[dst].j = out;
                break;
            }
            case OP_BINOP_2ADDR_WIDE: {
                if (pc + 3 > code_size) goto fail;
                uint8_t bin = code[pc++];
                uint8_t dst = code[pc++];
                uint8_t src = code[pc++];
                const bool shift = is_shift_binop(bin);
                if (!reg_bounds_wide(dst, regs.size())) {
                    goto fail;
                }
                if (shift ? !reg_bounds(src, regs.size()) : !reg_bounds_wide(src, regs.size())) {
                    goto fail;
                }
                int64_t out = 0;
                int64_t rhs = shift ? static_cast<int64_t>(regs[src].i) : regs[src].j;
                if (!binop_i64(env, bin, regs[dst].j, rhs, &out)) {
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_pending(env, pending);
                    clear_regs(env, regs);
                    if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                    return nullptr;
                }
                regs[dst].j = out;
                break;
            }
            case OP_BINOP_FLOAT: {
                if (pc + 4 > code_size) goto fail;
                uint8_t bin = code[pc++];
                uint8_t dst = code[pc++];
                uint8_t b = code[pc++];
                uint8_t c = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(b, regs.size()) ||
                    !reg_bounds(c, regs.size())) {
                    goto fail;
                }
                regs[dst].i = float_bits(binop_f32(bin, as_float(regs[b].i), as_float(regs[c].i)));
                break;
            }
            case OP_BINOP_2ADDR_FLOAT: {
                if (pc + 3 > code_size) goto fail;
                uint8_t bin = code[pc++];
                uint8_t dst = code[pc++];
                uint8_t src = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(src, regs.size())) goto fail;
                regs[dst].i = float_bits(
                        binop_f32(bin, as_float(regs[dst].i), as_float(regs[src].i)));
                break;
            }
            case OP_BINOP_DOUBLE: {
                if (pc + 4 > code_size) goto fail;
                uint8_t bin = code[pc++];
                uint8_t dst = code[pc++];
                uint8_t b = code[pc++];
                uint8_t c = code[pc++];
                if (!reg_bounds_wide(dst, regs.size()) || !reg_bounds_wide(b, regs.size()) ||
                    !reg_bounds_wide(c, regs.size())) {
                    goto fail;
                }
                regs[dst].j = double_bits(
                        binop_f64(bin, as_double(regs[b].j), as_double(regs[c].j)));
                break;
            }
            case OP_BINOP_2ADDR_DOUBLE: {
                if (pc + 3 > code_size) goto fail;
                uint8_t bin = code[pc++];
                uint8_t dst = code[pc++];
                uint8_t src = code[pc++];
                if (!reg_bounds_wide(dst, regs.size()) || !reg_bounds_wide(src, regs.size())) {
                    goto fail;
                }
                regs[dst].j = double_bits(
                        binop_f64(bin, as_double(regs[dst].j), as_double(regs[src].j)));
                break;
            }
            case OP_UNOP: {
                if (pc + 3 > code_size) goto fail;
                uint8_t kind = code[pc++];
                uint8_t dst = code[pc++];
                uint8_t src = code[pc++];
                bool wide_src = (kind == UN_NEG_LONG || kind == UN_NOT_LONG
                        || kind == UN_LONG_TO_INT || kind == UN_LONG_TO_FLOAT
                        || kind == UN_LONG_TO_DOUBLE || kind == UN_NEG_DOUBLE
                        || kind == UN_DOUBLE_TO_INT || kind == UN_DOUBLE_TO_LONG
                        || kind == UN_DOUBLE_TO_FLOAT);
                bool wide_dst = (kind == UN_NEG_LONG || kind == UN_NOT_LONG
                        || kind == UN_INT_TO_LONG || kind == UN_INT_TO_DOUBLE
                        || kind == UN_LONG_TO_DOUBLE || kind == UN_FLOAT_TO_LONG
                        || kind == UN_FLOAT_TO_DOUBLE || kind == UN_NEG_DOUBLE
                        || kind == UN_DOUBLE_TO_LONG);
                if (wide_dst ? !reg_bounds_wide(dst, regs.size()) : !reg_bounds(dst, regs.size())) {
                    goto fail;
                }
                if (wide_src ? !reg_bounds_wide(src, regs.size()) : !reg_bounds(src, regs.size())) {
                    goto fail;
                }
                if (!apply_unop(kind, &regs[dst], regs[src])) goto fail;
                break;
            }
            case OP_CMP: {
                if (pc + 4 > code_size) goto fail;
                uint8_t kind = code[pc++];
                uint8_t dst = code[pc++];
                uint8_t b = code[pc++];
                uint8_t c = code[pc++];
                if (!reg_bounds(dst, regs.size())) goto fail;
                switch (kind) {
                    case CMP_FLOAT_L:
                    case CMP_FLOAT_G:
                        if (!reg_bounds(b, regs.size()) || !reg_bounds(c, regs.size())) goto fail;
                        regs[dst].i = cmp_float(as_float(regs[b].i), as_float(regs[c].i),
                                                kind == CMP_FLOAT_G);
                        break;
                    case CMP_DOUBLE_L:
                    case CMP_DOUBLE_G:
                        if (!reg_bounds_wide(b, regs.size()) || !reg_bounds_wide(c, regs.size())) {
                            goto fail;
                        }
                        regs[dst].i = cmp_double(as_double(regs[b].j), as_double(regs[c].j),
                                                 kind == CMP_DOUBLE_G);
                        break;
                    case CMP_LONG:
                        if (!reg_bounds_wide(b, regs.size()) || !reg_bounds_wide(c, regs.size())) {
                            goto fail;
                        }
                        regs[dst].i = cmp_long(regs[b].j, regs[c].j);
                        break;
                    default:
                        goto fail;
                }
                break;
            }
            case OP_MONITOR_ENTER: {
                if (pc + 1 > code_size) goto fail;
                uint8_t obj = code[pc++];
                if (!reg_bounds(obj, regs.size()) || regs[obj].o == nullptr) {
                    env->ThrowNew(env->FindClass("java/lang/NullPointerException"),
                                  "monitor-enter on null");
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_pending(env, pending);
                    clear_regs(env, regs);
                    if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                    return nullptr;
                }
                if (env->MonitorEnter(regs[obj].o) != 0) {
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_pending(env, pending);
                    clear_regs(env, regs);
                    if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                    return nullptr;
                }
                break;
            }
            case OP_MONITOR_EXIT: {
                if (pc + 1 > code_size) goto fail;
                uint8_t obj = code[pc++];
                if (!reg_bounds(obj, regs.size()) || regs[obj].o == nullptr) {
                    env->ThrowNew(env->FindClass("java/lang/NullPointerException"),
                                  "monitor-exit on null");
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_pending(env, pending);
                    clear_regs(env, regs);
                    if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                    return nullptr;
                }
                if (env->MonitorExit(regs[obj].o) != 0) {
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_pending(env, pending);
                    clear_regs(env, regs);
                    if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                    return nullptr;
                }
                break;
            }
            case OP_INVOKE_STATIC:
            case OP_INVOKE_VIRTUAL:
            case OP_INVOKE_DIRECT:
            case OP_INVOKE_INTERFACE:
            case OP_INVOKE_SUPER: {
                if (pc + 3 > code_size) goto fail;
                uint16_t mid = read_u16(code + pc);
                pc += 2;
                uint8_t argc = code[pc++];
                if (pc + argc > code_size) goto fail;
                if (mid >= img.methods.size()) goto fail;
                const uint8_t* arg_regs = code + pc;
                pc += argc;
                if (!invoke_method(env, op, img.methods[mid], arg_regs, argc, regs, pending)) {
                    if (env->ExceptionCheck()) {
                        if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                            break;
                        }
                        clear_pending(env, pending);
                        clear_regs(env, regs);
                        if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                        return nullptr;
                    }
                    goto fail;
                }
                break;
            }
            case OP_MOVE_RESULT: {
                if (pc + 1 > code_size) goto fail;
                uint8_t dst = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !pending.valid) goto fail;
                regs[dst].i = pending.i;
                clear_pending(env, pending);
                break;
            }
            case OP_MOVE_RESULT_WIDE: {
                if (pc + 1 > code_size) goto fail;
                uint8_t dst = code[pc++];
                if (!reg_bounds_wide(dst, regs.size()) || !pending.valid) goto fail;
                regs[dst].j = pending.j;
                clear_pending(env, pending);
                break;
            }
            case OP_MOVE_RESULT_OBJ: {
                if (pc + 1 > code_size) goto fail;
                uint8_t dst = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !pending.valid) goto fail;
                if (regs[dst].o) env->DeleteLocalRef(regs[dst].o);
                // Transfer ownership of pending local ref — do not NewLocalRef+leak.
                regs[dst].o = pending.o;
                pending.o = nullptr;
                pending.valid = false;
                break;
            }
            case OP_SGET: {
                if (pc + 4 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint16_t fid = read_u16(code + pc);
                pc += 2;
                uint8_t kind = code[pc++];
                if (!reg_bounds(dst, regs.size()) || fid >= img.fields.size()) goto fail;
                if (!get_static_field(env, img.fields[fid], kind, &regs[dst])) {
                    if (env->ExceptionCheck()) {
                        if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                            break;
                        }
                        clear_regs(env, regs);
                        if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                        return nullptr;
                    }
                    goto fail;
                }
                break;
            }
            case OP_SPUT: {
                if (pc + 4 > code_size) goto fail;
                uint8_t src = code[pc++];
                uint16_t fid = read_u16(code + pc);
                pc += 2;
                uint8_t kind = code[pc++];
                if (!reg_bounds(src, regs.size()) || fid >= img.fields.size()) goto fail;
                if (!put_static_field(env, img.fields[fid], kind, regs[src])) {
                    if (env->ExceptionCheck()) {
                        if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                            break;
                        }
                        clear_regs(env, regs);
                        if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                        return nullptr;
                    }
                    goto fail;
                }
                break;
            }
            case OP_IGET: {
                if (pc + 5 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint8_t obj = code[pc++];
                uint16_t fid = read_u16(code + pc);
                pc += 2;
                uint8_t kind = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(obj, regs.size()) ||
                    fid >= img.fields.size()) {
                    goto fail;
                }
                if (!get_instance_field(env, img.fields[fid], kind, regs[obj].o, &regs[dst])) {
                    if (env->ExceptionCheck()) {
                        if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                            break;
                        }
                        clear_regs(env, regs);
                        if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                        return nullptr;
                    }
                    goto fail;
                }
                break;
            }
            case OP_IPUT: {
                if (pc + 5 > code_size) goto fail;
                uint8_t src = code[pc++];
                uint8_t obj = code[pc++];
                uint16_t fid = read_u16(code + pc);
                pc += 2;
                uint8_t kind = code[pc++];
                if (!reg_bounds(src, regs.size()) || !reg_bounds(obj, regs.size()) ||
                    fid >= img.fields.size()) {
                    goto fail;
                }
                if (!put_instance_field(env, img.fields[fid], kind, regs[obj].o, regs[src])) {
                    if (env->ExceptionCheck()) {
                        if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                            break;
                        }
                        clear_regs(env, regs);
                        if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                        return nullptr;
                    }
                    goto fail;
                }
                break;
            }
            case OP_NEW_INSTANCE: {
                if (pc + 3 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint16_t tid = read_u16(code + pc);
                pc += 2;
                if (!reg_bounds(dst, regs.size()) || tid >= img.types.size()) goto fail;
                jclass cls = find_class_desc(env, img.types[tid]);
                if (cls == nullptr) goto fail;
                if (regs[dst].o) env->DeleteLocalRef(regs[dst].o);
                regs[dst].o = env->AllocObject(cls);
                if (env->ExceptionCheck()) {
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_regs(env, regs);
                    if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                    return nullptr;
                }
                break;
            }
            case OP_NEW_ARRAY: {
                if (pc + 4 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint8_t size_reg = code[pc++];
                uint16_t tid = read_u16(code + pc);
                pc += 2;
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(size_reg, regs.size()) ||
                    tid >= img.types.size()) {
                    goto fail;
                }
                jsize len = regs[size_reg].i;
                if (regs[dst].o) env->DeleteLocalRef(regs[dst].o);
                regs[dst].o = new_array_for_type(env, img.types[tid], len);
                if (env->ExceptionCheck()) {
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_regs(env, regs);
                    if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                    return nullptr;
                }
                break;
            }
            case OP_FILLED_NEW_ARRAY: {
                if (pc + 3 > code_size) goto fail;
                uint16_t tid = read_u16(code + pc);
                pc += 2;
                uint8_t argc = code[pc++];
                if (pc + argc > code_size) goto fail;
                if (tid >= img.types.size()) goto fail;
                const uint8_t* arg_regs = code + pc;
                pc += argc;
                if (!filled_new_array(env, img.types[tid], arg_regs, argc, regs, pending)) {
                    if (env->ExceptionCheck()) {
                        if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                            break;
                        }
                        clear_pending(env, pending);
                        clear_regs(env, regs);
                        if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                        return nullptr;
                    }
                    goto fail;
                }
                break;
            }
            case OP_ARRAY_LENGTH: {
                if (pc + 2 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint8_t arr = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(arr, regs.size())) goto fail;
                regs[dst].i = env->GetArrayLength(static_cast<jarray>(regs[arr].o));
                if (env->ExceptionCheck()) {
                    if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                        break;
                    }
                    clear_regs(env, regs);
                    if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                    return nullptr;
                }
                break;
            }
            case OP_AGET: {
                if (pc + 4 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint8_t arr = code[pc++];
                uint8_t idx = code[pc++];
                uint8_t kind = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(arr, regs.size()) ||
                    !reg_bounds(idx, regs.size())) {
                    goto fail;
                }
                if (!aget(env, static_cast<jarray>(regs[arr].o), regs[idx].i, kind, &regs[dst])) {
                    if (env->ExceptionCheck()) {
                        if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                            break;
                        }
                        clear_regs(env, regs);
                        if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                        return nullptr;
                    }
                    goto fail;
                }
                break;
            }
            case OP_APUT: {
                if (pc + 4 > code_size) goto fail;
                uint8_t src = code[pc++];
                uint8_t arr = code[pc++];
                uint8_t idx = code[pc++];
                uint8_t kind = code[pc++];
                if (!reg_bounds(src, regs.size()) || !reg_bounds(arr, regs.size()) ||
                    !reg_bounds(idx, regs.size())) {
                    goto fail;
                }
                if (!aput(env, static_cast<jarray>(regs[arr].o), regs[idx].i, kind, regs[src])) {
                    if (env->ExceptionCheck()) {
                        if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                            break;
                        }
                        clear_regs(env, regs);
                        if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                        return nullptr;
                    }
                    goto fail;
                }
                break;
            }
            case OP_CHECK_CAST: {
                if (pc + 3 > code_size) goto fail;
                uint8_t obj = code[pc++];
                uint16_t tid = read_u16(code + pc);
                pc += 2;
                if (!reg_bounds(obj, regs.size()) || tid >= img.types.size()) goto fail;
                if (regs[obj].o != nullptr) {
                    jclass cls = find_class_desc(env, img.types[tid]);
                    if (cls == nullptr) goto fail;
                    if (!env->IsInstanceOf(regs[obj].o, cls)) {
                        env->ThrowNew(env->FindClass("java/lang/ClassCastException"),
                                      "PVM2 check-cast");
                        if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                            break;
                        }
                        clear_regs(env, regs);
                        if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                        return nullptr;
                    }
                }
                break;
            }
            case OP_INSTANCE_OF: {
                if (pc + 4 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint8_t obj = code[pc++];
                uint16_t tid = read_u16(code + pc);
                pc += 2;
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(obj, regs.size()) ||
                    tid >= img.types.size()) {
                    goto fail;
                }
                if (regs[obj].o == nullptr) {
                    regs[dst].i = 0;
                } else {
                    jclass cls = find_class_desc(env, img.types[tid]);
                    if (cls == nullptr) goto fail;
                    regs[dst].i = env->IsInstanceOf(regs[obj].o, cls) ? 1 : 0;
                }
                break;
            }
            case OP_THROW: {
                if (pc + 1 > code_size) goto fail;
                uint8_t src = code[pc++];
                if (!reg_bounds(src, regs.size()) || regs[src].o == nullptr) goto fail;
                env->Throw(static_cast<jthrowable>(regs[src].o));
                if (dispatch_exception(env, img, fault_pc, &pc, &stashed_exception)) {
                    break;
                }
                clear_regs(env, regs);
                if (stashed_exception) env->DeleteLocalRef(stashed_exception);
                return nullptr;
            }
            case OP_MOVE_EXCEPTION: {
                if (pc + 1 > code_size) goto fail;
                uint8_t dst = code[pc++];
                if (!reg_bounds(dst, regs.size()) || stashed_exception == nullptr) goto fail;
                if (regs[dst].o) env->DeleteLocalRef(regs[dst].o);
                regs[dst].o = env->NewLocalRef(stashed_exception);
                env->DeleteLocalRef(stashed_exception);
                stashed_exception = nullptr;
                break;
            }
            case OP_CONST_CLASS: {
                if (pc + 3 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint16_t tid = read_u16(code + pc);
                pc += 2;
                if (!reg_bounds(dst, regs.size()) || tid >= img.types.size()) goto fail;
                jclass cls = find_class_desc(env, img.types[tid]);
                if (cls == nullptr) goto fail;
                if (regs[dst].o) env->DeleteLocalRef(regs[dst].o);
                regs[dst].o = env->NewLocalRef(cls);
                break;
            }
            case OP_NEG: {
                if (pc + 2 > code_size) goto fail;
                uint8_t dst = code[pc++];
                uint8_t src = code[pc++];
                if (!reg_bounds(dst, regs.size()) || !reg_bounds(src, regs.size())) goto fail;
                regs[dst].i = -regs[src].i;
                break;
            }
            default:
                PLOGE("PVM2 unknown op 0x%02x pc=%zu", op, fault_pc);
                goto fail;
        }
    }

    clear_pending(env, pending);
    clear_regs(env, regs);
    if (stashed_exception) env->DeleteLocalRef(stashed_exception);
    if (!finished) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), "VMP fell off end");
        return nullptr;
    }
    return result;

fail:
    clear_pending(env, pending);
    clear_regs(env, regs);
    if (stashed_exception) env->DeleteLocalRef(stashed_exception);
    if (!env->ExceptionCheck()) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), "VMP interpret error");
    }
    return nullptr;
}

/** Multi-ISA entry points (separate .bitcode symbols) — Phase 3. */
PROTECTOR_ENCRYPT static jobject pvm2_run_a(JNIEnv* env, int dex_index, uint32_t method_idx,
                                            jobjectArray args) {
    return interpret_body(env, dex_index, method_idx, args);
}

PROTECTOR_ENCRYPT static jobject pvm2_run_b(JNIEnv* env, int dex_index, uint32_t method_idx,
                                            jobjectArray args) {
    return interpret_body(env, dex_index, method_idx, args);
}

PROTECTOR_ENCRYPT static jobject pvm2_run_c(JNIEnv* env, int dex_index, uint32_t method_idx,
                                            jobjectArray args) {
    return interpret_body(env, dex_index, method_idx, args);
}

static uint8_t peek_isa_id(const std::vector<uint8_t>& image) {
    if (image.size() < 16) {
        return 0;
    }
    uint16_t ver = static_cast<uint16_t>(image[4] | (image[5] << 8));
    if (ver < PVM2_VERSION_V3) {
        return 0;
    }
    return image[15];
}

PROTECTOR_ENCRYPT jobject interpret(JNIEnv* env, int dex_index, uint32_t method_idx,
                                    jobjectArray args) {
    if (!risk::vmp_allowed()) {
        env->ThrowNew(env->FindClass("java/lang/SecurityException"), "VMP refused by RASP");
        return nullptr;
    }
    auto& state = runtime_state();
    auto dex_it = state.code_map.find(dex_index);
    if (dex_it == state.code_map.end()) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), "VMP bad dex");
        return nullptr;
    }
    auto m_it = dex_it->second.find(method_idx);
    if (m_it == dex_it->second.end() || m_it->second == nullptr || m_it->second->vm_image.empty()) {
        env->ThrowNew(env->FindClass("java/lang/RuntimeException"), "VMP bad method");
        return nullptr;
    }
    uint8_t isa = peek_isa_id(m_it->second->vm_image);
    switch (isa % PVM2_ISA_COUNT) {
        case 1:
            return pvm2_run_b(env, dex_index, method_idx, args);
        case 2:
            return pvm2_run_c(env, dex_index, method_idx, args);
        default:
            return pvm2_run_a(env, dex_index, method_idx, args);
    }
}

} // namespace protector::vm
