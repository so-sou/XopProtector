#include "report/threat_report.h"
#include "common/log.h"

#include <android/api-level.h>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <mutex>
#include <string>
#include <unistd.h>

namespace protector::report {

static constexpr int kRingCap = 32;
static constexpr int kReasonMax = 64;

struct ThreatEvent {
    char reason[kReasonMax];
    int rasp_action;
    int64_t unix_sec;
    int pid;
    int sdk;
};

static std::mutex g_mu;
static ThreatEvent g_ring[kRingCap];
static int g_ring_count = 0;
static int g_ring_next = 0;
static std::string g_dir;
static std::atomic_bool g_enabled{true};
static ThreatSink g_sink = nullptr;
static void* g_sink_user = nullptr;

void set_threat_sink(ThreatSink sink, void* user) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_sink = sink;
    g_sink_user = user;
}

void set_report_dir(const std::string& dir) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_dir = dir;
}

void set_report_enabled(bool enabled) {
    g_enabled.store(enabled, std::memory_order_relaxed);
}

static void append_file_line(const char* json) {
    if (g_dir.empty() || json == nullptr) return;
    std::string path = g_dir + "/threats.log";
    FILE* fp = fopen(path.c_str(), "a");
    if (!fp) return;
    fputs(json, fp);
    fputc('\n', fp);
    fclose(fp);
}

static std::string make_json(const ThreatEvent& e) {
    char buf[256];
    // Controlled fields only — reason sanitized to [A-Za-z0-9_].
    snprintf(buf, sizeof(buf),
             "{\"ts\":%lld,\"reason\":\"%s\",\"rasp_action\":%d,\"pid\":%d,\"sdk\":%d}",
             static_cast<long long>(e.unix_sec), e.reason, e.rasp_action, e.pid, e.sdk);
    return std::string(buf);
}

void report_threat(const char* reason, int rasp_action) {
    if (!g_enabled.load(std::memory_order_relaxed)) return;
    ThreatEvent e{};
    e.rasp_action = rasp_action;
    e.unix_sec = static_cast<int64_t>(time(nullptr));
    e.pid = static_cast<int>(getpid());
    e.sdk = android_get_device_api_level();
    if (reason == nullptr) reason = "unknown";
    strncpy(e.reason, reason, kReasonMax - 1);
    e.reason[kReasonMax - 1] = 0;
    for (char* p = e.reason; *p; ++p) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
              || (c >= '0' && c <= '9') || c == '_')) {
            *p = '_';
        }
    }

    std::string json;
    ThreatSink sink = nullptr;
    void* user = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        g_ring[g_ring_next] = e;
        g_ring_next = (g_ring_next + 1) % kRingCap;
        if (g_ring_count < kRingCap) g_ring_count++;
        json = make_json(e);
        append_file_line(json.c_str());
        sink = g_sink;
        user = g_sink_user;
    }
    PLOGI("threat report: %s", json.c_str());
    if (sink) {
        sink(json.c_str(), user);
    }
}

void write_crash_reason(const char* reason, const char* kind) {
    std::string dir;
    {
        std::lock_guard<std::mutex> lock(g_mu);
        dir = g_dir;
    }
    if (dir.empty()) return;
    std::string path = dir + "/crash_reason.txt";
    FILE* fp = fopen(path.c_str(), "w");
    if (!fp) return;
    const char* r = reason != nullptr ? reason : "unknown";
    const char* k = kind != nullptr ? kind : "crash";
    fprintf(fp, "ts=%lld\npid=%d\nkind=%s\nreason=%s\nsdk=%d\n",
            static_cast<long long>(time(nullptr)),
            static_cast<int>(getpid()),
            k, r, android_get_device_api_level());
    fclose(fp);
}

std::string drain_threats_json() {
    std::lock_guard<std::mutex> lock(g_mu);
    if (g_ring_count == 0) return "[]";
    std::string out = "[";
    int start = (g_ring_next - g_ring_count + kRingCap) % kRingCap;
    for (int i = 0; i < g_ring_count; i++) {
        if (i) out += ',';
        out += make_json(g_ring[(start + i) % kRingCap]);
    }
    out += ']';
    g_ring_count = 0;
    g_ring_next = 0;
    return out;
}

} // namespace protector::report
