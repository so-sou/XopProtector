#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace protector::report {

/** Optional sink: called with one JSON line (no trailing newline required). */
using ThreatSink = void (*)(const char* json_line, void* user);
void set_threat_sink(ThreatSink sink, void* user);

/** Directory for threats.log / crash_reason.txt (usually code_cache/protector). Empty = memory only. */
void set_report_dir(const std::string& dir);

/** Master switch from config.json report_enabled (default true). */
void set_report_enabled(bool enabled);

/**
 * Record a threat event (also appends to threats.log when dir is set).
 * Safe to call from risk thread / handle_risk.
 * Phase 5 JSON: ts, reason, rasp_action, pid, sdk.
 */
void report_threat(const char* reason, int rasp_action);

/**
 * Write a last-breath crash reason under the report dir before RASP kill paths.
 * Best-effort; must not allocate heavily or throw.
 */
void write_crash_reason(const char* reason, const char* kind);

/**
 * Drain in-memory ring buffer as a JSON array string.
 * Cleared after drain. Returns "[]" if empty.
 */
std::string drain_threats_json();

} // namespace protector::report
