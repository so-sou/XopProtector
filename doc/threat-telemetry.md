# Phase 5 — Threat telemetry + crash breadcrumb

**Status:** done.

## Threat JSON (ring + `threats.log`)

```json
{"ts":1710000000,"reason":"frida_maps","rasp_action":2,"pid":1234,"sdk":30}
```

Drain via `JniBridge.drainThreatReports()` → JSON array.

## Crash breadcrumb

Before RASP Block kill paths, writes `crash_reason.txt` under the protector cache:

```
ts=...
pid=...
kind=sigill|sigsegv|abort|hang|exit
reason=...
sdk=...
```

## Java

`CrashGuard.install()` chains `UncaughtExceptionHandler` and soft-reports `uncaught_<ExceptionName>`.
