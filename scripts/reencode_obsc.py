#!/usr/bin/env python3
"""Re-encode OBSC_DECODE / StrEnc literals to rolling XOR (Phase 4)."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def roll(i: int) -> int:
    return (0x5A ^ ((i * 0x1B) & 0xFF)) & 0xFF


def enc_bytes(plain: str) -> bytes:
    data = plain.encode("utf-8")
    return bytes((b ^ roll(i)) & 0xFF for i, b in enumerate(data))


def to_c(plain: str) -> str:
    return '"' + "".join(f"\\x{b:02x}" for b in enc_bytes(plain)) + '"'


def to_java_arr(plain: str) -> str:
    parts = []
    for b in enc_bytes(plain):
        if b > 127:
            parts.append(f"(byte)0x{b:02x}")
        else:
            parts.append(f"0x{b:02x}")
    return "{" + ", ".join(parts) + "}"


def fixed_xor_c(plain: str) -> str:
    """Old fixed-0x5A encoding as it appears in source."""
    data = plain.encode("utf-8")
    return '"' + "".join(f"\\x{(b ^ 0x5A):02x}" for b in data) + '"'


def patch_risk_cpp() -> None:
    path = ROOT / "native/src/main/cpp/risk/risk.cpp"
    text = path.read_text(encoding="utf-8")
    plains = [
        "frida",
        "linjector",
        "gum-js",
        "frida-agent",
        "gum-js-loop",
        "pool-frida",
        "xposed",
        "XposedBridge",
        "lsposed",
        "LSPosed",
        "edxposed",
        "EdXposed",
        "/system/bin/su",
        "/sbin/magisk",
        "/data/adb/magisk",
        "/data/adb/modules",
        "/dev/socket/qemud",
        "/dev/qemu_pipe",
    ]
    for plain in plains:
        old = fixed_xor_c(plain)
        new = to_c(plain)
        if old not in text:
            raise SystemExit(f"risk.cpp missing old literal for {plain!r}: {old}")
        text = text.replace(f"OBSC_DECODE({old})", f"OBSC_DECODE({new})")
    path.write_text(text, encoding="utf-8")
    print(f"patched {path}")


def patch_java_file(rel: str, plains: list[str]) -> None:
    path = ROOT / rel
    text = path.read_text(encoding="utf-8")
    for plain in plains:
        old_bytes = bytes(b ^ 0x5A for b in plain.encode("utf-8"))
        # Build possible old Java forms (with/without (byte) casts)
        old_parts = []
        for b in old_bytes:
            if b > 127:
                old_parts.append(f"(byte)0x{b:02x}")
            else:
                old_parts.append(f"0x{b:02x}")
        old_arr = "{" + ", ".join(old_parts) + "}"
        # Also allow multiline: "0x2a, 0x28," style already in file as contiguous
        new_arr = to_java_arr(plain)
        if old_arr not in text:
            # try without (byte) casts
            old_parts2 = [f"0x{b:02x}" for b in old_bytes]
            old_arr2 = "{" + ", ".join(old_parts2) + "}"
            if old_arr2 in text:
                text = text.replace(old_arr2, new_arr)
                continue
            raise SystemExit(f"{rel} missing old bytes for {plain!r}: {old_arr}")
        text = text.replace(old_arr, new_arr)
    path.write_text(text, encoding="utf-8")
    print(f"patched {path}")


def main() -> None:
    patch_risk_cpp()
    patch_java_file(
        "native/src/main/java/com/yqsh/protector/shell/ProxyApplication.java",
        [
            "protector.ProxyApp",
            "protector/dexes.zip",
            "protector/code.bin",
            "protector/config.json",
            "protector/sokeys.bin",
            "protector",
            "code.bin",
            "dexes.zip",
            "config.json",
            "sokeys.bin",
            "protector/netguard.json",
            "netguard.json",
        ],
    )
    # ProxyComponentFactory uses inline StrEnc.d(new byte[]{...})
    path = ROOT / "native/src/main/java/com/yqsh/protector/shell/ProxyComponentFactory.java"
    text = path.read_text(encoding="utf-8")
    for plain in [
        "protector",
        "dexes.zip",
        "code.bin",
        "config.json",
        "sokeys.bin",
        "netguard.json",
    ]:
        old_bytes = bytes(b ^ 0x5A for b in plain.encode("utf-8"))
        old_parts = []
        for b in old_bytes:
            if b > 127:
                old_parts.append(f"(byte)0x{b:02x}")
            else:
                old_parts.append(f"0x{b:02x}")
        old_arr = "{" + ", ".join(old_parts) + "}"
        new_arr = to_java_arr(plain)
        if old_arr not in text:
            old_arr2 = "{" + ", ".join(f"0x{b:02x}" for b in old_bytes) + "}"
            if old_arr2 in text:
                text = text.replace(old_arr2, new_arr)
                continue
            raise SystemExit(f"ProxyComponentFactory missing {plain!r}")
        text = text.replace(old_arr, new_arr)
    path.write_text(text, encoding="utf-8")
    print(f"patched {path}")

    # DexMerger
    dm = ROOT / "native/src/main/java/com/yqsh/protector/shell/DexMerger.java"
    text = dm.read_text(encoding="utf-8")
    plain = "dexes.zip"
    old_bytes = bytes(b ^ 0x5A for b in plain.encode("utf-8"))
    old_arr = "{" + ", ".join(f"0x{b:02x}" for b in old_bytes) + "}"
    new_arr = to_java_arr(plain)
    if old_arr not in text:
        raise SystemExit("DexMerger missing dexes.zip")
    dm.write_text(text.replace(old_arr, new_arr), encoding="utf-8")
    print(f"patched {dm}")


if __name__ == "__main__":
    main()
