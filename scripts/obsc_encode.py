#!/usr/bin/env python3
"""Phase 4 — encode plaintext to rolling-XOR OBSC / StrEnc literals.

Must match native OBSC_ROLL and Java StrEnc.roll:
  roll(i) = 0x5A ^ ((i * 0x1B) & 0xFF)

Usage:
  python scripts/obsc_encode.py "frida"
  python scripts/obsc_encode.py --java "protector/config.json"
  python scripts/obsc_encode.py --batch scripts/obsc_strings.txt
"""
from __future__ import annotations

import argparse
import sys


def roll(i: int) -> int:
    return (0x5A ^ ((i * 0x1B) & 0xFF)) & 0xFF


def encode(plain: str) -> bytes:
    data = plain.encode("utf-8")
    return bytes((b ^ roll(i)) & 0xFF for i, b in enumerate(data))


def to_c(plain: str) -> str:
    enc = encode(plain)
    return '"' + "".join(f"\\x{b:02x}" for b in enc) + '"'


def to_java(plain: str) -> str:
    enc = encode(plain)
    parts = []
    for b in enc:
        if b > 127:
            parts.append(f"(byte)0x{b:02x}")
        else:
            parts.append(f"0x{b:02x}")
    return "{" + ", ".join(parts) + "}"


def main() -> int:
    ap = argparse.ArgumentParser(description="Rolling-XOR string encoder for protector")
    ap.add_argument("text", nargs="?", help="plaintext to encode")
    ap.add_argument("--java", action="store_true", help="emit Java byte[] initializer")
    ap.add_argument("--batch", metavar="FILE", help="one plaintext per line (# comments ok)")
    args = ap.parse_args()

    lines: list[str] = []
    if args.batch:
        with open(args.batch, "r", encoding="utf-8") as f:
            for line in f:
                t = line.strip()
                if not t or t.startswith("#"):
                    continue
                lines.append(t)
    elif args.text is not None:
        lines.append(args.text)
    else:
        ap.print_help()
        return 2

    for plain in lines:
        lit = to_java(plain) if args.java else to_c(plain)
        print(f"{plain!r} -> {lit}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
