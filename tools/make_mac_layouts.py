#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Sven Würth
# SPDX-License-Identifier: MIT
"""Create macOS variants of the BadUSB keyboard layouts (.kl) for VaultFlipper.

A .kl file is an array of 128 uint16 (little endian), indexed by ASCII code:
low byte = HID keycode, high byte = modifiers (0x02 Shift, 0x04 Alt/Option, 0x40 AltGr).
Macs have no AltGr; their special characters sit on Option combinations.

  python3 tools/make_mac_layouts.py de-DE.kl flipper/vaultflipper/files/layouts/de-DE-mac.kl
"""
import struct
import sys

SHIFT, OPTION = 0x02, 0x04

# German (macOS, ISO keyboard): character -> (keycode, modifiers)
DE_MAC = {
    "@": (0x0F, OPTION),  # Option+L
    "\\": (0x24, SHIFT | OPTION),  # Shift+Option+7
    "|": (0x24, OPTION),  # Option+7
    "{": (0x25, OPTION),  # Option+8
    "}": (0x26, OPTION),  # Option+9
    "[": (0x22, OPTION),  # Option+5
    "]": (0x23, OPTION),  # Option+6
    "~": (0x11, OPTION),  # Option+N (dead key)
}


def main(src: str, dst: str) -> None:
    with open(src, "rb") as f:
        table = list(struct.unpack("<128H", f.read()))
    for ch, (key, mods) in DE_MAC.items():
        table[ord(ch)] = key | (mods << 8)
    with open(dst, "wb") as f:
        f.write(struct.pack("<128H", *table))
    print(f"{dst}: {len(DE_MAC)} characters changed")


if __name__ == "__main__":
    main(*sys.argv[1:3])
