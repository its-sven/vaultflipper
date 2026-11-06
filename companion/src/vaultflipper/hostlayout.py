# SPDX-FileCopyrightText: 2026 Sven Würth
# SPDX-License-Identifier: MIT
"""Guess the keyboard layout of this computer and map it to a Flipper layout name.

The result is only a default for the Flipper; it can always be changed there.
"""

from __future__ import annotations

import platform
import re
import subprocess

# macOS input source IDs (com.apple.keylayout.<X>) -> Flipper layout
MAC = {
    "German": "de-DE-mac",
    "Austrian": "de-DE-mac",
    "US": "en-US",
    "ABC": "en-US",
    "USInternational-PC": "en-US",
    "French": "fr-FR-mac",
    "French-PC": "fr-FR",
    "Italian": "it-IT-mac",
    "Italian-Pro": "it-IT-mac",
    "Dvorak": "dvorak",
}

# Windows keyboard layout IDs (low word of the HKL) -> Flipper layout
WINDOWS = {
    0x0407: "de-DE",
    0x0C07: "de-DE",
    0x0807: "de-CH",
    0x100C: "fr-CH",
    0x040C: "fr-FR",
    0x080C: "fr-BE",
    0x0C0C: "fr-CA",
    0x0409: "en-US",
    0x0809: "en-UK",
    0x0410: "it-IT",
    0x0C0A: "es-ES",
    0x080A: "es-LA",
    0x0413: "nl-NL",
    0x0416: "pt-BR",
    0x0816: "pt-PT",
    0x041D: "sv-SE",
    0x0414: "nb-NO",
    0x0406: "da-DA",
    0x040E: "hu-HU",
    0x041A: "hr-HR",
    0x0424: "si-SI",
    0x041B: "sk-SK",
    0x0405: "cz_CS",
    0x041F: "tr-TR",
    0x0411: "ja-JP",
}

# X11 / localectl layout codes -> Flipper layout
X11 = {
    "de": "de-DE",
    "at": "de-DE",
    "ch": "de-CH",
    "fr": "fr-FR",
    "be": "fr-BE",
    "us": "en-US",
    "gb": "en-UK",
    "it": "it-IT",
    "es": "es-ES",
    "latam": "es-LA",
    "nl": "nl-NL",
    "br": "pt-BR",
    "pt": "pt-PT",
    "se": "sv-SE",
    "no": "nb-NO",
    "dk": "da-DA",
    "hu": "hu-HU",
    "hr": "hr-HR",
    "si": "si-SI",
    "sk": "sk-SK",
    "cz": "cz_CS",
    "tr": "tr-TR",
    "jp": "ja-JP",
}


def _run(*cmd: str) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def from_mac_source(source_id: str) -> str | None:
    name = source_id.strip().rsplit(".", 1)[-1]
    return MAC.get(name)


def from_x11(text: str) -> str | None:
    m = re.search(r"(?:X11 Layout|layout):\s*([a-z]+)", text)
    return X11.get(m.group(1)) if m else None


def detect() -> str | None:
    system = platform.system()
    if system == "Darwin":
        return from_mac_source(_run("defaults", "read", "com.apple.HIToolbox", "AppleCurrentKeyboardLayoutInputSourceID"))
    if system == "Windows":
        try:
            import ctypes

            hkl = ctypes.windll.user32.GetKeyboardLayout(0)  # type: ignore[attr-defined]
            return WINDOWS.get(hkl & 0xFFFF)
        except Exception:
            return None
    return from_x11(_run("localectl", "status")) or from_x11(_run("setxkbmap", "-query"))
