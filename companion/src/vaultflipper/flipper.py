# SPDX-FileCopyrightText: 2026 Sven Würth
# SPDX-License-Identifier: MIT
"""Transfer files over the Flipper Zero USB CLI (storage write_chunk / read / md5)."""

from __future__ import annotations

import calendar
import hashlib
import re
import time

import serial
from serial.tools import list_ports

from .i18n import _

APP_DIR = "/ext/apps_data/vaultflipper"
VAULT_PATH = f"{APP_DIR}/vault.vfv"
TMP_PATH = f"{APP_DIR}/vault.tmp"
PUBKEY_PATH = f"{APP_DIR}/device.pub"
CLOCK_PATH = f"{APP_DIR}/clock"
CLOCK_UNSET = 1577836800  # 2020-01-01: an earlier Flipper clock was never set
PROMPT = b">: "
FLIPPER_VID, FLIPPER_PID = 0x0483, 0x5740
CHUNK = 512


class FlipperError(Exception):
    pass


def find_port() -> str:
    # 0483:5740 is ST's generic serial ID, also used by dev boards and 3D printers
    for p in list_ports.comports():
        named = "flipper" in f"{p.manufacturer} {p.product}".lower() or "flip" in (p.device or "").lower()
        if named or ((p.vid, p.pid) == (FLIPPER_VID, FLIPPER_PID) and not p.manufacturer):
            return p.device
    raise FlipperError(_("No Flipper found. Connect it via USB and close qFlipper and the VaultFlipper app."))


class FlipperCli:
    def __init__(self, port: str | None = None, timeout: float = 5.0):
        self.port = port or find_port()
        try:
            self.ser = serial.Serial(self.port, 230400, timeout=timeout)
        except (OSError, ValueError) as ex:  # busy (qFlipper) or a wrong --port
            raise FlipperError(_("Could not open {port}: {err}. Close qFlipper and the VaultFlipper app.", port=self.port, err=ex)) from None
        time.sleep(0.2)
        self.ser.reset_input_buffer()
        self.ser.write(b"\r")
        self._read_until(PROMPT)
        self._drain()  # a late welcome banner would shift every later reply

    def _drain(self) -> None:
        timeout, self.ser.timeout = self.ser.timeout, 0.2
        try:
            while self.ser.read(4096):
                pass
        finally:
            self.ser.timeout = timeout

    def close(self) -> None:
        self.ser.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _read_until(self, marker: bytes) -> bytes:
        data = self.ser.read_until(marker)
        if not data.endswith(marker):
            raise FlipperError(_("Timed out waiting for the Flipper."))
        return data

    def command(self, cmd: str) -> str:
        self.ser.write(cmd.encode() + b"\r")
        out = self._read_until(PROMPT).decode(errors="replace").replace("\r", "")
        lines = out.split("\n")
        if lines and lines[0].strip() == cmd.strip():
            lines = lines[1:]  # drop the echo
        return "\n".join(lines).removesuffix(">: ").strip()

    def write_file(self, path: str, data: bytes) -> None:
        self.command(f"storage remove {path}")  # "does not exist" is fine
        for off in range(0, len(data), CHUNK):
            chunk = data[off : off + CHUNK]
            self.ser.write(f"storage write_chunk {path} {len(chunk)}\r".encode())
            resp = self._read_until(b"\n")  # echo
            if b"Ready" not in resp:
                resp += self.ser.read_until(b"\n")
                if b"Ready" not in resp:
                    raise FlipperError(_("Flipper rejected the write: {resp}", resp=resp))
            self.ser.write(chunk)
            tail = self._read_until(PROMPT).decode(errors="replace")
            if "error" in tail.lower():
                raise FlipperError(_("Write error: {msg}", msg=tail.strip()))

    def md5(self, path: str) -> str:
        timeout, self.ser.timeout = self.ser.timeout, 30  # hashing a large vault takes a while
        try:
            out = self.command(f"storage md5 {path}")
        finally:
            self.ser.timeout = timeout
        m = re.search(r"\b[0-9a-f]{32}\b", out)
        if not m:
            raise FlipperError(_("Could not read {path}: {msg}", path=path, msg=out))
        return m.group(0)

    def read_text(self, path: str) -> str:
        out = self.command(f"storage read {path}")
        if "Size:" not in out:
            raise FlipperError(_("Could not read {path}: {msg}", path=path, msg=out))
        return out.split("\n", 1)[1] if "\n" in out else ""


def clock_offset(cli: FlipperCli) -> int | None:
    """Seconds the Flipper clock is ahead of UTC (its time zone plus drift).

    The Flipper keeps local time, set by qFlipper or the mobile app; 2FA codes
    need UTC. None if the clock cannot be read or was never set."""
    t0 = time.time()
    out = cli.command("date")
    t1 = time.time()
    m = re.search(r"(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})", out)
    if not m:
        return None
    rtc = calendar.timegm(tuple(int(x) for x in m.groups()))
    if rtc < CLOCK_UNSET:
        return None
    return round(rtc + 0.5 - (t0 + t1) / 2)  # the clock shows whole seconds


def format_offset(seconds: int) -> str:
    """3600 -> 'UTC+01:00' (rounded to 15 minutes)."""
    q = round(seconds / 900) * 900
    sign = "+" if q >= 0 else "-"
    q = abs(q)
    return f"UTC{sign}{q // 3600:02d}:{q % 3600 // 60:02d}"


def read_device_pubkey(port: str | None = None) -> bytes:
    with FlipperCli(port) as cli:
        try:
            text = cli.read_text(PUBKEY_PATH)
        except FlipperError:
            text = ""
    m = re.search(r"[0-9a-fA-F]{64}", text)
    if not m:
        raise FlipperError(_("device.pub not found - open VaultFlipper on the Flipper once, then pair again."))
    return bytes.fromhex(m.group(0))


def push_vault(blob: bytes, port: str | None = None) -> int | None:
    """Send the vault; also store the clock offset for 2FA codes and return it."""
    with FlipperCli(port) as cli:
        cli.command(f"storage mkdir {APP_DIR}")
        cli.write_file(TMP_PATH, blob)
        if cli.md5(TMP_PATH) != hashlib.md5(blob).hexdigest():
            raise FlipperError(_("Checksum mismatch - transfer failed."))
        cli.command(f"storage remove {VAULT_PATH}")
        out = cli.command(f"storage rename {TMP_PATH} {VAULT_PATH}")
        if "error" in out.lower():
            raise FlipperError(_("Rename failed: {msg}", msg=out))
        # The vault is in place; a clock problem must not fail the sync.
        try:
            offset = clock_offset(cli)
            if offset is not None:
                cli.write_file(CLOCK_PATH, f"{offset}\n".encode())
        except FlipperError:
            return None
        return offset
