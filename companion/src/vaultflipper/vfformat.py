# SPDX-FileCopyrightText: 2026 Sven Würth
# SPDX-License-Identifier: MIT
"""VaultFlipper file format (counterpart of flipper/vaultflipper/vf_core.h)."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

import nacl.bindings as sodium
import nacl.pwhash.argon2id as argon2id
import nacl.utils

from .i18n import _

MAGIC = b"VFLP"
DIR_MAGIC = b"VFD2"
PAGE_MAGIC = b"VFG2"
VERSION = 2
HEADER_SIZE = 72
BLOCK_OVERHEAD = 40  # nonce 24 + tag 16
MAX_DIR = 24 * 1024
MAX_PAGE = 8 * 1024
PAGE_TARGET = 6 * 1024
PAGE_ENTRIES = 48
MAX_PAGES = 1024
MAX_ACCOUNTS = 16
CODES_ACCOUNT = 0xFF  # account byte of the pages that hold the 2FA list
MAX_ENTRY = 4 * 1024
MIN_BLOCKS, MAX_BLOCKS = 8, 64
MIN_PASSES, MAX_PASSES = 1, 1000
DEFAULT_BLOCKS = 32
DEFAULT_PASSES = 64
X25519_LABEL = b"VaultFlipper x25519 v1"

TAG_ACCOUNT = 1
TAG_GROUP = 2
TAG_NAME = 3
TAG_USER = 4
TAG_PASS = 5
TAG_TOTP = 6
TAG_URI = 7
TAG_META_LAYOUT = 0x10
TAG_META_SYNCED = 0x11
TAG_FIRST = 0x20
TAG_LAST = 0x21

PIN_SYMBOLS = {"U": "U", "D": "D", "L": "L", "R": "R", "↑": "U", "↓": "D", "←": "L", "→": "R"}
MIN_PIN = 8
MAX_PIN = 32


class FormatError(Exception):
    pass


@dataclass
class Entry:
    account: str
    group: str
    name: str
    username: str = ""
    password: str = ""
    totp: str = ""
    uri: str = ""
    source_id: str = ""  # for de-duplication, not stored


@dataclass
class Vault:
    entries: list[Entry]
    layout: str = "de-DE"
    synced: str = ""
    meta: dict = field(default_factory=dict)
    codes: list[Entry] = field(default_factory=list)  # the 2FA list, only filled when reading


def normalize_pin(raw: str) -> str:
    """PIN as an arrow sequence: U/D/L/R (or arrow symbols), spaces allowed."""
    # Real arrow keys arrive as terminal escape sequences (ESC [ A or ESC O A).
    for seq, sym in (("A", "U"), ("B", "D"), ("C", "R"), ("D", "L")):
        raw = raw.replace("\x1b[" + seq, sym).replace("\x1bO" + seq, sym)
    out = []
    for ch in raw.strip().upper():
        if ch in " ,-":
            continue
        if ch not in PIN_SYMBOLS:
            raise ValueError(_("Invalid character in PIN: {ch!r} (allowed: U D L R)", ch=ch))
        out.append(PIN_SYMBOLS[ch])
    pin = "".join(out)
    if not MIN_PIN <= len(pin) <= MAX_PIN:
        raise ValueError(_("PIN must be {min}-{max} keys long (got {n})", min=MIN_PIN, max=MAX_PIN, n=len(pin)))
    return pin


def device_keypair(device_secret: bytes) -> tuple[bytes, bytes]:
    """For tests: how the Flipper derives its key pair."""
    sk = hashlib.blake2b(X25519_LABEL, key=device_secret, digest_size=32).digest()
    return sk, sodium.crypto_scalarmult_base(sk)


def fingerprint(pk: bytes) -> str:
    h = hashlib.blake2b(pk, digest_size=32).hexdigest().upper()
    return f"{h[0:4]}-{h[4:8]}"


def _field(tag: int, value: str) -> bytes:
    data = value.encode("utf-8")
    if b"\x00" in data:
        raise FormatError("NUL byte in a field")
    if len(data) > 0xFFFF:
        raise FormatError("field too long")
    return struct.pack("<BH", tag, len(data)) + data + b"\x00"


def _record(fields: list[tuple[int, str]]) -> bytes:
    fields = [(t, v) for t, v in fields if v]
    return struct.pack("<B", len(fields)) + b"".join(_field(t, v) for t, v in fields)


def entry_record(e: Entry) -> bytes:
    return _record([(TAG_NAME, e.name), (TAG_USER, e.username), (TAG_PASS, e.password), (TAG_TOTP, e.totp), (TAG_URI, e.uri)])


def _pin_key(pin: str, salt: bytes, blocks: int, passes: int) -> bytes:
    # libsodium Argon2id: lanes = 1, memlimit in bytes - identical to Monocypher with nb_lanes = 1
    return argon2id.kdf(32, pin.encode("ascii"), salt, opslimit=passes, memlimit=blocks * 1024)


def _final_key(shared: bytes, pin_key: bytes) -> bytes:
    return hashlib.blake2b(pin_key, key=shared, digest_size=32).digest()


@dataclass
class Page:
    account: int
    group: str
    entries: list[Entry]

    def plaintext(self) -> bytes:
        return PAGE_MAGIC + struct.pack("<H", len(self.entries)) + b"".join(entry_record(e) for e in self.entries)


def _add(pages: list[Page], acc: int, e: Entry) -> None:
    cur = pages[-1] if pages else None
    if (
        cur is None
        or cur.account != acc
        or cur.group != e.group
        or len(cur.entries) >= PAGE_ENTRIES
        or len(cur.plaintext()) + len(entry_record(e)) > PAGE_TARGET
    ):
        cur = Page(acc, e.group, [])
        pages.append(cur)
    cur.entries.append(e)


def code_entries(entries: list[Entry]) -> list[Entry]:
    """The 2FA list: name, username and secret of every login with a TOTP secret."""
    found = [Entry("", "", e.name, e.username, totp=e.totp) for e in entries if e.totp]
    return sorted(found, key=lambda x: (x.name.casefold(), x.username.casefold()))


def paginate(vault: Vault) -> tuple[list[str], list[Page]]:
    """Group sorted entries by account and group, split into pages; the 2FA list comes last."""
    accounts: list[str] = []
    pages: list[Page] = []
    for e in vault.entries:
        if len(entry_record(e)) > MAX_ENTRY:
            raise FormatError(f"entry too large: {e.account} / {e.name}")
        if e.account not in accounts:
            accounts.append(e.account)
        _add(pages, accounts.index(e.account), e)
    if not pages:
        raise FormatError(_("Nothing to sync: no logins found."))
    for e in code_entries(vault.entries):
        _add(pages, CODES_ACCOUNT, e)
    if len(accounts) > MAX_ACCOUNTS:
        raise FormatError(_("Too many accounts: at most {max}.", max=MAX_ACCOUNTS))
    if len(pages) > MAX_PAGES:
        raise FormatError(_("Too many folders and logins for one Flipper vault. Narrow the account filters."))
    return accounts, pages


def _short(name: str, limit: int = 12) -> str:
    """First/last names in the directory only label folder pages ("Amazon - Dropbox"):
    the app shows at most 12 bytes, so store no more and fit more pages."""
    raw = name.encode("utf-8")[:limit]
    return raw.decode("utf-8", errors="ignore")


def _directory(vault: Vault, accounts: list[str], pages: list[Page], offsets: list[tuple[int, int]]) -> bytes:
    out = bytearray(DIR_MAGIC)
    out += _record([(TAG_META_LAYOUT, vault.layout), (TAG_META_SYNCED, vault.synced)])
    out += struct.pack("<B", len(accounts))
    for name in accounts:
        out += _record([(TAG_ACCOUNT, name)])
    out += struct.pack("<H", len(pages))
    for page, (offset, length) in zip(pages, offsets):
        out += struct.pack("<BIIH", page.account, offset, length, len(page.entries))
        out += _record([(TAG_GROUP, page.group), (TAG_FIRST, _short(page.entries[0].name)), (TAG_LAST, _short(page.entries[-1].name))])
    return bytes(out)


def _block(key: bytes, header: bytes, number: int, plain: bytes) -> bytes:
    nonce = nacl.utils.random(24)
    aad = header + struct.pack("<I", number)
    ct_tag = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plain, aad, nonce, key)
    return nonce + ct_tag[-16:] + ct_tag[:-16]


@dataclass
class BuildInfo:
    size: int
    pages: int
    accounts: int


def build_file(
    vault: Vault,
    device_pk: bytes,
    pin: str,
    blocks: int = DEFAULT_BLOCKS,
    passes: int = DEFAULT_PASSES,
) -> tuple[bytes, BuildInfo]:
    if not MIN_BLOCKS <= blocks <= MAX_BLOCKS or blocks % 4 or not MIN_PASSES <= passes <= MAX_PASSES:
        raise FormatError(_("Argon2 parameters outside the Flipper's limits"))
    if len(device_pk) != 32:
        raise FormatError(_("Device key must be 32 bytes"))
    accounts, pages = paginate(vault)
    plains = [p.plaintext() for p in pages]

    # offsets are fixed-width, so the directory size is known before the offsets
    dir_len = len(_directory(vault, accounts, pages, [(0, 0)] * len(pages)))
    if dir_len > MAX_DIR:
        raise FormatError(_("Too many folders and logins for one Flipper vault. Narrow the account filters."))
    offsets = []
    pos = HEADER_SIZE + BLOCK_OVERHEAD + dir_len
    for plain in plains:
        offsets.append((pos, len(plain)))
        pos += BLOCK_OVERHEAD + len(plain)
    directory = _directory(vault, accounts, pages, offsets)

    salt = nacl.utils.random(16)
    eph_sk = nacl.utils.random(32)
    eph_pk = sodium.crypto_scalarmult_base(eph_sk)
    shared = sodium.crypto_scalarmult(eph_sk, device_pk)
    key = _final_key(shared, _pin_key(pin, salt, blocks, passes))
    header = MAGIC + bytes([VERSION, 0, 0, 0]) + struct.pack("<II", blocks, passes) + salt + eph_pk + struct.pack("<II", len(directory), 0)
    assert len(header) == HEADER_SIZE

    out = bytearray(header)
    out += _block(key, header, 0, directory)
    for i, plain in enumerate(plains):
        assert len(out) == offsets[i][0]
        out += _block(key, header, i + 1, plain)
    return bytes(out), BuildInfo(size=len(out), pages=len(pages), accounts=len(accounts))


def _parse_records(data: bytes, pos: int, count: int) -> tuple[list[dict[int, str]], int]:
    recs = []
    for _i in range(count):
        n = data[pos]
        pos += 1
        rec = {}
        for _j in range(n):
            tag, ln = struct.unpack_from("<BH", data, pos)
            pos += 3
            rec[tag] = data[pos : pos + ln].decode("utf-8")
            pos += ln + 1
        recs.append(rec)
    return recs, pos


def open_with_device_secret(blob: bytes, pin: str, device_secret: bytes) -> Vault:
    """For tests: decrypt everything the way the Flipper does (needs the device secret)."""
    if blob[:4] != MAGIC or blob[4] != VERSION:
        raise FormatError("not a VaultFlipper file")
    header = blob[:HEADER_SIZE]
    blocks, passes = struct.unpack_from("<II", header, 8)
    salt, eph_pk = header[16:32], header[32:64]
    (dir_len,) = struct.unpack_from("<I", header, 64)
    sk, _pk = device_keypair(device_secret)
    key = _final_key(sodium.crypto_scalarmult(sk, eph_pk), _pin_key(pin, salt, blocks, passes))

    def block(number: int, offset: int, length: int) -> bytes:
        nonce, tag = blob[offset : offset + 24], blob[offset + 24 : offset + 40]
        ct = blob[offset + 40 : offset + 40 + length]
        return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(ct + tag, header + struct.pack("<I", number), nonce, key)

    d = block(0, HEADER_SIZE, dir_len)
    if d[:4] != DIR_MAGIC:
        raise FormatError("bad directory")
    (meta,), pos = _parse_records(d, 4, 1)
    n_acc = d[pos]
    accs, pos = _parse_records(d, pos + 1, n_acc)
    (n_pages,) = struct.unpack_from("<H", d, pos)
    pos += 2
    entries: list[Entry] = []
    codes: list[Entry] = []
    for i in range(n_pages):
        acc, offset, length, count = struct.unpack_from("<BIIH", d, pos)
        (info,), pos = _parse_records(d, pos + 11, 1)
        page = block(i + 1, offset, length)
        recs, _end = _parse_records(page, 6, count)
        for r in recs:
            (codes if acc == CODES_ACCOUNT else entries).append(
                Entry(
                    account="" if acc == CODES_ACCOUNT else accs[acc].get(TAG_ACCOUNT, ""),
                    group=info.get(TAG_GROUP, ""),
                    name=r.get(TAG_NAME, ""),
                    username=r.get(TAG_USER, ""),
                    password=r.get(TAG_PASS, ""),
                    totp=r.get(TAG_TOTP, ""),
                    uri=r.get(TAG_URI, ""),
                )
            )
    return Vault(entries=entries, layout=meta.get(TAG_META_LAYOUT, ""), synced=meta.get(TAG_META_SYNCED, ""), codes=codes)
