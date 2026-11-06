# SPDX-FileCopyrightText: 2026 Sven Würth
# SPDX-License-Identifier: MIT
import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from vaultflipper import cli
from vaultflipper import vfformat as vf
from vaultflipper.bitwarden import Account, BwClient, items_to_entries

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "tests" / "native"
SECRET = bytes(range(32))
OTHER_SECRET = bytes(range(1, 33))
PIN = "UUDDLRLRUDLR"


def sample_entries():
    return [
        vf.Entry("Personal", "Finance", "Bank", "alice", "pä$$w0rd!@#", "JBSWY3DPEHPK3PXP", "https://example.org"),
        vf.Entry("Work", "IT/Network", "Router", "admin", "x\"y'z\\|"),
        vf.Entry("Work", "", "Name only"),
    ]


def sealed(entries=None, pin=PIN, secret=SECRET, **kw):
    _, pk = vf.device_keypair(secret)
    vault = vf.Vault(entries=entries or sample_entries(), synced="2026-11-05 10:00")
    return vf.build_file(vault, pk, pin, **kw)[0]


# --- format & crypto -----------------------------------------------------------


def test_roundtrip_python():
    blob = sealed()
    v = vf.open_with_device_secret(blob, PIN, SECRET)
    assert [e.name for e in v.entries] == ["Bank", "Router", "Name only"]
    assert v.entries[0].password == "pä$$w0rd!@#"
    assert v.layout == "de-DE"


def test_wrong_pin_and_device_fail():
    blob = sealed()
    with pytest.raises(Exception):
        vf.open_with_device_secret(blob, "UUDDLRLRUDLL", SECRET)
    with pytest.raises(Exception):
        vf.open_with_device_secret(blob, PIN, OTHER_SECRET)


def test_header_tamper_detected():
    blob = bytearray(sealed())
    blob[12] ^= 1  # change passes -> AAD mismatch
    with pytest.raises(Exception):
        vf.open_with_device_secret(bytes(blob), PIN, SECRET)


def big_vault(n=2500, groups=40):
    return [
        vf.Entry(f"Acc{i % 3}", f"Group {i % groups:02d}", f"Login {i:05d}", f"user{i}", f"pw-{i}-" + "x" * 40, "", f"https://site{i}.example.com")
        for i in range(n)
    ]


def sorted_entries(entries):
    order = {}
    for e in entries:
        order.setdefault(e.account, len(order))
    return sorted(entries, key=lambda e: (order[e.account], e.group, e.name))


def test_limits():
    with pytest.raises(vf.FormatError):
        sealed(blocks=30)  # not a multiple of 4
    with pytest.raises(vf.FormatError):
        sealed([vf.Entry("A", "G", "huge", "u", "p" * 5000)])  # entry over 4 KB


def test_pagination_splits_groups():
    accounts, pages = vf.paginate(vf.Vault(entries=sorted_entries(big_vault())))
    assert accounts == ["Acc0", "Acc1", "Acc2"]
    assert all(len(p.entries) <= vf.PAGE_ENTRIES and len(p.plaintext()) <= vf.MAX_PAGE for p in pages)
    assert sum(len(p.entries) for p in pages) == 2500
    assert len({(p.account, p.group) for p in pages}) == 120  # 3 accounts x 40 groups


def test_large_vault_roundtrip_python():
    entries = sorted_entries(big_vault())
    blob = sealed(entries)
    assert len(blob) > 150_000
    v = vf.open_with_device_secret(blob, PIN, SECRET)
    assert [e.name for e in v.entries] == [e.name for e in entries]


@pytest.mark.parametrize(
    "raw,ok",
    [("UUDDLRLR", "UUDDLRLR"), ("u u d d l r l r", "UUDDLRLR"), ("↑↑↓↓←→←→", "UUDDLRLR")],
)
def test_normalize_pin(raw, ok):
    assert vf.normalize_pin(raw) == ok


@pytest.mark.parametrize("raw", ["UUDD", "UUDDLRLX", "U" * 33])
def test_normalize_pin_rejects(raw):
    with pytest.raises(ValueError):
        vf.normalize_pin(raw)


# --- native C core (same code as on the Flipper) -------------------------------


@pytest.fixture(scope="module")
def native():
    if not shutil.which("cc"):
        pytest.skip("no C compiler")
    subprocess.run(["make", "-s", "-C", str(NATIVE)], check=True)
    return NATIVE / "vf_native"


def test_native_pubkey_matches(native):
    out = subprocess.run([native, "pubkey", SECRET.hex()], capture_output=True, text=True, check=True).stdout.split()
    _, pk = vf.device_keypair(SECRET)
    assert out == [pk.hex(), vf.fingerprint(pk)]


def test_native_opens_python_file(native, tmp_path):
    f = tmp_path / "vault.vfv"
    f.write_bytes(sealed())
    res = subprocess.run([native, "open", f, PIN, SECRET.hex()], capture_output=True, text=True)
    assert res.returncode == 0, res.stdout
    lines = [ln for ln in res.stdout.splitlines() if not ln.startswith("PAGE ")]
    assert lines[0] == "META layout=de-DE synced=2026-11-05 10:00 count=3 pages=4 accounts=2 codes=1"
    assert lines[1] == "ENTRY Personal|Finance|Bank|alice|pä$$w0rd!@#|JBSWY3DPEHPK3PXP|https://example.org"
    assert lines[2] == "ENTRY Work|IT/Network|Router|admin|x\"y'z\\|" + "||"
    assert lines[3] == "ENTRY Work||Name only||||"
    assert lines[4] == "ENTRY #codes||Bank|alice||JBSWY3DPEHPK3PXP|"  # 2FA list: no password, no URL


def test_native_opens_large_vault_and_searches(native, tmp_path):
    entries = sorted_entries(big_vault())
    f = tmp_path / "vault.vfv"
    f.write_bytes(sealed(entries))
    res = subprocess.run([native, "open", f, PIN, SECRET.hex()], capture_output=True, text=True)
    assert res.returncode == 0, res.stdout[-500:]
    got = [ln.split("|")[2] for ln in res.stdout.splitlines() if ln.startswith("ENTRY ")]
    assert got == [e.name for e in entries]
    meta = res.stdout.splitlines()[0]
    assert "count=2500" in meta and "accounts=3" in meta
    found = subprocess.run([native, "search", f, PIN, SECRET.hex(), "login 0123"], capture_output=True, text=True).stdout
    assert sorted(ln.split("|")[2] for ln in found.splitlines() if ln.startswith("ENTRY ")) == ["Login 01230", "Login 01231", "Login 01232", "Login 01233", "Login 01234", "Login 01235", "Login 01236", "Login 01237", "Login 01238", "Login 01239"]


def test_native_detects_swapped_pages(native, tmp_path):
    import struct

    entries = sorted_entries(big_vault(200, groups=4))
    blob = bytearray(sealed(entries))
    v_dir_len = struct.unpack_from("<I", blob, 64)[0]
    first = vf.HEADER_SIZE + vf.BLOCK_OVERHEAD + v_dir_len
    # swap the nonce+tag of the first two pages: same key, wrong block number -> must fail
    _accounts, pages = vf.paginate(vf.Vault(entries=entries))
    second = first + vf.BLOCK_OVERHEAD + len(pages[0].plaintext())
    a, b = bytes(blob[first : first + 40]), bytes(blob[second : second + 40])
    blob[first : first + 40], blob[second : second + 40] = b, a
    f = tmp_path / "vault.vfv"
    f.write_bytes(bytes(blob))
    res = subprocess.run([native, "open", f, PIN, SECRET.hex()], capture_output=True, text=True)
    assert "PAGE 0 ERROR -2" in res.stdout and "PAGE 1 ERROR -2" in res.stdout


def test_native_rejects_wrong_pin_and_device(native, tmp_path):
    f = tmp_path / "vault.vfv"
    f.write_bytes(sealed())
    r1 = subprocess.run([native, "open", f, "UUDDLRLRUDLL", SECRET.hex()], capture_output=True, text=True)
    r2 = subprocess.run([native, "open", f, PIN, OTHER_SECRET.hex()], capture_output=True, text=True)
    assert (r1.returncode, r1.stdout.strip()) == (1, "ERROR -2")
    assert (r2.returncode, r2.stdout.strip()) == (1, "ERROR -2")


def test_native_rejects_bad_params(native, tmp_path):
    blob = bytearray(sealed())
    blob[8:12] = (1024).to_bytes(4, "little")  # 1 MiB - too much for the Flipper
    f = tmp_path / "vault.vfv"
    f.write_bytes(bytes(blob))
    r = subprocess.run([native, "open", f, PIN, SECRET.hex()], capture_output=True, text=True)
    assert r.stdout.strip() == "ERROR -4"


# --- 2FA codes ------------------------------------------------------------------

RFC_KEYS = {
    "SHA1": b"12345678901234567890",
    "SHA256": b"12345678901234567890123456789012",
    "SHA512": b"1234567890123456789012345678901234567890123456789012345678901234",
}
# RFC 6238 appendix B (8 digits)
RFC_VECTORS = [
    (59, "94287082", "46119246", "90693936"),
    (1111111109, "07081804", "68084774", "25091201"),
    (1111111111, "14050471", "67062674", "99943326"),
    (1234567890, "89005924", "91819424", "93441116"),
    (2000000000, "69279037", "90698825", "38618901"),
    (20000000000, "65353130", "77737706", "47863826"),
]


def rfc_field(algo: str) -> str:
    import base64

    return f"{algo}:8:30:" + base64.b32encode(RFC_KEYS[algo]).decode().rstrip("=")


def test_totp_normalize():
    from vaultflipper import totp

    assert totp.normalize("jbsw y3dp ehpk 3pxp") == "SHA1:6:30:JBSWY3DPEHPK3PXP"
    assert totp.normalize("otpauth://totp/Ex:alice?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60") == "SHA256:8:60:JBSWY3DPEHPK3PXP"
    assert totp.normalize("otpauth://totp/Ex?secret=jbswy3dpehpk3pxp&issuer=Ex") == "SHA1:6:30:JBSWY3DPEHPK3PXP"
    assert totp.normalize("steam://JBSWY3DPEHPK3PXP") == "STEAM:5:30:JBSWY3DPEHPK3PXP"
    assert totp.normalize("otpauth://hotp/Ex?secret=JBSWY3DPEHPK3PXP&counter=1") is None  # counter-based
    assert totp.normalize("otpauth://totp/Ex?secret=JBSWY3DPEHPK3PXP&algorithm=MD5") is None
    assert totp.normalize("not a secret!") is None
    assert totp.normalize("") is None
    assert totp.normalize("A" * 200) is None  # longer than the Flipper keeps
    assert totp.normalize("otpauth://steam/Steam:me?secret=JBSWY3DPEHPK3PXP") == "STEAM:5:30:JBSWY3DPEHPK3PXP"
    assert totp.normalize("otpauth://totp/me?secret=JBSWY3DPEHPK3PXP&encoder=steam") == "STEAM:5:30:JBSWY3DPEHPK3PXP"
    assert totp.normalize("otpauth://totp/Shop%20#2:me?secret=JBSWY3DPEHPK3PXP") == "SHA1:6:30:JBSWY3DPEHPK3PXP"
    assert totp.normalize("otpauth://totp/Shop #2:me?secret=JBSWY3DPEHPK3PXP") == "SHA1:6:30:JBSWY3DPEHPK3PXP"


def test_totp_rfc6238_python():
    from vaultflipper import totp

    for t, *codes in RFC_VECTORS:
        for algo, want in zip(RFC_KEYS, codes):
            assert totp.code(rfc_field(algo), t) == want, (algo, t)


def test_native_totp_matches(native):
    import random

    from vaultflipper import totp

    def run(field, t):
        return subprocess.run([native, "totp", field, str(t)], capture_output=True, text=True).stdout.split()

    for t, *codes in RFC_VECTORS:
        for algo, want in zip(RFC_KEYS, codes):
            assert run(rfc_field(algo), t) == [want, str(30 - t % 30)], (algo, t)
    rnd = random.Random(7)
    for _i in range(40):
        import base64

        key = bytes(rnd.randrange(256) for _j in range(rnd.choice([10, 16, 20, 32, 64])))
        secret = base64.b32encode(key).decode().rstrip("=")
        algo = rnd.choice(["SHA1", "SHA256", "SHA512", "STEAM"])
        digits = 5 if algo == "STEAM" else rnd.choice([6, 7, 8, 10])
        field = f"{algo}:{digits}:{rnd.choice([30, 60])}:{secret}"
        t = rnd.randrange(0, 4_000_000_000)
        assert run(field, t)[0] == totp.code(field, t), field
    assert run("JBSWY3DPEHPK3PXP", 59)[0] == totp.code("SHA1:6:30:JBSWY3DPEHPK3PXP", 59)  # bare secret
    assert run("SHA3:6:30:JBSWY3DPEHPK3PXP", 59) == ["INVALID"]
    assert run("SHA1:6:30:JBSW1", 59) == ["INVALID"]


def test_code_list_sorted_across_accounts(native, tmp_path):
    entries = [
        vf.Entry("A", "Mail", "Zulu", "z", "pw1", "SHA1:6:30:JBSWY3DPEHPK3PXP"),
        vf.Entry("A", "Mail", "No 2FA", "n", "pw2"),
        vf.Entry("B", "Dev", "alpha", "a", "pw3", "SHA256:8:60:JBSWY3DPEHPK3PXP"),
    ]
    blob = sealed(entries)
    v = vf.open_with_device_secret(blob, PIN, SECRET)
    assert [(c.name, c.username, c.password, c.totp) for c in v.codes] == [
        ("alpha", "a", "", "SHA256:8:60:JBSWY3DPEHPK3PXP"),
        ("Zulu", "z", "", "SHA1:6:30:JBSWY3DPEHPK3PXP"),
    ]
    assert len(v.entries) == 3
    f = tmp_path / "vault.vfv"
    f.write_bytes(blob)
    out = subprocess.run([native, "open", f, PIN, SECRET.hex()], capture_output=True, text=True, check=True).stdout
    assert "count=3 pages=3 accounts=2 codes=2" in out.splitlines()[0]


def test_prepare_normalizes_totp(capsys):
    good = vf.Entry("P", "G", "Good", totp="otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8")
    bad = vf.Entry("P", "G", "Counter", totp="otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP")
    out = cli.prepare([good, bad])
    assert [(x.name, x.totp) for x in out] == [("Counter", ""), ("Good", "SHA1:8:30:JBSWY3DPEHPK3PXP")]
    assert "Counter" in capsys.readouterr().out


def test_account_without_totp():
    items = [{"id": "1", "type": 1, "name": "M", "login": {"username": "a", "totp": "JBSWY3DPEHPK3PXP"}}]
    assert items_to_entries(Account("P", "s"), items, {}, {}, {})[0].totp == "JBSWY3DPEHPK3PXP"
    assert items_to_entries(Account("P", "s", include_totp=False), items, {}, {}, {})[0].totp == ""


def test_clock_offset_and_format():
    import time as _time

    from vaultflipper import flipper

    class FakeCli:
        def __init__(self, text):
            self.text = text

        def command(self, cmd):
            assert cmd == "date"
            return self.text

    now = _time.time()
    local = _time.strftime("%Y-%m-%d %H:%M:%S", _time.gmtime(now + 3600))
    off = flipper.clock_offset(FakeCli(local + " 5"))
    assert abs(off - 3600) <= 2
    assert flipper.clock_offset(FakeCli("2000-01-01 00:00:05 6")) is None  # never set
    assert flipper.clock_offset(FakeCli("garbage")) is None
    assert flipper.format_offset(3599) == "UTC+01:00"
    assert flipper.format_offset(19800) == "UTC+05:30"
    assert flipper.format_offset(-12600) == "UTC-03:30"


# --- Bitwarden conversion -------------------------------------------------------

ITEMS = [
    {"id": "1", "type": 1, "name": "Mail", "folderId": "f1", "favorite": True, "login": {"username": "a", "password": "b", "uris": [{"uri": "https://mail"}]}},
    {"id": "2", "type": 1, "name": "Router", "organizationId": "o1", "collectionIds": ["c1"], "login": {"username": "admin", "password": "c"}},
    {"id": "3", "type": 2, "name": "Note"},
    {"id": "4", "type": 1, "name": "Old", "deletedDate": "2026-01-01", "login": {}},
    {"id": "5", "type": 1, "name": "Bare", "login": {"password": "d"}},
]
FOLDERS = {"f1": "Personal"}
ORGS = {"o1": "Family"}
COLS = {"c1": {"id": "c1", "organizationId": "o1", "name": "Shared"}}


def test_items_to_entries_groups():
    es = items_to_entries(Account("P", "https://vault"), ITEMS, FOLDERS, ORGS, COLS)
    assert [(e.name, e.group) for e in es] == [("Mail", "Personal"), ("Router", "Family/Shared"), ("Bare", "No folder")]
    assert es[0].uri == "https://mail"


def test_items_filters():
    acc = Account("P", "s", favorites_only=True)
    assert [e.name for e in items_to_entries(acc, ITEMS, FOLDERS, ORGS, COLS)] == ["Mail"]
    acc = Account("P", "s", include_orgs=False)
    assert "Router" not in [e.name for e in items_to_entries(acc, ITEMS, FOLDERS, ORGS, COLS)]
    acc = Account("P", "s", collections=["Family/Shared"], folders=["None"])
    assert [e.name for e in items_to_entries(acc, ITEMS, FOLDERS, ORGS, COLS)] == ["Router"]
    # one kind of filter selects only that kind of item
    acc = Account("P", "s", collections=["Shared"])
    assert [e.name for e in items_to_entries(acc, ITEMS, FOLDERS, ORGS, COLS)] == ["Router"]
    acc = Account("P", "s", folders=["Personal"])
    assert [e.name for e in items_to_entries(acc, ITEMS, FOLDERS, ORGS, COLS)] == ["Mail"]


def test_collection_filter_names_the_matching_collection():
    cols = {**COLS, "c2": {"id": "c2", "organizationId": "o1", "name": "Streaming"}}
    items = [{"id": "9", "type": 1, "name": "TV", "organizationId": "o1", "collectionIds": ["c1", "c2"], "login": {}}]
    es = items_to_entries(Account("P", "s", collections=["Family/Streaming"]), items, FOLDERS, ORGS, cols)
    assert [e.group for e in es] == ["Family/Streaming"]


def test_folders_differing_in_case_stay_together():
    entries = [vf.Entry("A", g, n, "", "pw", "", "") for g, n in (("Work", "a"), ("work", "b"), ("Work", "c"))]
    groups = [x.group for x in cli.prepare(entries)]
    assert groups in (["Work", "Work", "work"], ["work", "Work", "Work"])


def test_directory_labels_are_short():
    assert vf._short("Ärztekammer Login") == "Ärztekammer"  # 12 bytes
    assert vf._short("abcdefghijkä") == "abcdefghijk"  # never half a character
    assert vf._short("Mail") == "Mail"


def test_prepare_dedupes_and_transliterates():
    a = vf.Entry("Personal", "Büro", "Zähler", source_id="s#1")
    b = vf.Entry("Work", "X", "Zähler", source_id="s#1")
    out = cli.prepare([a, b])
    assert len(out) == 1 and out[0].group == "Buero" and out[0].name == "Zaehler"


# --- bw CLI with a fake binary ------------------------------------------------------

FAKE_BW = r"""#!/usr/bin/env python3
import json, os, sys
args = [a for a in sys.argv[1:] if a != "--nointeraction"]
log = os.path.join(os.environ["BITWARDENCLI_APPDATA_DIR"], "calls.log")
open(log, "a").write(" ".join(args) + " session=" + os.environ.get("BW_SESSION", "-") + "\n")
cmd = args[0]
if cmd == "status": print(json.dumps({"status": "locked", "userEmail": "t@example.org", "serverUrl": "https://vault.test"}))
elif cmd == "unlock": print("SESSIONKEY")
elif cmd == "list":
    data = {"items": ITEMS, "folders": [{"id": "f1", "name": "Personal"}], "organizations": [{"id": "o1", "name": "Family"}],
            "collections": [{"id": "c1", "organizationId": "o1", "name": "Shared"}]}
    print(json.dumps(data[args[1]]))
"""


def test_bw_client_with_fake_cli(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "bw"
    fake.write_text(FAKE_BW.replace("ITEMS", f"json.loads({json.dumps(ITEMS)!r})"))
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    client = BwClient(Account("Personal", "https://vault.test"), tmp_path)
    client.unlock()
    es = client.fetch()
    client.lock()
    assert [e.name for e in es] == ["Mail", "Router", "Bare"]
    calls = (tmp_path / "bw" / "Personal" / "calls.log").read_text().splitlines()
    assert calls[0].startswith("status") and calls[1].startswith("unlock --raw")
    assert all("session=SESSIONKEY" in c for c in calls[2:])
    assert client.session is None


def test_cli_build_from_export(tmp_path, monkeypatch, capsys, native):
    monkeypatch.setenv("VAULTFLIPPER_HOME", str(tmp_path / "cfg"))
    _, pk = vf.device_keypair(SECRET)
    assert cli.main(["pair", "--pubkey", pk.hex(), "--yes"]) == 0
    export = tmp_path / "export.json"
    export.write_text(json.dumps({"encrypted": False, "folders": [{"id": "f1", "name": "Personal"}], "items": ITEMS}))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": PIN)
    out = tmp_path / "vault.vfv"
    assert cli.main(["build", "--export", f"Test={export}", "--out", str(out)]) == 0
    res = subprocess.run([native, "open", out, PIN, SECRET.hex()], capture_output=True, text=True, check=True)
    assert "ENTRY Test|Personal|Mail|a|b||https://mail" in res.stdout
    cfg = json.loads((tmp_path / "cfg" / "config.json").read_text())
    assert cfg["device_pubkey"] == pk.hex()
    assert oct((tmp_path / "cfg" / "config.json").stat().st_mode & 0o777) == "0o600"


# --- typing test and translations ----------------------------------------------


def test_typetest_compare():
    assert cli.compare_typetest(cli.TYPETEST) == []
    got = cli.TYPETEST.replace("@", "q").replace("~", "")
    assert ("@", "q") in cli.compare_typetest(got)
    assert ("~", "∅") in cli.compare_typetest(got)


def test_german_translation(monkeypatch):
    from vaultflipper import i18n

    monkeypatch.setattr(i18n, "LANG", "de")
    assert i18n._("Paired.") == "Gekoppelt."
    assert i18n._("Device fingerprint: {fp}", fp="AB12-CD34") == "Geräte-Fingerprint: AB12-CD34"
    monkeypatch.setattr(i18n, "LANG", "en")
    assert i18n._("Paired.") == "Paired."


def test_all_translations_have_same_placeholders():
    import string

    from vaultflipper import i18n

    fields = lambda t: sorted(f for _, f, _, _ in string.Formatter().parse(t) if f)
    for en, de in i18n.DE.items():
        assert fields(en) == fields(de), en


def test_every_message_is_translated():
    import ast

    from vaultflipper import i18n

    src = Path(cli.__file__).parent
    missing = []
    for f in src.glob("*.py"):
        for node in ast.walk(ast.parse(f.read_text())):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "_" and node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Constant) and arg.value not in i18n.DE:
                    missing.append(f"{f.name}: {arg.value}")
    assert not missing, missing


# --- arrow keys, layout detection, setup wizard -----------------------------------


def test_pin_accepts_real_arrow_keys():
    raw = "\x1b[A\x1b[A\x1b[B\x1b[B\x1b[D\x1b[C\x1bOD\x1bOC"
    assert vf.normalize_pin(raw) == "UUDDLRLR"


def test_hostlayout_mapping():
    from vaultflipper import hostlayout

    assert hostlayout.from_mac_source("com.apple.keylayout.German\n") == "de-DE-mac"
    assert hostlayout.from_mac_source("com.apple.keylayout.ABC") == "en-US"
    assert hostlayout.from_mac_source("com.apple.keylayout.Klingon") is None
    assert hostlayout.from_x11("   System Locale: LANG=de_DE.UTF-8\n       X11 Layout: ch\n") == "de-CH"
    assert hostlayout.from_x11("rules: evdev\nlayout: us\n") == "en-US"


def test_check_name():
    assert cli.check_name("Family 2") == "Family 2"
    for bad in ("../x", "", "a" * 40, "x/y"):
        with pytest.raises(SystemExit):
            cli.check_name(bad)


def _fake_bw(tmp_path, monkeypatch, status="unauthenticated"):
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    fake = bindir / "bw"
    script = FAKE_BW.replace("ITEMS", f"json.loads({json.dumps(ITEMS)!r})")
    script = script.replace('"status": "locked"', '"status": STATUS')
    script = script.replace("cmd = args[0]", f"cmd = args[0]\nSTATUS = 'locked' if os.path.exists(os.path.join(os.environ['BITWARDENCLI_APPDATA_DIR'], 'logged-in')) else {status!r}\nif cmd == 'login': open(os.path.join(os.environ['BITWARDENCLI_APPDATA_DIR'], 'logged-in'), 'w').close()\nif cmd == '--version': print('2026.10.0')")
    fake.write_text(script)
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")


def test_setup_wizard_end_to_end(tmp_path, monkeypatch, capsys, native):
    monkeypatch.setenv("VAULTFLIPPER_HOME", str(tmp_path / "cfg"))
    _fake_bw(tmp_path, monkeypatch)
    _, pk = vf.device_keypair(SECRET)
    monkeypatch.setattr(cli, "read_device_pubkey", lambda port=None: pk)
    monkeypatch.setattr(cli.hostlayout, "detect", lambda: "de-DE-mac")
    monkeypatch.setattr(cli, "server_info", lambda url: ("Vaultwarden", "2026.6.0"))
    sent = {}
    monkeypatch.setattr(cli, "push_vault", lambda blob, port=None: sent.setdefault("blob", blob))
    answers = iter([
        "",  # name -> default "Personal"
        "3",  # self-hosted
        "https://vault.example.com/",
        "",  # sign-in method -> email and master password
        "alice@example.com",
        "",  # add another? -> no
        "",  # press Enter when ready
        "",  # fingerprint matches -> yes
        "",  # layout -> detected default
        "",  # sync now -> yes
    ])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": "\x1b[A" * 4 + "\x1b[B" * 4 + "\x1b[D\x1b[C" * 2)
    assert cli.main(["setup"]) == 0
    cfg = json.loads((tmp_path / "cfg" / "config.json").read_text())
    assert cfg["accounts"][0]["name"] in ("Personal", "Privat")
    assert cfg["accounts"][0]["server"] == "https://vault.example.com"
    assert cfg["device_pubkey"] == pk.hex() and cfg["layout"] == "de-DE-mac"
    f = tmp_path / "vault.vfv"
    f.write_bytes(sent["blob"])
    res = subprocess.run([native, "open", f, "UUUUDDDDLRLR", SECRET.hex()], capture_output=True, text=True, check=True)
    assert "layout=de-DE-mac" in res.stdout and "|Mail|a|b|" in res.stdout


def test_status_reports_mismatched_flipper(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VAULTFLIPPER_HOME", str(tmp_path / "cfg"))
    _fake_bw(tmp_path, monkeypatch, status="locked")
    _, pk = vf.device_keypair(SECRET)
    _, other = vf.device_keypair(OTHER_SECRET)
    cli.main(["pair", "--pubkey", pk.hex(), "--yes"])
    monkeypatch.setattr(cli, "read_device_pubkey", lambda port=None: other)
    cli.main(["status"])
    out = capsys.readouterr().out
    assert vf.fingerprint(other) in out and "pair" in out


def test_no_unused_translations():
    import ast

    from vaultflipper import i18n

    used = set()
    for f in Path(cli.__file__).parent.glob("*.py"):
        for node in ast.walk(ast.parse(f.read_text())):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "_" and node.args:
                if isinstance(node.args[0], ast.Constant):
                    used.add(node.args[0].value)
    assert not [k for k in i18n.DE if k not in used]


def test_login_switches_to_sso_and_calls_bw(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULTFLIPPER_HOME", str(tmp_path / "cfg"))
    _fake_bw(tmp_path, monkeypatch)
    monkeypatch.setattr(cli, "server_info", lambda url: None)
    assert cli.main(["account", "add", "Work", "--server", "https://vault.example.com"]) == 0
    assert cli.main(["login", "Work", "--sso", "--sso-identifier", "acme"]) == 0
    cfg = json.loads((tmp_path / "cfg" / "config.json").read_text())
    assert cfg["accounts"][0]["login"] == "sso" and cfg["accounts"][0]["sso_identifier"] == "acme"
    calls = (tmp_path / "cfg" / "bw" / "Work" / "calls.log").read_text()
    assert "config server https://vault.example.com" in calls
    assert "login --sso acme" in calls
    mode = (tmp_path / "cfg" / "bw" / "Work").stat().st_mode & 0o777
    assert mode == 0o700


def test_sync_continues_without_failing_account(tmp_path, monkeypatch, native):
    monkeypatch.setenv("VAULTFLIPPER_HOME", str(tmp_path / "cfg"))
    _fake_bw(tmp_path, monkeypatch)
    _, pk = vf.device_keypair(SECRET)
    cli.main(["pair", "--pubkey", pk.hex(), "--yes"])
    cli.main(["account", "add", "Good", "--server", "https://a.example.com"])
    cli.main(["account", "add", "Broken", "--server", "https://b.example.com"])
    (tmp_path / "cfg" / "bw" / "Good").mkdir(parents=True)
    (tmp_path / "cfg" / "bw" / "Good" / "logged-in").touch()  # only "Good" is logged in
    monkeypatch.setattr(cli.getpass, "getpass", lambda prompt="": PIN)
    out = tmp_path / "vault.vfv"
    assert cli.main(["sync", "--out", str(out)]) == 0
    res = subprocess.run([native, "open", out, PIN, SECRET.hex()], capture_output=True, text=True, check=True)
    assert "ENTRY Good|" in res.stdout and "Broken" not in res.stdout


def test_server_info_parses_config(monkeypatch):
    import io

    from vaultflipper import bitwarden

    body = json.dumps({"server": {"name": "Vaultwarden"}, "version": "2026.6.0"}).encode()

    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(bitwarden.urllib.request, "urlopen", lambda req, timeout: Resp(body))
    assert bitwarden.server_info("https://vault.example.com/") == ("Vaultwarden", "2026.6.0")


def test_sso_on_vaultwarden_uses_fixed_identifier(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULTFLIPPER_HOME", str(tmp_path / "cfg"))
    _fake_bw(tmp_path, monkeypatch)
    monkeypatch.setattr(cli, "server_info", lambda url: ("Vaultwarden", "2026.6.0"))
    cli.main(["account", "add", "Work", "--server", "https://vault.example.com"])
    assert cli.main(["login", "Work", "--sso"]) == 0
    assert "login --sso vaultwarden" in (tmp_path / "cfg" / "bw" / "Work" / "calls.log").read_text()
