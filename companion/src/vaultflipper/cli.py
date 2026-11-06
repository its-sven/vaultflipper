# SPDX-FileCopyrightText: 2026 Sven Würth
# SPDX-License-Identifier: MIT
"""vaultflipper – companion CLI: Bitwarden/Vaultwarden -> Flipper Zero."""

from __future__ import annotations

import argparse
import difflib
import getpass  # noqa: F401  (tests patch getpass.getpass)
import json
import os
import re
import subprocess
import sys
import unicodedata
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from . import __version__, hostlayout, totp, ui
from . import vfformat as vf
from .bitwarden import LOGIN_METHODS, Account, BwClient, BwError, bw_binary, entries_from_export, server_info
from .flipper import FlipperError, format_offset, push_vault, read_device_pubkey
from .i18n import _
from .ui import e

TRANSLIT = str.maketrans({"ä": "ae", "ö": "oe", "ü": "ue", "Ä": "Ae", "Ö": "Oe", "Ü": "Ue", "ß": "ss", "€": "EUR"})
TYPETEST = "".join(chr(c) for c in range(33, 127))
ARROWS = {"U": "↑", "D": "↓", "L": "←", "R": "→"}
SERVERS = [
    ("Bitwarden US", "https://vault.bitwarden.com"),
    ("Bitwarden EU", "https://vault.bitwarden.eu"),
]
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,31}$")


# --- configuration ------------------------------------------------------------


def config_dir() -> Path:
    base = os.environ.get("VAULTFLIPPER_HOME")
    return Path(base) if base else Path.home() / ".config" / "vaultflipper"


def load_config() -> dict:
    p = config_dir() / "config.json"
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return {
        "accounts": [],
        "device_pubkey": "",
        "layout": "",
        "argon_blocks": vf.DEFAULT_BLOCKS,
        "argon_passes": vf.DEFAULT_PASSES,
    }


def save_config(cfg: dict) -> None:
    d = config_dir()
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    p = d / "config.json"
    p.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.chmod(p, 0o600)


def accounts_from(cfg: dict, names: list[str] | None = None) -> list[Account]:
    accs = [Account(**a) for a in cfg.get("accounts", [])]
    if names:
        missing = set(names) - {a.name for a in accs}
        if missing:
            raise SystemExit(_("Unknown accounts: {names}", names=", ".join(sorted(missing))))
        accs = [a for a in accs if a.name in names]
    return accs


def update_account(cfg: dict, acc: Account) -> None:
    cfg["accounts"] = [asdict(acc) if a["name"] == acc.name else a for a in cfg["accounts"]]
    save_config(cfg)


def check_name(name: str) -> str:
    if not NAME_RE.match(name):
        raise SystemExit(_("Account names may use letters, digits, space, dot, dash and underscore (max. 32)."))
    return name


def default_layout(cfg: dict) -> str:
    return cfg.get("layout") or hostlayout.detect() or "en-US"


def device_pubkey(cfg: dict) -> bytes:
    pk = cfg.get("device_pubkey")
    if not pk:
        raise SystemExit(_("No Flipper paired yet. Run: vaultflipper pair"))
    return bytes.fromhex(pk)


def login_label(method: str) -> str:
    return {"password": _("email + master password"), "sso": _("single sign-on (SSO)"), "apikey": _("API key")}[method]


# --- entries ------------------------------------------------------------------


def display(s: str) -> str:
    """The Flipper font is ASCII-only: transliterate umlauts, drop the rest."""
    s = s.translate(TRANSLIT)
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode()
    return s.strip() or "?"


def prepare(entries: list[vf.Entry]) -> list[vf.Entry]:
    seen: set[str] = set()
    out = []
    bad_totp: list[vf.Entry] = []
    for en in entries:
        if en.source_id and en.source_id in seen:
            continue  # shared organization item reachable from several accounts
        if en.totp:
            canonical = totp.normalize(en.totp)
            if canonical is None:
                bad_totp.append(en)
            en.totp = canonical or ""
        if len(vf.entry_record(en)) > vf.MAX_ENTRY:
            ui.warn(_("Skipped {name}: the entry is larger than 4 KB.", name=e(en.name)))
            continue
        seen.add(en.source_id)
        en.account, en.group, en.name = display(en.account), display(en.group), display(en.name)
        out.append(en)
    if bad_totp:
        ui.warn(_("{n} 2FA secrets cannot be used on the Flipper (counter-based or unreadable) and were left out:", n=len(bad_totp)))
        for x in bad_totp[:10]:
            ui.hint(f"{e(x.account)} / {e(x.name)}")
    order: dict[str, int] = {}
    for en in out:
        order.setdefault(en.account, len(order))
    # x.group after the casefold key keeps "Work" and "work" apart: pages split on the exact name
    out.sort(key=lambda x: (order[x.account], x.group.casefold(), x.group, x.name.casefold()))
    return out


def warn_untypable(entries: list[vf.Entry]) -> None:
    bad = [x for x in entries if not (x.username + x.password).isascii()]
    if bad:
        ui.warn(_("{n} entries contain characters a USB keyboard cannot type (e.g. ä, €); those characters are skipped:", n=len(bad)))
        for x in bad[:10]:
            ui.hint(f"{e(x.account)} / {e(x.group)} / {e(x.name)}")


def ask_pin() -> str:
    ui.info(_("Choose a PIN: press the [key]arrow keys[/] (or type U D L R), at least 8 presses, then Enter."))
    ui.hint(_("Nothing is shown while you type."))
    while True:
        try:
            pin = vf.normalize_pin(ui.secret(_("PIN")))
            again = vf.normalize_pin(ui.secret(_("Repeat PIN")))
        except ValueError as ex:
            ui.warn(e(ex))
            continue
        if again != pin:
            ui.warn(_("PINs do not match."))
            continue
        ui.ok(_("PIN set: {n} presses", n=len(pin)) + f"  [accent]{' '.join(ARROWS[c] for c in pin)}[/]")
        if len(pin) < 12:
            ui.hint(_("Tip: 12 or more presses make guessing on a stolen device much slower."))
        return pin


def seal_and_deliver(entries: list[vf.Entry], cfg: dict, args) -> None:
    entries = prepare(entries)
    vault = vf.Vault(entries=entries, layout=args.layout or default_layout(cfg), synced=datetime.now().strftime("%Y-%m-%d %H:%M"))
    _accounts, pages = vf.paginate(vault)  # checks the limits before asking for a PIN

    counts: dict[str, int] = {}
    for x in entries:
        counts[x.account] = counts.get(x.account, 0) + 1
    t = ui.table(_("Account"), _("Logins"))
    for name, n in counts.items():
        t.add_row(f"[value]{e(name)}[/]", str(n))
    ui.console.print()
    ui.console.print(t)
    ui.info(_("{n} logins on {pages} pages, keyboard layout {layout}", n=len(entries), pages=len(pages), layout=f"[value]{e(vault.layout)}[/]"))
    codes = sum(1 for x in entries if x.totp)
    if codes:
        ui.info(_("{n} logins with 2FA codes – shown under [key]2FA codes[/] on the Flipper", n=codes))
    warn_untypable(entries)
    if args.dry_run:
        ui.console.print()
        for x in entries:
            ui.hint(f"{e(x.account)} / {e(x.group)} / {e(x.name)}")
        return

    pk = device_pubkey(cfg)
    ui.console.print()
    pin = ask_pin()
    with ui.status(_("Encrypting for your Flipper…")):
        blob, built = vf.build_file(vault, pk, pin, cfg.get("argon_blocks", vf.DEFAULT_BLOCKS), cfg.get("argon_passes", vf.DEFAULT_PASSES))
    del pin
    ui.ok(_("Encrypted: {size} KB in {pages} pages.", size=f"{built.size / 1024:.0f}", pages=built.pages))
    if args.out:
        Path(args.out).write_bytes(blob)
        ui.ok(_("Wrote {path} – copy it to /ext/apps_data/vaultflipper/vault.vfv on the Flipper.", path=e(args.out)))
        return
    with ui.status(_("Sending to the Flipper over USB…")):
        offset = push_vault(blob, args.port)
    ui.ok(_("Sent to the Flipper. Open VaultFlipper and unlock with your PIN."))
    report_clock(offset, codes)


def report_clock(offset: int | None, codes: int) -> None:
    if not codes:
        return
    if offset is None:
        ui.warn(_("The Flipper clock is not set, so 2FA codes would be wrong. Connect qFlipper once to set it, then sync again."))
    else:
        ui.ok(_("Flipper clock: {tz} – 2FA codes use it. After a daylight saving change, sync again or set the time zone on the Flipper.", tz=f"[value]{format_offset(offset)}[/]"))


# --- commands -------------------------------------------------------------------


def cmd_account_add(args) -> None:
    cfg = load_config()
    check_name(args.name)
    if any(a["name"] == args.name for a in cfg["accounts"]):
        raise SystemExit(_("Account '{name}' already exists.", name=args.name))
    acc = Account(
        name=args.name,
        server=args.server.rstrip("/"),
        email=args.email or "",
        folders=args.folder or [],
        collections=args.collection or [],
        favorites_only=args.favorites_only,
        include_orgs=not args.no_orgs,
        include_totp=not args.no_totp,
        login=args.login,
        sso_identifier=args.sso_identifier or "",
    )
    cfg["accounts"].append(asdict(acc))
    save_config(cfg)
    ui.ok(_("Added [value]{name}[/] ({server}). Next: [key]vaultflipper login {name}[/]", name=e(acc.name), server=e(acc.server)))


def account_table(accs: list[Account], with_status: bool) -> None:
    t = ui.table(_("Account"), _("Server"), _("Sign-in"), _("Status"), _("Filter"))
    for a in accs:
        st = ""
        if with_status:
            try:
                raw = BwClient(a, config_dir()).status().get("status", "?")
            except BwError:
                raw = "?"
            st = {"locked": f"[ok]{_('logged in')}[/]", "unlocked": f"[ok]{_('logged in')}[/]", "unauthenticated": f"[fail]{_('not logged in')}[/]"}.get(raw, raw)
        flt = []
        if a.folders:
            flt.append(_("folders") + ": " + ", ".join(a.folders))
        if a.collections:
            flt.append(_("collections") + ": " + ", ".join(a.collections))
        if a.favorites_only:
            flt.append(_("favorites only"))
        if not a.include_orgs:
            flt.append(_("no organizations"))
        if not a.include_totp:
            flt.append(_("no 2FA codes"))
        t.add_row(f"[value]{e(a.name)}[/]", e(a.server.removeprefix("https://")), login_label(a.login), st, e("; ".join(flt)) or "[hint]–[/]")
    ui.console.print(t)


def cmd_account_list(args) -> None:
    cfg = load_config()
    accs = accounts_from(cfg)
    if not accs:
        ui.warn(_("No accounts yet. Add one: vaultflipper account add NAME --server URL"))
    else:
        account_table(accs, with_status=not args.offline)
    pk = cfg.get("device_pubkey")
    ui.console.print()
    if pk:
        ui.ok(_("Paired Flipper: {fp}", fp=f"[value]{vf.fingerprint(bytes.fromhex(pk))}[/]"))
    else:
        ui.warn(_("No Flipper paired yet. Run: vaultflipper pair"))


def cmd_account_remove(args) -> None:
    cfg = load_config()
    before = len(cfg["accounts"])
    cfg["accounts"] = [a for a in cfg["accounts"] if a["name"] != args.name]
    if len(cfg["accounts"]) == before:
        raise SystemExit(_("Account '{name}' not found.", name=args.name))
    save_config(cfg)
    gone = Account(name=args.name, server="")
    if gone.appdata(config_dir()).is_dir():
        try:  # do not leave a signed-in bw behind (refresh token, API key)
            BwClient(gone, config_dir()).logout()
        except (BwError, OSError, ValueError):
            pass
    ui.ok(_("Removed [value]{name}[/] and signed it out (bw data stays in {path}).", name=e(args.name), path=e(config_dir() / "bw" / args.name)))


def do_login(cfg: dict, acc: Account) -> bool:
    if acc.login == "sso" and not acc.sso_identifier:
        found = server_info(acc.server)
        if found and found[0] == "Vaultwarden":
            acc.sso_identifier = "vaultwarden"  # Vaultwarden's fixed SSO identifier
            update_account(cfg, acc)
    ui.info(_("Signing in to [value]{name}[/] with {method}", name=e(acc.name), method=login_label(acc.login)))
    if acc.login == "password":
        ui.hint(_("bw asks for your master password (and 2FA code)."))
    good = BwClient(acc, config_dir()).login()
    (ui.ok if good else ui.fail)(_("Signed in.") if good else _("Sign-in did not complete."))
    return good


def cmd_login(args) -> None:
    cfg = load_config()
    (acc,) = accounts_from(cfg, [args.name])
    if args.method:
        acc.login = args.method
        if args.sso_identifier is not None:
            acc.sso_identifier = args.sso_identifier
        update_account(cfg, acc)
    if not do_login(cfg, acc):
        raise SystemExit(1)


def cmd_pair(args) -> None:
    cfg = load_config()
    if args.pubkey or args.file:
        text = args.pubkey or Path(args.file).read_text().strip()[:64]
        try:
            pk = bytes.fromhex(text)
        except ValueError:
            raise SystemExit(_("Device key must be 32 bytes (64 hex characters).")) from None
    else:
        with ui.status(_("Reading the device key from the Flipper…")):
            pk = read_device_pubkey(args.port)
    if len(pk) != 32:
        raise SystemExit(_("Device key must be 32 bytes (64 hex characters)."))
    ui.info(_("Device fingerprint: {fp}", fp=f"[accent]{vf.fingerprint(pk)}[/]"))
    ui.hint(_("VaultFlipper shows the same fingerprint on its start screen and under About."))
    if not args.yes and not ui.ask_yes(_("Does it match?"), default=False):
        raise SystemExit(_("Cancelled."))
    cfg["device_pubkey"] = pk.hex()
    save_config(cfg)
    ui.ok(_("Paired."))


def collect(accs: list[Account], interactive: bool) -> list[vf.Entry]:
    entries: list[vf.Entry] = []
    failed: list[str] = []
    for acc in accs:
        ui.console.print()
        client = BwClient(acc, config_dir())
        try:
            client.unlock()
            with ui.status(_("Fetching logins from {name}…", name=e(acc.name))):
                got = client.fetch()
            ui.ok(_("{name}: {n} logins", name=f"[value]{e(acc.name)}[/]", n=len(got)))
            entries += got
        except BwError as ex:
            ui.fail(e(ex))
            failed.append(acc.name)
        finally:
            try:
                client.lock()
            except BwError:
                pass
    if failed:
        if len(failed) == len(accs):
            raise SystemExit(_("No account could be read – nothing was sent to the Flipper."))
        names = ", ".join(failed)
        if interactive and not ui.ask_yes(_("Continue without {names}? Their logins will be missing on the Flipper.", names=e(names)), default=True):
            raise SystemExit(_("Cancelled."))
        if not interactive:
            ui.warn(_("Continuing without {names}.", names=e(names)))
    return entries


def cmd_sync(args) -> None:
    cfg = load_config()
    accs = accounts_from(cfg, args.account)
    if not accs:
        raise SystemExit(_("No accounts configured. Run: vaultflipper setup"))
    if not args.dry_run:
        device_pubkey(cfg)  # fail early when not paired
    entries = collect(accs, interactive=sys.stdin.isatty())
    seal_and_deliver(entries, cfg, args)


def cmd_build(args) -> None:
    cfg = load_config()
    entries: list[vf.Entry] = []
    for spec in args.export:
        name, _sep, path = spec.partition("=")
        if not path:
            raise SystemExit(_("--export expects NAME=export.json"))
        entries += entries_from_export(Account(name=name, server=f"export:{name}"), Path(path))
    seal_and_deliver(entries, cfg, args)


def cmd_push(args) -> None:
    with ui.status(_("Sending to the Flipper over USB…")):
        offset = push_vault(Path(args.file).read_bytes(), args.port)
    ui.ok(_("Sent."))
    report_clock(offset, 1)


def compare_typetest(got: str) -> list[tuple[str, str]]:
    """Returns (expected, received) pairs that differ."""
    diffs: list[tuple[str, str]] = []
    sm = difflib.SequenceMatcher(a=TYPETEST, b=got, autojunk=False)
    for op, a1, a2, b1, b2 in sm.get_opcodes():
        if op == "equal":
            continue
        exp, rec = TYPETEST[a1:a2], got[b1:b2]
        if op == "replace" and len(exp) == len(rec):
            diffs += list(zip(exp, rec))
        else:
            diffs.append((exp or "∅", rec or "∅"))
    return diffs


def cmd_typetest(args) -> None:
    ui.banner(_("Typing test"), _("Checks that every character arrives correctly"))
    ui.info(_("Keep [key]this terminal[/] in front."))
    ui.info(_("On the Flipper: VaultFlipper > [key]Keyboard[/] – pick the layout of this computer."))
    ui.info(_("Then choose [key]Typing test[/]. The Flipper types all characters and presses Enter."))
    ui.console.print()
    got = ui.ask(_("Waiting for the Flipper"))
    diffs = compare_typetest(got)
    if not diffs:
        ui.ok(_("All {n} characters arrived correctly. The layout fits.", n=len(TYPETEST)))
        return
    ui.fail(_("{n} characters differ. Try another layout on the Flipper:", n=len(diffs)))
    t = ui.table(_("expected"), _("received"))
    for exp, rec in diffs:
        t.add_row(f"[ok]{e(exp)}[/]", f"[fail]{e(rec)}[/]")
    ui.console.print(t)
    raise SystemExit(1)


# --- setup wizard -----------------------------------------------------------------


def bw_version() -> str:
    try:
        out = subprocess.run([bw_binary(), "--version"], capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        out = ""
    return out or "?"


def add_account_interactive(cfg: dict) -> Account:
    taken = {a["name"] for a in cfg["accounts"]}
    default = _("Personal") if not taken else ""
    while True:
        name = ui.ask(_("Name for this account (shown on the Flipper)"), default)
        if not NAME_RE.match(name):
            ui.warn(_("Account names may use letters, digits, space, dot, dash and underscore (max. 32)."))
        elif name in taken:
            ui.warn(_("Account '{name}' already exists.", name=e(name)))
        else:
            break
    options = [f"{label} [hint]({url.removeprefix('https://')})[/]" for label, url in SERVERS]
    options.append(_("Self-hosted (Vaultwarden or Bitwarden)"))
    choice = ui.choose(_("Where is this vault hosted?"), options)
    kind = ""
    if choice <= len(SERVERS):
        server = SERVERS[choice - 1][1]
    else:
        while True:
            server = ui.ask(_("Server URL, e.g. https://vault.example.com")).rstrip("/")
            if not server.startswith(("https://", "http://")):
                ui.warn(_("Please enter a URL starting with https://"))
                continue
            with ui.status(_("Checking {server}…", server=e(server))):
                found = server_info(server)
            if found:
                kind = found[0]
                ui.ok(_("{name} {version} reachable.", name=f"[value]{e(found[0])}[/]", version=e(found[1])))
                break
            ui.warn(_("No Bitwarden or Vaultwarden server answered at {server}.", server=e(server)))
            if ui.ask_yes(_("Use it anyway?"), default=False):
                break
    method = LOGIN_METHODS[
        ui.choose(
            _("How do you sign in to this vault?"),
            [_("Email and master password"), _("Single sign-on (SSO, company login in the browser)"), _("API key (advanced)")],
        )
        - 1
    ]
    email = ui.ask(_("Email address (optional)")) if method == "password" else ""
    sso_id = ""
    if method == "sso":
        # Vaultwarden has a single SSO provider and uses the fixed identifier "vaultwarden".
        sso_id = ui.ask(_("SSO identifier (optional, leave empty if unsure)"), "vaultwarden" if kind == "Vaultwarden" else "")
    acc = Account(name=name, server=server, email=email, login=method, sso_identifier=sso_id)
    cfg["accounts"].append(asdict(acc))
    save_config(cfg)
    return acc


def cmd_setup(args) -> None:
    total = 5
    ui.banner(_("VaultFlipper setup"), _("Accounts · pairing · keyboard · first sync – about two minutes"))

    ui.step(1, total, _("Bitwarden CLI"))
    bw_binary()
    ui.ok(f"bw [value]{e(bw_version())}[/]")

    ui.step(2, total, _("Accounts"))
    cfg = load_config()
    accs = accounts_from(cfg)
    if accs:
        account_table(accs, with_status=True)
    if not accs or ui.ask_yes(_("Add another account?"), default=False):
        while True:
            acc = add_account_interactive(cfg)
            do_login(cfg, acc)
            if not ui.ask_yes(_("Add another account?"), default=False):
                break
    for a in accounts_from(cfg):
        if BwClient(a, config_dir()).status().get("status") != "unauthenticated":
            continue
        ui.warn(_("[value]{name}[/] is not logged in.", name=e(a.name)))
        choice = ui.choose(
            _("How do you sign in to {name}?", name=e(a.name)),
            [_("Email and master password"), _("Single sign-on (SSO, company login in the browser)"), _("API key (advanced)"), _("Skip for now")],
            default=LOGIN_METHODS.index(a.login) + 1,
        )
        if choice > len(LOGIN_METHODS):
            continue
        a.login = LOGIN_METHODS[choice - 1]
        update_account(cfg, a)
        do_login(cfg, a)

    ui.step(3, total, _("Pair your Flipper"))
    ui.info(_("Connect the Flipper via USB, open [key]Apps > Tools > VaultFlipper[/] once, then close the app and qFlipper."))
    ui.ask(_("Press Enter when ready"))
    with ui.status(_("Reading the device key from the Flipper…")):
        pk = read_device_pubkey(args.port)
    fp = vf.fingerprint(pk)
    if cfg.get("device_pubkey") == pk.hex():
        ui.ok(_("Already paired with this Flipper ({fp}).", fp=f"[value]{fp}[/]"))
    else:
        ui.info(_("Device fingerprint: {fp}", fp=f"[accent]{fp}[/]"))
        if not ui.ask_yes(_("Does the Flipper show the same fingerprint?"), default=True):
            raise SystemExit(_("Cancelled."))
        cfg["device_pubkey"] = pk.hex()
        save_config(cfg)
        ui.ok(_("Paired."))

    ui.step(4, total, _("Keyboard layout"))
    detected = hostlayout.detect()
    if detected:
        ui.ok(_("This computer uses [value]{layout}[/].", layout=detected))
    layout = ui.ask(_("Default layout for the Flipper"), cfg.get("layout") or detected or "en-US")
    cfg["layout"] = layout
    save_config(cfg)
    ui.hint(_("You can switch layouts on the Flipper any time (Settings > Keyboard layout)."))

    ui.step(5, total, _("Sync"))
    if ui.ask_yes(_("Sync now?"), default=True):
        cmd_sync(argparse.Namespace(account=None, out=None, port=args.port, layout=None, dry_run=False))

    ui.console.print()
    ui.banner(_("All set"), "")
    ui.info(_("On the Flipper: [key]Apps > Tools > VaultFlipper[/], enter your PIN."))
    ui.info(_("While unlocked, the Flipper is a USB keyboard. On a Mac the Keyboard Setup Assistant appears once: click Continue, then choose [key]Mac keyboard setup[/] on the Flipper."))
    ui.info(_("Check the layout: [key]vaultflipper typetest[/]"))
    ui.info(_("Update the Flipper later: [key]vaultflipper sync[/]"))


def cmd_status(args) -> None:
    cfg = load_config()
    ui.banner("VaultFlipper", _("Status"))
    try:
        ui.ok(f"bw [value]{e(bw_version())}[/]")
    except BwError as ex:
        ui.fail(e(ex))
    accs = accounts_from(cfg)
    if accs:
        ui.console.print()
        account_table(accs, with_status=True)
        ui.console.print()
    else:
        ui.fail(_("No accounts yet. Run: vaultflipper setup"))
    paired = cfg.get("device_pubkey")
    if not paired:
        ui.fail(_("No Flipper paired yet. Run: vaultflipper pair"))
        return
    ui.ok(_("Paired Flipper: {fp}", fp=f"[value]{vf.fingerprint(bytes.fromhex(paired))}[/]"))
    try:
        with ui.status(_("Looking for the Flipper…")):
            pk = read_device_pubkey(args.port)
    except FlipperError:
        ui.info(_("No Flipper connected (or VaultFlipper/qFlipper is using it)."))
    else:
        if pk.hex() == paired:
            ui.ok(_("The connected Flipper is the paired one."))
        else:
            ui.fail(_("The connected Flipper ({fp}) is not the paired one. Run: vaultflipper pair", fp=vf.fingerprint(pk)))
    ui.info(_("Default layout: {layout}", layout=f"[value]{e(default_layout(cfg))}[/]"))


# --- parser -------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vaultflipper", description=_("Companion for VaultFlipper: Bitwarden/Vaultwarden logins to your Flipper Zero."))
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("setup", help=_("Guided setup: accounts, pairing, layout, first sync"))
    a.add_argument("--port", help=_("serial port of the Flipper (default: auto)"))
    a.set_defaults(func=cmd_setup)

    a = sub.add_parser("status", help=_("Check bw, accounts and the paired Flipper"))
    a.add_argument("--port", help=_("serial port of the Flipper (default: auto)"))
    a.set_defaults(func=cmd_status)

    a = sub.add_parser("sync", help=_("Fetch all accounts, encrypt and send to the Flipper"))
    a.add_argument("--account", action="append", help=_("only these accounts (repeatable)"))

    def deliver_opts(x):
        x.add_argument("--out", help=_("write a file instead of sending over USB"))
        x.add_argument("--port", help=_("serial port of the Flipper (default: auto)"))
        x.add_argument("--layout", help=_("default keyboard layout, e.g. de-DE, de-DE-mac, en-US (default: detected; can be changed on the Flipper)"))
        x.add_argument("--dry-run", action="store_true", help=_("only list what would be synced"))

    deliver_opts(a)
    a.set_defaults(func=cmd_sync)

    acc = sub.add_parser("account", help=_("Manage accounts")).add_subparsers(dest="acmd", required=True)
    a = acc.add_parser("add", help=_("Add an account or server"))
    a.add_argument("name")
    a.add_argument("--server", required=True, help=_("e.g. https://vault.example.com or https://vault.bitwarden.eu"))
    a.add_argument("--email")
    a.add_argument("--login", choices=LOGIN_METHODS, default="password", help=_("how you sign in (default: password)"))
    a.add_argument("--sso-identifier", help=_("organization identifier for SSO (optional)"))
    a.add_argument("--folder", action="append", help=_("only these folders (repeatable)"))
    a.add_argument("--collection", action="append", help=_("only these collections, 'Org/Collection' or 'Collection' (repeatable)"))
    a.add_argument("--favorites-only", action="store_true", help=_("only favorites"))
    a.add_argument("--no-orgs", action="store_true", help=_("skip shared organization items"))
    a.add_argument("--no-totp", action="store_true", help=_("leave out 2FA secrets (no codes on the Flipper)"))
    a.set_defaults(func=cmd_account_add)
    a = acc.add_parser("list", help=_("Show accounts"))
    a.add_argument("--offline", action="store_true", help=_("do not query bw status"))
    a.set_defaults(func=cmd_account_list)
    a = acc.add_parser("remove", help=_("Remove an account from the configuration"))
    a.add_argument("name")
    a.set_defaults(func=cmd_account_remove)

    a = sub.add_parser("login", help=_("Log in to an account (interactive, via bw)"))
    a.add_argument("name")
    g = a.add_mutually_exclusive_group()
    g.add_argument("--sso", dest="method", action="store_const", const="sso", help=_("sign in with single sign-on and remember it"))
    g.add_argument("--apikey", dest="method", action="store_const", const="apikey", help=_("sign in with an API key and remember it"))
    g.add_argument("--password", dest="method", action="store_const", const="password", help=_("sign in with email and master password and remember it"))
    a.add_argument("--sso-identifier", help=_("organization identifier for SSO (optional)"))
    a.set_defaults(func=cmd_login)

    a = sub.add_parser("pair", help=_("Pair with your Flipper (reads its device key)"))
    a.add_argument("--port", help=_("serial port of the Flipper (default: auto)"))
    a.add_argument("--pubkey", help=_("device key as hex instead of USB"))
    a.add_argument("--file", help=_("device.pub file instead of USB"))
    a.add_argument("--yes", action="store_true", help=_("do not ask for confirmation"))
    a.set_defaults(func=cmd_pair)

    a = sub.add_parser("typetest", help=_("Check which characters arrive correctly with the chosen keyboard layout"))
    a.set_defaults(func=cmd_typetest)

    a = sub.add_parser("build", help=_("Build from unencrypted Bitwarden JSON exports (offline/testing)"))
    a.add_argument("--export", action="append", required=True, metavar="NAME=FILE")
    deliver_opts(a)
    a.set_defaults(func=cmd_build)

    a = sub.add_parser("push", help=_("Send a finished .vfv file to the Flipper"))
    a.add_argument("file")
    a.add_argument("--port", help=_("serial port of the Flipper (default: auto)"))
    a.set_defaults(func=cmd_push)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except (BwError, FlipperError, vf.FormatError) as ex:
        ui.error(str(ex))
        return 1
    except (OSError, ValueError) as ex:  # missing files, a busy serial port, broken JSON
        ui.error(str(ex))
        return 1
    except SystemExit as ex:
        if isinstance(ex.code, str):
            ui.error(ex.code)
            return 1
        raise
    except (KeyboardInterrupt, EOFError):
        ui.console.print()
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
