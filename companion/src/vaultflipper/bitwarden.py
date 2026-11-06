# SPDX-FileCopyrightText: 2026 Sven Würth
# SPDX-License-Identifier: MIT
"""Fetch logins from Bitwarden/Vaultwarden through the official `bw` CLI.

Each account gets its own BITWARDENCLI_APPDATA_DIR, so several servers and
accounts work side by side. You type your master password into `bw` itself;
this tool only ever sees the session key, and keeps it in memory.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from . import ui
from .i18n import _
from .vfformat import Entry

LOGIN_TYPE = 1
LOGIN_METHODS = ("password", "sso", "apikey")


class BwError(Exception):
    pass


@dataclass
class Account:
    name: str
    server: str
    email: str = ""
    folders: list[str] = field(default_factory=list)  # empty = all
    collections: list[str] = field(default_factory=list)  # empty = all ("Org/Collection" or "Collection")
    favorites_only: bool = False
    include_orgs: bool = True
    include_totp: bool = True  # 2FA secrets (TOTP) for codes on the Flipper
    login: str = "password"  # password | sso | apikey
    sso_identifier: str = ""  # optional organization identifier for SSO

    def appdata(self, base: Path) -> Path:
        return base / "bw" / self.name


def server_info(url: str) -> tuple[str, str] | None:
    """Name and version of a Bitwarden-compatible server, or None if unreachable."""
    try:
        req = urllib.request.Request(url.rstrip("/") + "/api/config", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=6) as resp:  # noqa: S310 (user-provided https URL)
            data = json.loads(resp.read(65536))
        name = (data.get("server") or {}).get("name") or "Bitwarden"
        return name, str(data.get("version") or "?")
    except (OSError, ValueError):
        return None


def bw_binary() -> str:
    path = shutil.which("bw")
    if not path:
        raise BwError(_("Bitwarden CLI `bw` not found (e.g. `brew install bitwarden-cli` or `npm i -g @bitwarden/cli`)."))
    return path


class BwClient:
    def __init__(self, account: Account, base: Path):
        self.account = account
        self.appdata = account.appdata(base)
        self.appdata.mkdir(parents=True, exist_ok=True)
        for d in (self.appdata.parent, self.appdata):
            os.chmod(d, 0o700)  # bw keeps the encrypted vault cache here
        self.session: str | None = None

    def _env(self) -> dict:
        env = dict(os.environ)
        env["BITWARDENCLI_APPDATA_DIR"] = str(self.appdata)
        env.pop("BW_SESSION", None)
        if self.session:
            env["BW_SESSION"] = self.session
        return env

    def _run(self, *args: str, interactive: bool = False) -> str:
        cmd = [bw_binary(), *args]
        if interactive:
            # prompts go to the terminal (bw writes them to stderr); stdout carries the session key
            res = subprocess.run(cmd, env=self._env(), stdout=subprocess.PIPE, text=True)
        else:
            # --nointeraction: an invalid session fails instead of prompting on the captured stderr
            res = subprocess.run([cmd[0], "--nointeraction", *args], env=self._env(), capture_output=True, text=True)
        if res.returncode != 0:
            err = "" if interactive else (res.stderr or "").strip()
            raise BwError(_("bw {cmd} failed ({name}): {err}", cmd=args[0], name=self.account.name, err=err))
        return res.stdout or ""

    def status(self) -> dict:
        return json.loads(self._run("status"))

    def configure_server(self) -> None:
        if self.status().get("status") == "unauthenticated":
            self._run("config", "server", self.account.server)

    def login(self) -> bool:
        """Interactive login. Password, 2FA and SSO happen in bw or the browser."""
        self.configure_server()
        method = self.account.login
        if method == "sso":
            args = ["login", "--sso"] + ([self.account.sso_identifier] if self.account.sso_identifier else [])
            ui.hint(_("Your browser opens for the company sign-in. Come back here afterwards."))
        elif method == "apikey":
            args = ["login", "--apikey"]
            ui.hint(_("bw asks for client_id and client_secret (web vault > Settings > Security > Keys)."))
        else:
            args = ["login"] + ([self.account.email] if self.account.email else [])
        subprocess.run([bw_binary(), *args], env=self._env(), check=False)
        return self.status().get("status") != "unauthenticated"

    def unlock(self) -> None:
        st = self.status()
        if st.get("status") == "unauthenticated":
            raise BwError(_("Account '{name}' is not logged in. Run: vaultflipper login {name}", name=self.account.name))
        ui.info(
            _(
                "Unlock [value]{name}[/] [hint]({email} @ {server})[/] – enter the master password:",
                name=ui.e(self.account.name),
                email=ui.e(st.get("userEmail", "?")),
                server=ui.e(st.get("serverUrl") or "bitwarden.com"),
            )
        )
        try:
            key = self._run("unlock", "--raw", interactive=True).strip()
        except BwError:
            if self.account.login == "sso":
                raise BwError(
                    _(
                        "Could not unlock '{name}'. SSO accounts need a master password for the Bitwarden CLI; accounts that only use trusted devices cannot be unlocked by bw.",
                        name=self.account.name,
                    )
                ) from None
            raise
        if not key:
            raise BwError(_("No session key for '{name}'", name=self.account.name))
        self.session = key

    def lock(self) -> None:
        if self.session:
            try:
                self._run("lock")
            finally:
                self.session = None

    def _list(self, what: str) -> list[dict]:
        return json.loads(self._run("list", what))

    def logout(self) -> None:
        if self.status().get("status") != "unauthenticated":
            self._run("logout")

    def fetch(self) -> list[Entry]:
        try:
            self._run("sync")
        except BwError as ex:  # offline: bw still has the copy from the last sync
            ui.warn(_("Could not reach the server for '{name}', using the last downloaded copy ({err}).", name=self.account.name, err=ex))
        items = self._list("items")
        folders = {f["id"]: f["name"] for f in self._list("folders") if f.get("id")}
        orgs = {o["id"]: o["name"] for o in self._list("organizations")}
        collections = {c["id"]: c for c in self._list("collections")}
        return items_to_entries(self.account, items, folders, orgs, collections)


def items_to_entries(
    account: Account,
    items: list[dict],
    folders: dict[str, str],
    orgs: dict[str, str],
    collections: dict[str, dict],
) -> list[Entry]:
    out: list[Entry] = []
    for it in items:
        if it.get("type") != LOGIN_TYPE or it.get("deletedDate"):
            continue
        if account.favorites_only and not it.get("favorite"):
            continue
        org_id = it.get("organizationId")
        if org_id:
            if not account.include_orgs:
                continue
            if account.folders and not account.collections:
                continue  # only --folder given: personal items only
            org = orgs.get(org_id, _("Organization"))
            cols = [collections[c]["name"] for c in it.get("collectionIds") or [] if c in collections]
            if account.collections:
                cols = [c for c in cols if c in account.collections or f"{org}/{c}" in account.collections]
                if not cols:
                    continue
            group = f"{org}/{cols[0]}" if cols else org
        else:
            if account.collections and not account.folders:
                continue  # only --collection given: organization items only
            folder = folders.get(it.get("folderId") or "", "")
            if account.folders and folder not in account.folders:
                continue
            group = folder or _("No folder")
        login = it.get("login") or {}
        uris = login.get("uris") or []
        out.append(
            Entry(
                account=account.name,
                group=group,
                name=it.get("name") or "",
                username=login.get("username") or "",
                password=login.get("password") or "",
                totp=(login.get("totp") or "") if account.include_totp else "",
                uri=(uris[0].get("uri") or "") if uris else "",
                source_id=f"{account.server}#{it.get('id', '')}",
            )
        )
    return out


def entries_from_export(account: Account, path: Path) -> list[Entry]:
    """Unencrypted Bitwarden JSON export (personal or organization)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("encrypted"):
        raise BwError(_("Encrypted exports are not supported - use the bw integration instead."))
    folders = {f["id"]: f["name"] for f in data.get("folders") or []}
    collections = {c["id"]: c for c in data.get("collections") or []}
    orgs = {c.get("organizationId"): _("Organization") for c in collections.values()}
    return items_to_entries(account, data.get("items") or [], folders, orgs, collections)
