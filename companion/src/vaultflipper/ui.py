# SPDX-FileCopyrightText: 2026 Sven Würth
# SPDX-License-Identifier: MIT
"""Terminal output: colors, steps, prompts and spinners (via rich).

Colors are switched off automatically when the output is not a terminal or
when NO_COLOR is set.
"""

from __future__ import annotations

import getpass

from rich.console import Console
from rich.markup import escape
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme

from .i18n import _

THEME = Theme(
    {
        "accent": "bold #FF8200",
        "ok": "bold green",
        "warn": "bold yellow",
        "fail": "bold red",
        "hint": "dim",
        "key": "bold cyan",
        "value": "bold",
    }
)

console = Console(theme=THEME, highlight=False)
err = Console(theme=THEME, highlight=False, stderr=True)
YES = ("y", "yes", "j", "ja")


def e(text: object) -> str:
    """Escape user data so brackets are never read as markup."""
    return escape(str(text))


def banner(title: str, subtitle: str = "") -> None:
    body = f"[accent]{title}[/]" + (f"\n[hint]{subtitle}[/]" if subtitle else "")
    console.print(Panel.fit(body, border_style="#FF8200", padding=(0, 2)))


def step(n: int, total: int, title: str) -> None:
    console.print()
    console.rule(f"[accent]{n}/{total}[/]  [bold]{title}[/]", align="left", style="#FF8200")


def _line(icon: str, msg: str, indent: int = 2) -> None:
    """Icon plus text; wrapped lines stay aligned under the text."""
    grid = Table.grid(padding=(0, 1))
    grid.add_column(width=1, no_wrap=True)
    grid.add_column(overflow="fold")
    grid.add_row(icon, msg)
    console.print(Padding(grid, (0, 0, 0, indent), expand=False))


def ok(msg: str) -> None:
    _line("[ok]✓[/]", msg)


def warn(msg: str) -> None:
    _line("[warn]![/]", msg)


def fail(msg: str) -> None:
    _line("[fail]✗[/]", msg)


def info(msg: str) -> None:
    _line("[accent]•[/]", msg)


def hint(msg: str) -> None:
    _line(" ", f"[hint]{msg}[/]")


def error(msg: str) -> None:
    err.print(f"[fail]{_('Error')}:[/] {e(msg)}")


def ask(prompt: str, default: str = "") -> str:
    shown = f"  [key]?[/] {prompt}" + (f" [hint]({e(default)})[/]" if default else "") + " "
    return console.input(shown).strip() or default


def ask_yes(prompt: str, default: bool) -> bool:
    hint_text = _("[Y/n]") if default else _("[y/N]")
    answer = console.input(f"  [key]?[/] {prompt} [hint]{e(hint_text)}[/] ").strip().lower()
    return default if not answer else answer in YES


def choose(prompt: str, options: list[str], default: int = 1) -> int:
    """Numbered menu; returns the 1-based choice."""
    console.print(f"  [key]?[/] {prompt}")
    for i, label in enumerate(options, 1):
        console.print(f"     [accent]{i}[/]  {label}")
    while True:
        raw = ask(_("Choice"), str(default))
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return int(raw)
        warn(_("Please enter a number from 1 to {n}.", n=len(options)))


def secret(prompt: str) -> str:
    console.print(f"  [key]?[/] {prompt}", end="")
    return getpass.getpass(" ")


def table(*columns: str) -> Table:
    t = Table(box=None, padding=(0, 2), show_edge=False, header_style="hint")
    for c in columns:
        t.add_column(c)
    return t


def status(msg: str):
    return console.status(f"[accent]{msg}[/]", spinner="dots", spinner_style="#FF8200")
