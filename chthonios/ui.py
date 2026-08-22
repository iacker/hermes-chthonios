"""Tiny ANSI presentation layer — zero dependencies.

Chthonios ships with a single runtime dependency (cryptography). We keep it
that way: no rich, no colorama. Just raw ANSI, gated on an interactive TTY and
the NO_COLOR convention (https://no-color.org).
"""
from __future__ import annotations
import os
import sys

# --- capability detection -------------------------------------------------

def _supports_color(stream) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("CHTHONIOS_FORCE_COLOR"):
        return True
    return bool(getattr(stream, "isatty", lambda: False)())


_COLOR = _supports_color(sys.stdout)

# --- palette (cyan -> violet brand gradient endpoints) --------------------

_CODES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "cyan": "\033[38;5;44m",
    "violet": "\033[38;5;135m",
    "green": "\033[38;5;42m",
    "red": "\033[38;5;203m",
    "amber": "\033[38;5;215m",
    "grey": "\033[38;5;245m",
    "white": "\033[97m",
}


def c(text: str, *styles: str) -> str:
    if not _COLOR:
        return text
    prefix = "".join(_CODES.get(s, "") for s in styles)
    return f"{prefix}{text}{_CODES['reset']}" if prefix else text


# --- glyphs (ASCII fallback when not a TTY) -------------------------------

class G:
    lock = "\u25c6"       # ◆ solid diamond = sealed
    unlock = "\u25c7"      # ◇ hollow diamond = open
    check = "\u2713"       # ✓
    cross = "\u2717"       # ✗
    key = "\u26bf"         # ⚿ (falls back cleanly)
    chip = "\u25c8"        # ◈
    arrow = "\u2192"       # →


# --- box drawing ----------------------------------------------------------

def _visible_len(s: str) -> int:
    """Length of s ignoring ANSI escapes and counting wide glyphs as 2."""
    import re
    stripped = re.sub(r"\033\[[0-9;]*m", "", s)
    width = 0
    for ch in stripped:
        width += 2 if ord(ch) > 0x2500 and ord(ch) not in (0x2714, 0x2718, 0x25c6, 0x2192) else 1
    return width


def box(title: str, lines: list[str], accent: str = "cyan") -> str:
    body = list(lines)
    inner = max([_visible_len(title)] + [_visible_len(l) for l in body]) + 2
    top = c("\u256d" + "\u2500" * inner + "\u256e", accent)
    bot = c("\u2570" + "\u2500" * inner + "\u256f", accent)
    bar = c("\u2502", accent)
    out = [top]
    tpad = inner - _visible_len(title) - 1
    out.append(f"{bar} {c(title, 'bold')}{' ' * tpad}{bar}")
    if body:
        out.append(c("\u251c" + "\u2500" * inner + "\u2524", accent))
    for l in body:
        pad = inner - _visible_len(l) - 1
        out.append(f"{bar} {l}{' ' * pad}{bar}")
    out.append(bot)
    return "\n".join(out)


def ok(msg: str) -> str:
    return f"{c(G.check, 'green')} {msg}"


def fail(msg: str) -> str:
    return f"{c(G.cross, 'red')} {msg}"


def sealed(msg: str) -> str:
    return f"{c(G.lock, 'violet')} {msg}"


def opened(msg: str) -> str:
    return f"{c(G.unlock, 'green')} {msg}"
