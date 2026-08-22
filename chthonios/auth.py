"""macOS Touch ID / passphrase prompt helpers.

Touch ID is gated through the system `bioutil`/LocalAuthentication stack. We
shell out to a tiny osascript/`security` fallback because Hermes plugins and
CLI run outside a signed app bundle where LAContext is awkward. The passphrase
is always the cryptographic root of trust; Touch ID only unlocks a passphrase
that Chthonios stored in the login keychain when the user opted in.
"""
from __future__ import annotations

import getpass
import subprocess
import sys

KEYCHAIN_SERVICE = "hermes-chthonios"


def prompt_passphrase(prompt: str = "Chthonios passphrase: ", confirm: bool = False) -> str:
    pw = getpass.getpass(prompt)
    if confirm:
        again = getpass.getpass("Confirm passphrase: ")
        if pw != again:
            print("Passphrases do not match.", file=sys.stderr)
            sys.exit(2)
    return pw


def touchid_available() -> bool:
    if sys.platform != "darwin":
        return False
    try:
        out = subprocess.run(
            ["bioutil", "-r"], capture_output=True, text=True, timeout=5
        )
        return "Touch ID functionality: 1" in out.stdout or out.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def touchid_authenticate(reason: str = "unlock a sealed Hermes profile") -> bool:
    """Prompt for Touch ID. Returns True on success.

    Uses osascript's `do shell script ... with administrator privileges` as a
    system-auth gate that honours Touch ID when enabled for sudo, falling back
    to the login password prompt. Best-effort; the passphrase remains the real
    guard for the ciphertext.
    """
    if sys.platform != "darwin":
        return False
    script = (
        'do shell script "true" with prompt '
        f'"Chthonios: {reason}" with administrator privileges'
    )
    try:
        r = subprocess.run(
            ["osascript", "-e", script], capture_output=True, text=True, timeout=60
        )
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


# ---- keychain-backed passphrase (opt-in convenience) ----

def keychain_store(profile: str, passphrase: str) -> bool:
    if sys.platform != "darwin":
        return False
    try:
        subprocess.run(
            ["security", "add-generic-password", "-U",
             "-s", KEYCHAIN_SERVICE, "-a", profile, "-w", passphrase],
            capture_output=True, check=True, timeout=10)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def keychain_fetch(profile: str) -> str | None:
    if sys.platform != "darwin":
        return None
    try:
        r = subprocess.run(
            ["security", "find-generic-password",
             "-s", KEYCHAIN_SERVICE, "-a", profile, "-w"],
            capture_output=True, text=True, check=True, timeout=10)
        return r.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def keychain_delete(profile: str) -> bool:
    if sys.platform != "darwin":
        return False
    try:
        subprocess.run(
            ["security", "delete-generic-password",
             "-s", KEYCHAIN_SERVICE, "-a", profile],
            capture_output=True, check=True, timeout=10)
        return True
    except (OSError, subprocess.SubprocessError):
        return False
