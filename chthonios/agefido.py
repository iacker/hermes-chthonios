"""
FIDO2 / YubiKey key source for Chthonios, via `age` + age-plugin-fido2-hmac.

Design property that matters here:

  * SEALING (encrypt) needs only the *recipient* string — no touch, no key.
    So an unattended agent can lock a profile on its own.
  * UNSEALING (decrypt) needs the FIDO2 token physically present + a touch
    (and optionally a PIN). Nothing and no one can decrypt without the key.

We shell out to `age` because the reference plugin is the audited,
maintained implementation of the hmac-secret ceremony. Chthonios stores the
NON-secret recipient in the profile state; the identity (which merely wraps a
credential to the token, still useless without the token) is written to a
0600 file beside the profile.

Enrollment is interactive (PIN + touch) and therefore must run in a real TTY —
i.e. the user's own terminal, never the agent. `enroll_command()` returns the
exact command to run.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

PLUGIN = "age-plugin-fido2-hmac"


class AgeError(Exception):
    pass


def _age_bin() -> str:
    exe = shutil.which("age")
    if not exe:
        raise AgeError("`age` not found in PATH (brew install age)")
    return exe


def available() -> bool:
    return bool(shutil.which("age") and shutil.which(PLUGIN))


def enroll_command(recipient_out: Path, identity_out: Path) -> str:
    """The interactive command the USER runs in their own terminal to bind a
    YubiKey. Produces a recipient line and an identity file.

    We keep the identity (needed for decryption) and the recipient (needed for
    encryption) separate so sealing never needs the identity file.
    """
    return (
        f"{PLUGIN} -g "
        f"| tee >(grep '^age1' > {recipient_out}) "
        f"> {identity_out} && chmod 600 {identity_out} {recipient_out}"
    )


def encrypt_to_recipient(plaintext: bytes, recipient: str) -> bytes:
    """Encrypt with age to a fido2-hmac recipient. No token needed."""
    if not recipient.startswith("age1"):
        raise AgeError(f"not an age recipient: {recipient[:12]}...")
    proc = subprocess.run(
        [_age_bin(), "-r", recipient, "-o", "-"],
        input=plaintext, capture_output=True,
    )
    if proc.returncode != 0:
        raise AgeError(f"age encrypt failed: {proc.stderr.decode(errors='replace')}")
    return proc.stdout


def decrypt_with_identity(ciphertext: bytes, identity_file: Path) -> bytes:
    """Decrypt with age using the fido2 identity file.

    REQUIRES the YubiKey physically present + a touch. This blocks on the
    device and therefore needs a TTY; call it from the user's terminal.
    """
    if not Path(identity_file).exists():
        raise AgeError(f"identity file missing: {identity_file}")
    proc = subprocess.run(
        [_age_bin(), "-d", "-i", str(identity_file), "-o", "-"],
        input=ciphertext, capture_output=True,
    )
    if proc.returncode != 0:
        raise AgeError(
            "age decrypt failed (key unplugged, wrong token, or cancelled): "
            + proc.stderr.decode(errors="replace"))
    return proc.stdout


def decrypt_command(sealed_file: Path, out_file: Path, identity_file: Path) -> str:
    """The exact command the user runs in their terminal to unseal with touch."""
    return (f"{_age_bin()} -d -i {identity_file} "
            f"-o {out_file} {sealed_file}")
