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
import time
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


AGE_MAGIC = b"age-encryption.org/v1"


def is_age_ciphertext(raw: bytes) -> bool:
    """True if `raw` begins with the age v1 header. Lets Chthonios validate a
    FIDO2 seal's structure without the token (decryption still needs the key)."""
    return raw[:len(AGE_MAGIC)] == AGE_MAGIC


def enroll_command(recipient_out: Path, identity_out: Path) -> str:
    """The interactive command the USER runs in their own terminal to bind a
    YubiKey. Produces an identity file (with the credential) and extracts the
    age recipient (the `# public key: age1...` line) to a separate file.

    Sealing later reads only the recipient; decryption reads the identity.
    """
    return (
        f"{PLUGIN} -g > {identity_out} "
        f"&& grep 'public key:' {identity_out} | sed 's/.*: //' > {recipient_out} "
        f"&& chmod 600 {identity_out} {recipient_out} "
        f"&& echo 'Enrolled. recipient -> {recipient_out}'"
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


def decrypt_with_identity(ciphertext: bytes, identity_file: Path,
                          pin: Optional[str] = None) -> bytes:
    """Decrypt with age using the fido2 identity file.

    REQUIRES the YubiKey physically present + a touch.

    `age` reads the token's PIN from /dev/tty, so a GUI caller (no controlling
    terminal) fails with "device not configured". Passing `pin` runs age on a
    pty instead, which age treats as a terminal and reads the PIN from — that
    is the only way a UI can drive this. The touch still happens on the token,
    so the hardware guarantee is unchanged: the PIN authorises the key, it
    never leaves it.

    ponytail: pty only when a pin is supplied; plain pipes otherwise, which
    keeps the terminal path byte-identical to before.
    """
    if not Path(identity_file).exists():
        raise AgeError(f"identity file missing: {identity_file}")
    argv = [_age_bin(), "-d", "-i", str(identity_file), "-o", "-"]
    if pin is not None:
        return _run_on_pty(argv, ciphertext, pin)
    proc = subprocess.run(argv, input=ciphertext, capture_output=True)
    if proc.returncode != 0:
        raise AgeError(
            "age decrypt failed (key unplugged, wrong token, or cancelled): "
            + proc.stderr.decode(errors="replace"))
    return proc.stdout


def _run_on_pty(argv: list, ciphertext: bytes, pin: str) -> bytes:
    """Run age with a pty for its PIN prompt, ciphertext on a real pipe.

    stdout must stay a pipe: a pty would corrupt binary plaintext with newline
    translation, and echo the PIN back into it.
    """
    import pty
    import select

    master, slave = pty.openpty()
    proc = subprocess.Popen(
        argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=slave, close_fds=True,
    )
    os.close(slave)
    assert proc.stdin is not None and proc.stdout is not None
    try:
        proc.stdin.write(ciphertext)
        proc.stdin.close()
        prompted = False
        # The touch can take a while; the user has to physically reach the key.
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline and proc.poll() is None:
            ready, _, _ = select.select([master], [], [], 0.5)
            if not ready:
                continue
            try:
                chunk = os.read(master, 1024)
            except OSError:
                break
            if not prompted and b"PIN" in chunk:
                os.write(master, (pin + "\n").encode())
                prompted = True
        out = proc.stdout.read()
        if proc.wait() != 0:
            raise AgeError("age decrypt failed (wrong PIN, no touch, or key "
                           "unplugged)")
        return out
    finally:
        if proc.poll() is None:
            proc.kill()
        os.close(master)


def decrypt_command(sealed_file: Path, out_file: Path, identity_file: Path) -> str:
    """The exact command the user runs in their terminal to unseal with touch."""
    return (f"{_age_bin()} -d -i {identity_file} "
            f"-o {out_file} {sealed_file}")
