"""
Chthonios Vault-token sealing.

The Hermes HashiCorp Vault secret source reads every API key from your Vault at
startup, but it needs one bootstrap credential in the environment first:
``VAULT_TOKEN``. That single token is the whole ballgame — with it, the 50+
keys in Vault are reachable; without it, nothing is. So instead of leaving it
in a shell profile or a plaintext file, Chthonios seals *that one token* behind
your YubiKey.

This collapses the attack surface from "N API keys sitting in .env" to "one
token, openable only with the hardware key + touch + PIN".

Flow:

    chthonios vault seal-token <profile>     # paste/pipe the token once -> sealed
    eval "$(chthonios vault env <profile>)"  # touch YubiKey -> exports VAULT_TOKEN

The sealed token lives at ``<profile>/.chthonios.vault-token`` (age FIDO2-hmac
ciphertext). ``env`` decrypts it in memory and prints a single
``export VAULT_TOKEN=...`` line to stdout — the token never lands on disk in
cleartext, exactly like ``ssh-agent`` or ``aws-vault exec``.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

from . import agefido, profiles

VAULT_TOKEN_SUFFIX = ".chthonios.vault-token"


class VaultTokenError(Exception):
    pass


def sealed_token_path(profile: str) -> Path:
    return profiles.profile_dir(profile) / VAULT_TOKEN_SUFFIX


def recipient_path(profile: str) -> Path:
    return profiles.profile_dir(profile) / ".chthonios.recipient"


def is_token_sealed(profile: str) -> bool:
    return sealed_token_path(profile).exists()


def _load_recipient(profile: str, explicit: Optional[str] = None) -> str:
    if explicit:
        return explicit.strip()
    rp = recipient_path(profile)
    if not rp.exists():
        raise VaultTokenError(
            f"no YubiKey recipient for profile '{profile}'. "
            f"Run `chthonios enroll-key {profile}` first."
        )
    rec = rp.read_text().strip()
    if not rec.startswith("age1"):
        raise VaultTokenError(f"invalid recipient in {rp}")
    return rec


def seal_token(profile: str, token: str, recipient: Optional[str] = None,
               *, overwrite: bool = False) -> Path:
    """Seal a Vault token to the profile's YubiKey recipient. No touch needed.

    Sealing (encrypt-to-recipient) never prompts for the hardware key — only
    *unsealing* does. Refuses to clobber an existing seal unless overwrite.
    """
    token = (token or "").strip()
    if not token:
        raise VaultTokenError("refusing to seal an empty token")
    out = sealed_token_path(profile)
    if out.exists() and not overwrite:
        raise VaultTokenError(
            f"already sealed: {out} (pass --force to replace)"
        )
    rec = _load_recipient(profile, recipient)
    ciphertext = agefido.encrypt_to_recipient(token.encode("utf-8"), rec)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_bytes(ciphertext)
    os.chmod(tmp, 0o600)
    os.replace(tmp, out)
    return out


def unseal_token(profile: str) -> str:
    """Decrypt the sealed Vault token in memory. Triggers YubiKey touch+PIN.

    Returns the token string. Never writes it to disk.
    """
    src = sealed_token_path(profile)
    if not src.exists():
        raise VaultTokenError(
            f"no sealed Vault token for profile '{profile}'. "
            f"Run `chthonios vault seal-token {profile}` first."
        )
    identity = profiles.identity_path(profile)
    if not identity.exists():
        raise VaultTokenError(
            f"no FIDO2 identity for profile '{profile}' ({identity}). "
            "The YubiKey that sealed this token is required to open it."
        )
    plaintext = agefido.decrypt_with_identity(src.read_bytes(), identity)
    token = plaintext.decode("utf-8").strip()
    if not token:
        raise VaultTokenError("unsealed token is empty (corrupt seal?)")
    return token
