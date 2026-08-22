"""
Chthonios sealing engine.

Encrypts a Hermes profile's secret file (.env) at rest with AES-256-GCM,
the key derived from a passphrase via scrypt. Sealed => the profile's API
keys are unreadable ciphertext => the profile cannot call any model.

File format (`.env.chthonios`, JSON):
    {
      "v": 1,
      "kdf": "scrypt",
      "n": 1048576, "r": 8, "p": 1,
      "salt": "<b64>",
      "nonce": "<b64>",
      "ct": "<b64>",          # AES-256-GCM(ciphertext||tag) of the plaintext .env
      "sealed_at": "<iso8601>",
      "hint": "<optional non-secret reminder>"
    }

No secret material is ever written in cleartext by this module.
"""
from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SEAL_VERSION = 1
# scrypt work factor. N=2**20 ~ interactive-secure on a modern laptop (~1s).
SCRYPT_N = 1 << 20
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32  # AES-256

SEALED_SUFFIX = ".chthonios"


class SealError(Exception):
    pass


class UnsealError(SealError):
    """Raised when decryption fails — almost always a wrong passphrase."""


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(txt: str) -> bytes:
    return base64.b64decode(txt.encode("ascii"))


def _derive_key(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=n, r=r, p=p)
    return kdf.derive(passphrase.encode("utf-8"))


def seal_bytes(plaintext: bytes, passphrase: str, hint: Optional[str] = None) -> dict:
    """Return a sealed envelope dict for the given plaintext."""
    if not passphrase:
        raise SealError("empty passphrase refused")
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    envelope = {
        "v": SEAL_VERSION,
        "kdf": "scrypt",
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "salt": _b64e(salt),
        "nonce": _b64e(nonce),
        "ct": _b64e(ct),
        "sealed_at": datetime.now(timezone.utc).isoformat(),
    }
    if hint:
        envelope["hint"] = hint
    return envelope


def unseal_bytes(envelope: dict, passphrase: str) -> bytes:
    """Decrypt a sealed envelope. Raises UnsealError on wrong passphrase."""
    try:
        salt = _b64d(envelope["salt"])
        nonce = _b64d(envelope["nonce"])
        ct = _b64d(envelope["ct"])
        n = int(envelope.get("n", SCRYPT_N))
        r = int(envelope.get("r", SCRYPT_R))
        p = int(envelope.get("p", SCRYPT_P))
    except (KeyError, ValueError, TypeError) as e:
        raise SealError(f"malformed sealed envelope: {e}") from e
    key = _derive_key(passphrase, salt, n, r, p)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception as e:  # cryptography raises InvalidTag
        raise UnsealError("wrong passphrase or corrupted seal") from e


# ---- file-level helpers (operate on a profile's .env) ----

def sealed_path(env_path: Path) -> Path:
    return env_path.with_name(env_path.name + SEALED_SUFFIX)


def is_sealed(env_path: Path) -> bool:
    return sealed_path(env_path).exists()


def seal_file(env_path: Path, passphrase: str, hint: Optional[str] = None,
              shred: bool = True) -> Path:
    """Encrypt env_path -> env_path.chthonios and remove the plaintext.

    Refuses to clobber an existing seal. Returns the sealed path.
    """
    env_path = Path(env_path)
    out = sealed_path(env_path)
    if out.exists():
        raise SealError(f"already sealed: {out} (unseal first to re-seal)")
    if not env_path.exists():
        raise SealError(f"nothing to seal: {env_path} does not exist")
    plaintext = env_path.read_bytes()
    envelope = seal_bytes(plaintext, passphrase, hint=hint)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(envelope, indent=2))
    os.chmod(tmp, 0o600)
    os.replace(tmp, out)
    if shred:
        _shred(env_path)
    return out


def unseal_file(env_path: Path, passphrase: str, keep_sealed: bool = True) -> Path:
    """Decrypt env_path.chthonios -> env_path (plaintext, 0600).

    By default the sealed copy is kept so the profile can be re-sealed cheaply.
    Returns the restored plaintext path.
    """
    env_path = Path(env_path)
    src = sealed_path(env_path)
    if not src.exists():
        raise SealError(f"not sealed: {src} does not exist")
    envelope = json.loads(src.read_text())
    plaintext = unseal_bytes(envelope, passphrase)  # raises UnsealError if wrong
    tmp = env_path.with_suffix(env_path.suffix + ".tmp")
    tmp.write_bytes(plaintext)
    os.chmod(tmp, 0o600)
    os.replace(tmp, env_path)
    if not keep_sealed:
        src.unlink()
    return env_path


def _shred(path: Path, passes: int = 1) -> None:
    """Best-effort overwrite-then-unlink. Not forensic-grade on SSD/CoW FS,
    but prevents casual recovery. The real protection is the seal, not this."""
    try:
        length = path.stat().st_size
        with open(path, "r+b", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(length))
                f.flush()
                os.fsync(f.fileno())
    except OSError:
        pass
    finally:
        try:
            path.unlink()
        except OSError:
            pass
