"""Resolve Hermes profile paths and manage seal state."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from . import sealing

STATE_FILE = "chthonios.json"  # per-profile, non-secret metadata


def hermes_home() -> Path:
    return Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))


def profile_dir(profile: str) -> Path:
    """Path to a named profile. 'default' lives at the hermes home root."""
    if profile in ("default", "", None):
        return hermes_home()
    return hermes_home() / "profiles" / profile


def env_path(profile: str) -> Path:
    return profile_dir(profile) / ".env"


def state_path(profile: str) -> Path:
    return profile_dir(profile) / STATE_FILE


def profile_exists(profile: str) -> bool:
    return profile_dir(profile).is_dir()


def load_state(profile: str) -> dict:
    p = state_path(profile)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_state(profile: str, state: dict) -> None:
    p = state_path(profile)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def is_sealed(profile: str) -> bool:
    return sealing.is_sealed(env_path(profile))


def is_unlocked(profile: str) -> bool:
    """A managed profile is unlocked when the plaintext .env is present."""
    return env_path(profile).exists()


def is_managed(profile: str) -> bool:
    """Chthonios manages a profile once it has ever been sealed."""
    return load_state(profile).get("managed", False) or is_sealed(profile)


def seal(profile: str, passphrase: str, hint: Optional[str] = None,
         require_touchid: bool = False) -> Path:
    out = sealing.seal_file(env_path(profile), passphrase, hint=hint)
    st = load_state(profile)
    st.update({
        "managed": True,
        "require_touchid": require_touchid,
        "hint": hint or st.get("hint"),
    })
    save_state(profile, st)
    return out


def unseal(profile: str, passphrase: str, keep_sealed: bool = True) -> Path:
    return sealing.unseal_file(env_path(profile), passphrase, keep_sealed=keep_sealed)


def relock(profile: str) -> bool:
    """Remove the plaintext .env, leaving only the sealed copy.

    This is the 'lock' action: the seal already exists, we just drop the
    decrypted working copy. Returns True if a plaintext copy was removed.
    """
    ep = env_path(profile)
    if not sealing.is_sealed(ep):
        raise sealing.SealError(f"{profile} is not sealed; nothing to relock")
    if ep.exists():
        sealing._shred(ep)
        return True
    return False
