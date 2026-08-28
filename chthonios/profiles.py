"""Resolve Hermes profile paths and manage seal state."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from . import sealing
from . import agefido

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


def identity_path(profile: str) -> Path:
    """Where the FIDO2 age identity file lives for a profile (0600)."""
    return profile_dir(profile) / ".chthonios.identity"


def reuse_key(source: str, target: str) -> str:
    """Point `target` at the YubiKey already enrolled for `source`.

    One physical key can open any number of profiles: the credential lives on
    the token, and the two files here (public recipient + identity, which only
    wraps a credential to that token) merely address it. Copying them binds a
    second profile to the same key, with no ceremony and no touch.

    ponytail: copy, not a shared path. Profiles stay self-contained, so
    deleting one cannot break another.
    """
    src_rec = profile_dir(source) / ".chthonios.recipient"
    src_id = identity_path(source)
    if not src_rec.exists() or not src_id.exists():
        raise sealing.SealError(
            f"'{source}' has no enrolled YubiKey (run: chthonios enroll-key {source})")
    if not profile_exists(target):
        raise sealing.SealError(f"Profile '{target}' not found.")
    for src, dst in ((src_rec, profile_dir(target) / ".chthonios.recipient"),
                     (src_id, identity_path(target))):
        dst.write_bytes(src.read_bytes())
        os.chmod(dst, 0o600)
    return src_rec.read_text().strip()


def seal_fido2(profile: str, recipient: str) -> Path:
    """Encrypt the profile's .env to a FIDO2 age recipient. No token needed
    to seal. The plaintext .env is shredded; only the age ciphertext remains.
    """
    ep = env_path(profile)
    out = sealing.sealed_path(ep)
    if out.exists():
        raise sealing.SealError(f"already sealed: {out}")
    if not ep.exists():
        raise sealing.SealError(f"nothing to seal: {ep} does not exist")
    ciphertext = agefido.encrypt_to_recipient(ep.read_bytes(), recipient)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_bytes(ciphertext)
    os.chmod(tmp, 0o600)
    os.replace(tmp, out)
    sealing._shred(ep)
    st = load_state(profile)
    st.update({"managed": True, "source": "fido2-hmac", "recipient": recipient})
    save_state(profile, st)
    return out


def unseal_fido2(profile: str, keep_sealed: bool = True,
                 pin: str | None = None) -> Path:
    """Decrypt with the FIDO2 identity. REQUIRES the YubiKey + a touch.

    Without `pin`, age reads it from /dev/tty, so this must run in the user's
    terminal. Pass `pin` (from a UI) to drive it without a controlling
    terminal; the touch is still required on the token.
    """
    ep = env_path(profile)
    src = sealing.sealed_path(ep)
    if not src.exists():
        raise sealing.SealError(f"not sealed: {src}")
    plaintext = agefido.decrypt_with_identity(src.read_bytes(),
                                              identity_path(profile), pin=pin)
    tmp = ep.with_suffix(ep.suffix + ".tmp")
    tmp.write_bytes(plaintext)
    os.chmod(tmp, 0o600)
    os.replace(tmp, ep)
    if not keep_sealed:
        src.unlink()
    return ep


def seal_backend(profile: str) -> str:
    """Return which backend sealed this profile: 'fido2-hmac' or 'passphrase'."""
    return load_state(profile).get("source", "passphrase")


def list_profiles() -> list[str]:
    """Every known profile name, de-duplicated, 'default' first.

    'default' lives at the hermes home root, but a profiles/default directory
    may also exist; both map to the same profile, so it must appear once.
    """
    names = ["default"]
    base = hermes_home() / "profiles"
    if base.is_dir():
        for p in sorted(base.iterdir()):
            if p.is_dir() and p.name not in names:
                names.append(p.name)
    return names


def verify(profile: str) -> dict:
    """Structurally validate a profile's seal WITHOUT any key or passphrase.

    Reads the sealed file and checks it is a well-formed envelope (passphrase
    seal) or a valid age ciphertext (FIDO2 seal). Catches truncation and
    corruption; does not attempt decryption. Returns a report dict with
    {profile, sealed, backend, ok, reason, sealed_at, size, ...}.
    """
    ep = env_path(profile)
    src = sealing.sealed_path(ep)
    report = {"profile": profile, "sealed": False, "backend": None,
              "ok": None, "reason": "not sealed", "sealed_at": None,
              "size": None}
    if not src.exists():
        return report
    report["sealed"] = True
    try:
        raw = src.read_bytes()
    except OSError as e:
        report.update(ok=False, reason=f"unreadable: {e}")
        return report
    report["size"] = len(raw)
    backend = seal_backend(profile)
    report["backend"] = backend
    if backend == "fido2-hmac":
        ok = agefido.is_age_ciphertext(raw)
        report.update(ok=ok,
                      reason="valid age ciphertext" if ok
                      else "not a recognized age ciphertext header")
    else:
        rep = sealing.inspect_envelope(raw)
        report.update(ok=rep["valid"], reason=rep["reason"],
                      sealed_at=rep.get("sealed_at"),
                      ct_bytes=rep.get("ct_bytes"), hint=rep.get("hint"))
    return report


def sealed_at(profile: str) -> Optional[str]:
    """Best-effort ISO timestamp of when a passphrase seal was written."""
    src = sealing.sealed_path(env_path(profile))
    if not src.exists():
        return None
    if seal_backend(profile) == "fido2-hmac":
        try:
            import datetime as _dt
            return _dt.datetime.fromtimestamp(
                src.stat().st_mtime, _dt.timezone.utc).isoformat(timespec="seconds")
        except OSError:
            return None
    try:
        return sealing.inspect_envelope(src.read_bytes()).get("sealed_at")
    except OSError:
        return None


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
