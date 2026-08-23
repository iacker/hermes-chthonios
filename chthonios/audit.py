"""
Chthonios secret-posture audit.

Answers one question at a glance: for a Hermes profile, where does each secret
actually live right now?

  * VAULT     — served by the HashiCorp Vault secret source (safe: not on disk)
  * SEALED    — the Vault token itself, sealed behind the YubiKey (Chthonios)
  * CLEARTEXT — still sitting in the profile's plaintext .env (exposed)
  * CACHE LEAK — a vault_cache.json wrote secret VALUES to disk (must be 0-TTL)

The audit is read-only and never prints secret values — only names, counts and
locations. It shells out to `vault kv list`/`get` for the Vault side (names
only) and reads config.yaml for the wiring.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from . import profiles, vault


# --- config -----------------------------------------------------------------

def _hermes_config_path() -> Path:
    return profiles.hermes_home() / "config.yaml"


def _load_vault_cfg() -> dict:
    """Read secrets.vault from config.yaml WITHOUT a YAML dependency.

    Chthonios ships with exactly one runtime dep (cryptography); we don't add
    PyYAML just to read one nested block. The ``secrets.vault`` section is
    flat ``key: value`` pairs under two levels of indentation, so a tiny
    indentation-aware scanner is enough and never executes arbitrary YAML.
    Returns {} if the file or the block is absent.
    """
    cfg_path = _hermes_config_path()
    if not cfg_path.exists():
        return {}
    # Prefer PyYAML when the host process provides it (Hermes does); fall back
    # to the minimal scanner in a bare Chthonios venv.
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(cfg_path.read_text()) or {}
        sec = data.get("secrets", {}) if isinstance(data, dict) else {}
        v = sec.get("vault") if isinstance(sec, dict) else None
        if isinstance(v, dict):
            return v
        return {}
    except Exception:
        pass
    return _scan_vault_block(cfg_path.read_text(errors="replace"))


def _scan_vault_block(text: str) -> dict:
    """Minimal scanner for the `secrets:` -> `vault:` -> flat pairs block."""
    lines = text.splitlines()
    out: dict = {}
    in_secrets = False
    secrets_indent = 0
    in_vault = False
    vault_indent = 0
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        stripped = raw.strip()
        if not in_secrets:
            if stripped == "secrets:":
                in_secrets = True
                secrets_indent = indent
            continue
        # inside secrets:
        if indent <= secrets_indent and stripped != "secrets:":
            # left the secrets block entirely
            if in_vault:
                break
            in_secrets = False
            continue
        if not in_vault:
            if stripped.rstrip(":") == "vault" and stripped.endswith(":"):
                in_vault = True
                vault_indent = indent
            continue
        # inside vault:
        if indent <= vault_indent:
            break  # next sibling key ends the vault block
        if ":" in stripped:
            k, _, v = stripped.partition(":")
            out[k.strip()] = _coerce_scalar(v.strip())
    return out


def _coerce_scalar(v: str):
    if v == "" or v is None:
        return ""
    low = v.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    # strip quotes
    if len(v) >= 2 and v[0] in "\"'" and v[-1] == v[0]:
        return v[1:-1]
    try:
        if "." in v:
            return float(v)
        return int(v)
    except ValueError:
        return v


# --- data model -------------------------------------------------------------

@dataclass
class AuditReport:
    profile: str
    vault_enabled: bool = False
    vault_reachable: bool = False
    vault_mount: str = ""
    vault_path: str = ""
    vault_keys: List[str] = field(default_factory=list)      # names only
    env_keys: List[str] = field(default_factory=list)        # cleartext .env
    token_sealed: bool = False
    recipient_enrolled: bool = False
    cache_ttl: object = None
    cache_leak_paths: List[str] = field(default_factory=list)  # vault_cache.json with values
    notes: List[str] = field(default_factory=list)

    @property
    def cleartext_also_in_vault(self) -> List[str]:
        """Cleartext .env keys that are ALSO in Vault — safe to delete from .env."""
        vset = set(self.vault_keys)
        return sorted(k for k in self.env_keys if k in vset)

    @property
    def cleartext_only(self) -> List[str]:
        """Keys that exist ONLY in cleartext .env — not covered by Vault."""
        vset = set(self.vault_keys)
        return sorted(k for k in self.env_keys if k not in vset)


# --- collectors -------------------------------------------------------------

_ENV_LINE_PREFIX = tuple("ABCDEFGHIJKLMNOPQRSTUVWXYZ_")


def _read_env_keys(profile: str) -> List[str]:
    ep = profiles.env_path(profile)
    if not ep.exists():
        return []
    keys = []
    for raw in ep.read_text(errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name = line.split("=", 1)[0].strip()
        if name and name[0] in _ENV_LINE_PREFIX:
            keys.append(name)
    return keys


def _vault_key_names(mount: str, path: str, timeout: float = 5.0) -> Optional[List[str]]:
    """Return the field NAMES at mount/path (never values). None if unreachable."""
    vault_bin = shutil.which("vault")
    if not vault_bin:
        return None
    token = os.environ.get("VAULT_TOKEN") or _read_token_file()
    if not token:
        return None
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "VAULT_ADDR": os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200"),
        "VAULT_TOKEN": token,
        "NO_COLOR": "1",
    }
    try:
        proc = subprocess.run(
            [vault_bin, "kv", "get", "-mount", mount, "-format", "json", path],
            env=env, capture_output=True, text=True, timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout).get("data", {}).get("data", {})
    except (ValueError, AttributeError):
        return None
    return sorted(str(k) for k in data.keys()) if isinstance(data, dict) else []


def _read_token_file() -> str:
    f = Path.home() / ".vault-token"
    try:
        return f.read_text().strip() if f.is_file() else ""
    except OSError:
        return ""


def _find_cache_leaks(profile: str) -> List[str]:
    """Locate any vault_cache.json that actually stored secret values."""
    leaks = []
    search_roots = [
        profiles.profile_dir(profile),
        profiles.hermes_home(),
    ]
    seen = set()
    for root in search_roots:
        if not root.exists():
            continue
        for p in root.rglob("vault_cache.json"):
            rp = str(p.resolve())
            if rp in seen:
                continue
            seen.add(rp)
            try:
                blob = json.loads(p.read_text())
            except Exception:
                continue
            # A leak = any cache entry carrying a non-empty 'secrets' map.
            if _cache_has_values(blob):
                leaks.append(rp)
    return leaks


def _cache_has_values(blob) -> bool:
    if isinstance(blob, dict):
        if isinstance(blob.get("secrets"), dict) and blob["secrets"]:
            return True
        return any(_cache_has_values(v) for v in blob.values())
    if isinstance(blob, list):
        return any(_cache_has_values(v) for v in blob)
    return False


# --- entry point ------------------------------------------------------------

def audit(profile: str) -> AuditReport:
    rep = AuditReport(profile=profile)

    vcfg = _load_vault_cfg()
    rep.vault_enabled = bool(vcfg.get("enabled"))
    rep.vault_mount = str(vcfg.get("mount_point") or "secret")
    rep.vault_path = str(vcfg.get("path") or "")
    rep.cache_ttl = vcfg.get("cache_ttl_seconds", None)

    rep.env_keys = _read_env_keys(profile)
    rep.token_sealed = vault.is_token_sealed(profile)
    rep.recipient_enrolled = vault.recipient_path(profile).exists()

    if rep.vault_enabled and rep.vault_path:
        names = _vault_key_names(rep.vault_mount, rep.vault_path)
        if names is not None:
            rep.vault_reachable = True
            rep.vault_keys = names
        else:
            rep.notes.append(
                "Vault is enabled in config but unreachable right now "
                "(no token, not running, or wrong address)."
            )

    rep.cache_leak_paths = _find_cache_leaks(profile)

    # Advisory on cache TTL
    try:
        ttl_num = float(rep.cache_ttl) if rep.cache_ttl is not None else None
    except (TypeError, ValueError):
        ttl_num = None
    if ttl_num is not None and ttl_num > 0:
        rep.notes.append(
            f"secrets.vault.cache_ttl_seconds={rep.cache_ttl}: Vault values will "
            "be written to disk. Set it to 0 to keep secrets off-disk."
        )

    return rep
