"""Tests for the secret-posture audit — no Vault, no network, no YubiKey.

Vault reachability is stubbed so these run offline; the focus is the pure
logic: the dependency-free config scanner, cleartext-vs-Vault classification,
and the cache-leak detector (the critical check).
"""
import json
import os
from pathlib import Path

import pytest

from chthonios import audit


CONFIG_YAML = """\
plugins:
  enabled:
    - hermes-hashicorp-vault
secrets:
  bitwarden:
    enabled: false
  vault:
    enabled: true
    path: env
    mount_point: hermes
    auth_method: token
    cache_ttl_seconds: 0
paste_collapse_threshold: 5
"""


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text(CONFIG_YAML)
    prof = tmp_path / "profiles" / "p1"
    prof.mkdir(parents=True)
    return tmp_path


# --- dependency-free config scanner ----------------------------------------

def test_scanner_reads_vault_block(home):
    cfg = audit._load_vault_cfg()
    assert cfg["enabled"] is True
    assert cfg["path"] == "env"
    assert cfg["mount_point"] == "hermes"
    assert cfg["cache_ttl_seconds"] == 0


def test_scanner_stops_at_sibling_key(home):
    # paste_collapse_threshold must NOT bleed into the vault block
    cfg = audit._load_vault_cfg()
    assert "paste_collapse_threshold" not in cfg


def test_scanner_ignores_other_source(home):
    cfg = audit._load_vault_cfg()
    assert "bitwarden" not in cfg  # only the vault subtree


def test_coerce_scalar_types():
    assert audit._coerce_scalar("true") is True
    assert audit._coerce_scalar("false") is False
    assert audit._coerce_scalar("0") == 0
    assert audit._coerce_scalar("300") == 300
    assert audit._coerce_scalar("''") == ""
    assert audit._coerce_scalar('"x"') == "x"


# --- env key reading --------------------------------------------------------

def test_env_keys_parsed(home):
    ep = home / "profiles" / "p1" / ".env"
    ep.write_text("# comment\nFOO=bar\nBAZ=qux\n\nnot_a_key\n")
    keys = audit._read_env_keys("p1")
    assert keys == ["FOO", "BAZ"]


# --- cleartext vs vault classification -------------------------------------

def test_redundant_and_exposed(home, monkeypatch):
    ep = home / "profiles" / "p1" / ".env"
    ep.write_text("SHARED=1\nONLY_ENV=2\n")
    # Stub Vault to return SHARED + a vault-only key
    monkeypatch.setattr(audit, "_vault_key_names", lambda *a, **k: ["SHARED", "VAULT_ONLY"])
    rep = audit.audit("p1")
    assert rep.vault_reachable
    assert rep.cleartext_also_in_vault == ["SHARED"]
    assert rep.cleartext_only == ["ONLY_ENV"]


def test_vault_unreachable_note(home, monkeypatch):
    monkeypatch.setattr(audit, "_vault_key_names", lambda *a, **k: None)
    rep = audit.audit("p1")
    assert not rep.vault_reachable
    assert any("unreachable" in n for n in rep.notes)


# --- cache-leak detector (the critical check) ------------------------------

def test_cache_leak_detected(home, monkeypatch):
    monkeypatch.setattr(audit, "_vault_key_names", lambda *a, **k: [])
    cache = home / "profiles" / "p1" / "cache"
    cache.mkdir()
    (cache / "vault_cache.json").write_text(json.dumps(
        {"k": {"secrets": {"LEAKED": "value"}, "fetched_at": 1}}
    ))
    rep = audit.audit("p1")
    assert rep.cache_leak_paths
    assert "vault_cache.json" in rep.cache_leak_paths[0]


def test_empty_cache_not_a_leak(home, monkeypatch):
    monkeypatch.setattr(audit, "_vault_key_names", lambda *a, **k: [])
    cache = home / "profiles" / "p1" / "cache"
    cache.mkdir()
    (cache / "vault_cache.json").write_text(json.dumps(
        {"k": {"secrets": {}, "fetched_at": 1}}
    ))
    rep = audit.audit("p1")
    assert rep.cache_leak_paths == []


def test_cache_ttl_positive_warns(home, monkeypatch, tmp_path):
    (tmp_path / "config.yaml").write_text(CONFIG_YAML.replace("cache_ttl_seconds: 0", "cache_ttl_seconds: 300"))
    monkeypatch.setattr(audit, "_vault_key_names", lambda *a, **k: [])
    rep = audit.audit("p1")
    assert any("cache_ttl_seconds" in n for n in rep.notes)
