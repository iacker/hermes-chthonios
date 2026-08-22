"""Adversarial and integrity tests: envelope inspection, verify(), and the
profile de-dup that fixed the double-'default' status bug."""
import base64
import json

import pytest

from chthonios import sealing, profiles


# ---- inspect_envelope: structural validation without the key ----

def _good_envelope() -> dict:
    return sealing.seal_bytes(b"SECRET=sk-abc123\n", "pw")


def test_inspect_valid_envelope():
    raw = json.dumps(_good_envelope()).encode()
    rep = sealing.inspect_envelope(raw)
    assert rep["valid"] is True
    assert rep["reason"] == "ok"
    assert rep["kdf"] == "scrypt"
    assert rep["ct_bytes"] and rep["ct_bytes"] > 0
    assert rep["sealed_at"]


def test_inspect_rejects_non_json():
    rep = sealing.inspect_envelope(b"not json at all{{{")
    assert rep["valid"] is False
    assert "JSON" in rep["reason"]


def test_inspect_rejects_non_object():
    rep = sealing.inspect_envelope(b"[1, 2, 3]")
    assert rep["valid"] is False
    assert "object" in rep["reason"]


def test_inspect_rejects_unknown_version():
    env = _good_envelope()
    env["v"] = 999
    rep = sealing.inspect_envelope(json.dumps(env).encode())
    assert rep["valid"] is False
    assert "version" in rep["reason"]


@pytest.mark.parametrize("field", ["salt", "nonce", "ct"])
def test_inspect_rejects_missing_field(field):
    env = _good_envelope()
    del env[field]
    rep = sealing.inspect_envelope(json.dumps(env).encode())
    assert rep["valid"] is False
    assert field in rep["reason"]


@pytest.mark.parametrize("field", ["salt", "nonce", "ct"])
def test_inspect_rejects_bad_base64(field):
    env = _good_envelope()
    env[field] = "!!!not base64!!!"
    rep = sealing.inspect_envelope(json.dumps(env).encode())
    assert rep["valid"] is False


@pytest.mark.parametrize("field,minlen", [("salt", 16), ("nonce", 12)])
def test_inspect_rejects_too_short(field, minlen):
    env = _good_envelope()
    env[field] = base64.b64encode(b"x").decode()  # 1 byte, below minimum
    rep = sealing.inspect_envelope(json.dumps(env).encode())
    assert rep["valid"] is False
    assert "short" in rep["reason"]


# ---- adversarial: every corruption unseal must reject ----

@pytest.mark.parametrize("field", ["salt", "nonce", "ct"])
def test_bitflip_each_field_rejected(field):
    env = _good_envelope()
    raw = bytearray(sealing._b64d(env[field]))
    raw[0] ^= 0xFF
    env[field] = sealing._b64e(bytes(raw))
    with pytest.raises(sealing.SealError):
        sealing.unseal_bytes(env, "pw")


def test_truncated_ciphertext_rejected():
    env = _good_envelope()
    raw = sealing._b64d(env["ct"])
    env["ct"] = sealing._b64e(raw[: len(raw) // 2])
    with pytest.raises(sealing.UnsealError):
        sealing.unseal_bytes(env, "pw")


def test_gcm_tag_flip_rejected():
    # flip the last byte, which lands in the GCM tag
    env = _good_envelope()
    raw = bytearray(sealing._b64d(env["ct"]))
    raw[-1] ^= 0x01
    env["ct"] = sealing._b64e(bytes(raw))
    with pytest.raises(sealing.UnsealError):
        sealing.unseal_bytes(env, "pw")


def test_unicode_passphrase_roundtrips():
    pt = b"SECRET=1\n"
    env = sealing.seal_bytes(pt, "clé-secrète-🔐-聖")
    assert sealing.unseal_bytes(env, "clé-secrète-🔐-聖") == pt
    with pytest.raises(sealing.UnsealError):
        sealing.unseal_bytes(env, "cle-secrete")


# ---- profiles.verify() and the de-dup fix, on an isolated HERMES_HOME ----

def _isolate_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / "profiles").mkdir()


def test_list_profiles_dedups_default(monkeypatch, tmp_path):
    _isolate_home(monkeypatch, tmp_path)
    # a profiles/default dir exists AND 'default' is implicit at the root:
    (tmp_path / "profiles" / "default").mkdir()
    (tmp_path / "profiles" / "ares").mkdir()
    names = profiles.list_profiles()
    assert names.count("default") == 1        # the bug you spotted
    assert names[0] == "default"
    assert "ares" in names


def test_verify_reports_unsealed(monkeypatch, tmp_path):
    _isolate_home(monkeypatch, tmp_path)
    (tmp_path / "profiles" / "p").mkdir()
    rep = profiles.verify("p")
    assert rep["sealed"] is False
    assert rep["ok"] is None


def test_verify_ok_on_real_seal(monkeypatch, tmp_path):
    _isolate_home(monkeypatch, tmp_path)
    d = tmp_path / "profiles" / "p"
    d.mkdir()
    (d / ".env").write_text("SECRET=sk-xyz\n")
    profiles.seal("p", "pw")
    rep = profiles.verify("p")
    assert rep["sealed"] is True
    assert rep["ok"] is True
    assert rep["backend"] == "passphrase"
    assert rep["sealed_at"]


def test_verify_catches_corrupted_seal(monkeypatch, tmp_path):
    _isolate_home(monkeypatch, tmp_path)
    d = tmp_path / "profiles" / "p"
    d.mkdir()
    (d / ".env").write_text("SECRET=sk-xyz\n")
    profiles.seal("p", "pw")
    # scribble over the sealed envelope
    sealed = sealing.sealed_path(d / ".env")
    sealed.write_text("garbage not json")
    rep = profiles.verify("p")
    assert rep["sealed"] is True
    assert rep["ok"] is False
