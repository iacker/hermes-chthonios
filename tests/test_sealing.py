"""Round-trip and tamper tests for the sealing engine — no Hermes profile needed."""
import json

import pytest

from chthonios import sealing


def test_seal_unseal_roundtrip():
    pt = b"RUNPOD_API_KEY=rpa_secret_value_123\nFOO=bar\n"
    env = sealing.seal_bytes(pt, "correct horse battery staple")
    assert sealing.unseal_bytes(env, "correct horse battery staple") == pt


def test_wrong_passphrase_raises():
    env = sealing.seal_bytes(b"secret", "right")
    with pytest.raises(sealing.UnsealError):
        sealing.unseal_bytes(env, "wrong")


def test_ciphertext_contains_no_plaintext():
    secret = b"RUNPOD_API_KEY=rpa_do_not_leak"
    env = sealing.seal_bytes(secret, "pw")
    blob = json.dumps(env).encode()
    assert b"rpa_do_not_leak" not in blob
    assert b"RUNPOD" not in blob


def test_tampered_ciphertext_rejected():
    env = sealing.seal_bytes(b"data", "pw")
    ct = bytearray(sealing._b64d(env["ct"]))
    ct[0] ^= 0xFF
    env["ct"] = sealing._b64e(bytes(ct))
    with pytest.raises(sealing.UnsealError):
        sealing.unseal_bytes(env, "pw")


def test_empty_passphrase_refused():
    with pytest.raises(sealing.SealError):
        sealing.seal_bytes(b"x", "")


def test_file_seal_unseal(tmp_path):
    env = tmp_path / ".env"
    env.write_text("RUNPOD_API_KEY=rpa_filetest\n")
    out = sealing.seal_file(env, "pw")
    assert out.exists()
    assert not env.exists()  # plaintext shredded
    assert sealing.is_sealed(env)

    sealing.unseal_file(env, "pw")
    assert env.read_text() == "RUNPOD_API_KEY=rpa_filetest\n"
    assert sealing.is_sealed(env)  # sealed copy kept by default


def test_double_seal_refused(tmp_path):
    env = tmp_path / ".env"
    env.write_text("X=1\n")
    sealing.seal_file(env, "pw")
    env.write_text("X=1\n")
    with pytest.raises(sealing.SealError):
        sealing.seal_file(env, "pw")
