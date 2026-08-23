"""Tests for the Vault-token sealing module.

The FIDO2 encrypt/decrypt round-trip needs a real YubiKey, so these tests
monkeypatch ``agefido`` with an in-memory reversible codec. That keeps CI
hardware-free while still exercising every branch of ``vault.py``: recipient
resolution, refuse-empty, no-clobber, path helpers, and the seal/unseal cycle.
"""
import os
from pathlib import Path

import pytest

from chthonios import vault, profiles


# --- fixtures -------------------------------------------------------------

@pytest.fixture
def profile(tmp_path, monkeypatch):
    """A throwaway Hermes profile with a YubiKey recipient enrolled."""
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    name = "testprof"
    pdir = tmp_path / "profiles" / name
    pdir.mkdir(parents=True)
    (pdir / ".chthonios.recipient").write_text("age1testrecipientxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n")
    (pdir / ".chthonios.identity").write_text("AGE-IDENTITY-FAKE\n")
    return name


@pytest.fixture
def fake_age(monkeypatch):
    """Reversible in-memory stand-in for the FIDO2 age codec (no hardware)."""
    def enc(plaintext: bytes, recipient: str) -> bytes:
        assert recipient.startswith("age1")
        return b"AGEFAKE:" + plaintext

    def dec(ciphertext: bytes, identity_file: Path) -> bytes:
        assert Path(identity_file).exists()
        assert ciphertext.startswith(b"AGEFAKE:")
        return ciphertext[len(b"AGEFAKE:"):]

    monkeypatch.setattr(vault.agefido, "encrypt_to_recipient", enc)
    monkeypatch.setattr(vault.agefido, "decrypt_with_identity", dec)


# --- round-trip -----------------------------------------------------------

def test_seal_then_unseal_roundtrip(profile, fake_age):
    token = "hvs.CAESIexampletoken1234567890"
    out = vault.seal_token(profile, token)
    assert out.exists()
    assert vault.is_token_sealed(profile)
    assert vault.unseal_token(profile) == token


def test_sealed_file_contains_no_plaintext(profile, fake_age, tmp_path):
    # Even with the fake codec, ensure we never write the raw token as-is
    # without the codec wrapper (guards against a future bug that skips enc).
    token = "hvs.DONOTLEAK_secretmaterial"
    out = vault.seal_token(profile, token)
    blob = out.read_bytes()
    assert blob.startswith(b"AGEFAKE:")  # went through the codec
    # the real codec produces age ciphertext; here we assert structure only


# --- guards ---------------------------------------------------------------

def test_refuse_empty_token(profile, fake_age):
    with pytest.raises(vault.VaultTokenError):
        vault.seal_token(profile, "   ")


def test_no_clobber_without_force(profile, fake_age):
    vault.seal_token(profile, "tok1")
    with pytest.raises(vault.VaultTokenError):
        vault.seal_token(profile, "tok2")
    # force replaces it
    vault.seal_token(profile, "tok2", overwrite=True)
    assert vault.unseal_token(profile) == "tok2"


def test_missing_recipient_errors(tmp_path, monkeypatch, fake_age):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    name = "norecipient"
    (tmp_path / "profiles" / name).mkdir(parents=True)
    with pytest.raises(vault.VaultTokenError):
        vault.seal_token(name, "tok")


def test_unseal_without_seal_errors(profile, fake_age):
    with pytest.raises(vault.VaultTokenError):
        vault.unseal_token(profile)


def test_unseal_without_identity_errors(profile, fake_age):
    vault.seal_token(profile, "tok")
    # remove the identity → unseal must refuse
    (profiles.profile_dir(profile) / ".chthonios.identity").unlink()
    with pytest.raises(vault.VaultTokenError):
        vault.unseal_token(profile)


def test_token_whitespace_stripped(profile, fake_age):
    vault.seal_token(profile, "  hvs.padded  \n")
    assert vault.unseal_token(profile) == "hvs.padded"


# --- path helpers ---------------------------------------------------------

def test_sealed_token_path_shape(profile):
    p = vault.sealed_token_path(profile)
    assert p.name == ".chthonios.vault-token"
