"""FIDO2/age seal path — uses a standard age keypair as a hardware stand-in.

The real YubiKey binding only changes WHERE the age identity comes from; the
seal (encrypt-to-recipient) and unseal (decrypt-with-identity) logic is
identical, so this exercises the full code path without a physical token.
"""
import shutil
import subprocess

import pytest

from chthonios import agefido

age = shutil.which("age")
pytestmark = pytest.mark.skipif(not age, reason="age not installed")


def _keypair(tmp_path):
    idf = tmp_path / "id.txt"
    subprocess.run([shutil.which("age-keygen"), "-o", str(idf)],
                   capture_output=True, check=True)
    rec = subprocess.run([shutil.which("age-keygen"), "-y", str(idf)],
                         capture_output=True, text=True, check=True).stdout.strip()
    return idf, rec


def test_encrypt_decrypt_roundtrip(tmp_path):
    if not shutil.which("age-keygen"):
        pytest.skip("age-keygen not available")
    idf, rec = _keypair(tmp_path)
    secret = b"RUNPOD_API_KEY=rpa_secret\nPROVIDER=runpod-qwen\n"
    ct = agefido.encrypt_to_recipient(secret, rec)
    assert ct.startswith(b"age-encryption.org/v1")
    assert b"rpa_secret" not in ct
    assert agefido.decrypt_with_identity(ct, idf) == secret


def test_bad_recipient_rejected():
    with pytest.raises(agefido.AgeError):
        agefido.encrypt_to_recipient(b"x", "not-a-recipient")
