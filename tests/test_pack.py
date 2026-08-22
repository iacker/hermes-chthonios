"""Tests for generic pack/unpack of files and directories (passphrase mode)."""
import pytest

from chthonios import pack, sealing


def test_pack_unpack_file_roundtrip(tmp_path):
    f = tmp_path / "secret.txt"
    f.write_text("API_KEY=sk-do-not-leak\n")
    art, is_dir = pack.pack(f, passphrase="pw")
    assert not is_dir
    assert art.name == "secret.txt.chthonios"
    assert f.exists()  # original kept by default

    # ciphertext must not contain the plaintext
    assert b"sk-do-not-leak" not in art.read_bytes()

    f.unlink()
    out = pack.unpack(art, passphrase="pw")
    assert out.read_text() == "API_KEY=sk-do-not-leak\n"


def test_pack_unpack_directory_roundtrip(tmp_path):
    d = tmp_path / "project"
    (d / "sub").mkdir(parents=True)
    (d / "a.txt").write_text("alpha")
    (d / "sub" / "b.txt").write_text("beta")

    art, is_dir = pack.pack(d, passphrase="pw")
    assert is_dir
    assert art.name == "project.tar.chthonios"
    assert d.exists()  # kept

    # wipe original and restore into a fresh dest
    import shutil
    shutil.rmtree(d)
    dest = tmp_path / "restored"
    out = pack.unpack(art, passphrase="pw", dest=dest)
    assert (out / "a.txt").read_text() == "alpha"
    assert (out / "sub" / "b.txt").read_text() == "beta"


def test_pack_remove_shreds_original(tmp_path):
    f = tmp_path / "gone.txt"
    f.write_text("bye")
    art, _ = pack.pack(f, passphrase="pw", remove=True)
    assert art.exists()
    assert not f.exists()


def test_pack_requires_exactly_one_key(tmp_path):
    f = tmp_path / "x"
    f.write_text("y")
    with pytest.raises(sealing.SealError):
        pack.pack(f)  # neither
    with pytest.raises(sealing.SealError):
        pack.pack(f, passphrase="pw", recipient="age1abc")  # both


def test_unpack_wrong_passphrase_rejected(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("data")
    art, _ = pack.pack(f, passphrase="right")
    with pytest.raises(sealing.UnsealError):
        pack.unpack(art, passphrase="wrong")


def test_pack_refuses_existing_artifact(tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("data")
    pack.pack(f, passphrase="pw")
    f.write_text("data")
    with pytest.raises(sealing.SealError):
        pack.pack(f, passphrase="pw")  # artifact already there


def test_pack_missing_source(tmp_path):
    with pytest.raises(sealing.SealError):
        pack.pack(tmp_path / "nope", passphrase="pw")
