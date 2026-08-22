"""Generic pack/unpack for an arbitrary file or directory.

Chthonios' profile commands seal a Hermes profile's .env. This module applies
the same sealing engine to any path, so `chthonios pack <folder>` produces an
encrypted artifact you can keep or move anywhere.

  * a FILE  ->  <name>.chthonios        (passphrase)  or  <name>.age
  * a DIR   ->  <name>.tar.chthonios    (passphrase)  or  <name>.tar.age

The original is KEPT by default; pass remove=True to shred/delete it only after
the artifact is written. Directory contents are tarred in-process and never
printed, so packing never exposes file contents.
"""
from __future__ import annotations

import io
import json
import os
import shutil
import tarfile
from pathlib import Path
from typing import Optional

from . import sealing, agefido

PASS_SUFFIX = ".chthonios"
AGE_SUFFIX = ".age"


def _tar_dir(src: Path) -> bytes:
    """Deterministic-ish tar of a directory, in memory. Contents are never
    read into anything but the archive buffer."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.add(str(src), arcname=src.name)
    return buf.getvalue()


def _shred_path(p: Path) -> None:
    if p.is_dir():
        # overwrite each file best-effort, then remove the tree
        for f in sorted(p.rglob("*"), reverse=True):
            if f.is_file():
                sealing._shred(f)
        shutil.rmtree(p, ignore_errors=True)
    else:
        sealing._shred(p)


def pack(src, passphrase: Optional[str] = None,
         recipient: Optional[str] = None, remove: bool = False) -> tuple[Path, bool]:
    """Seal a file or directory. Returns (artifact_path, was_directory).

    Provide exactly one of passphrase or recipient.
    """
    src = Path(src).expanduser()
    if not src.exists():
        raise sealing.SealError(f"nothing to pack: {src} does not exist")
    if bool(passphrase) == bool(recipient):
        raise sealing.SealError("provide exactly one of passphrase or recipient")

    is_dir = src.is_dir()
    data = _tar_dir(src) if is_dir else src.read_bytes()
    stem = src.name + (".tar" if is_dir else "")

    if recipient:
        ciphertext = agefido.encrypt_to_recipient(data, recipient)
        out = src.parent / (stem + AGE_SUFFIX)
        if out.exists():
            raise sealing.SealError(f"already exists: {out}")
        tmp = out.with_suffix(out.suffix + ".tmp")
        tmp.write_bytes(ciphertext)
    else:
        envelope = sealing.seal_bytes(data, passphrase)
        out = src.parent / (stem + PASS_SUFFIX)
        if out.exists():
            raise sealing.SealError(f"already exists: {out}")
        tmp = out.with_suffix(out.suffix + ".tmp")
        tmp.write_text(json.dumps(envelope, indent=2))

    os.chmod(tmp, 0o600)
    os.replace(tmp, out)
    if remove:
        _shred_path(src)
    return out, is_dir


def _looks_like_tar(name: str) -> bool:
    # <name>.tar.chthonios or <name>.tar.age
    base = name
    for suf in (PASS_SUFFIX, AGE_SUFFIX):
        if base.endswith(suf):
            base = base[: -len(suf)]
            break
    return base.endswith(".tar")


def unpack(sealed, passphrase: Optional[str] = None,
           identity=None, dest: Optional[Path] = None) -> Path:
    """Restore a packed artifact. Returns the restored path.

    dest defaults to the artifact's directory. A directory artifact extracts
    its tar there; a file artifact is written back under its original name.
    """
    sealed = Path(sealed).expanduser()
    if not sealed.exists():
        raise sealing.SealError(f"not found: {sealed}")
    raw = sealed.read_bytes()

    if sealed.name.endswith(AGE_SUFFIX):
        if identity is None:
            raise sealing.SealError("age artifact needs an identity file")
        data = agefido.decrypt_with_identity(raw, Path(identity))
        inner = sealed.name[: -len(AGE_SUFFIX)]
    elif sealed.name.endswith(PASS_SUFFIX):
        if not passphrase:
            raise sealing.SealError("passphrase required")
        data = sealing.unseal_bytes(json.loads(raw), passphrase)
        inner = sealed.name[: -len(PASS_SUFFIX)]
    else:
        raise sealing.SealError(f"unrecognized artifact suffix: {sealed.name}")

    out_dir = Path(dest).expanduser() if dest else sealed.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    if _looks_like_tar(sealed.name):
        with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tar:
            _safe_extract(tar, out_dir)
        # inner is '<name>.tar'; the restored top-level dir is its stem
        return out_dir / inner[: -len(".tar")]
    else:
        out = out_dir / inner
        tmp = out.with_suffix(out.suffix + ".tmp")
        tmp.write_bytes(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, out)
        return out


def _safe_extract(tar: tarfile.TarFile, dest: Path) -> None:
    """Extract, refusing any member that would escape dest (path traversal)."""
    dest = dest.resolve()
    for member in tar.getmembers():
        target = (dest / member.name).resolve()
        if not str(target).startswith(str(dest)):
            raise sealing.SealError(f"unsafe path in archive: {member.name}")
    tar.extractall(str(dest))
