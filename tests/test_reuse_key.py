"""reuse_key binds a second profile to an already-enrolled YubiKey.

One token can open any number of profiles: the credential lives on the key,
the files here only address it. This checks the copy happens, stays 0600, and
refuses politely when there is nothing to copy.

No YubiKey needed: only file plumbing is exercised.
"""
import os
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main() -> None:
    root = Path(tempfile.mkdtemp())
    os.environ["HERMES_HOME"] = str(root)
    from chthonios import profiles, sealing  # imported after HERMES_HOME is set

    src, dst = root / "profiles/redteam", root / "profiles/htbfarmer"
    for d in (src, dst):
        d.mkdir(parents=True)
        (d / ".env").write_text("K=v\n")

    (src / ".chthonios.recipient").write_text("age1testrecipient\n")
    (src / ".chthonios.identity").write_text("AGE-PLUGIN-FIDO2-HMAC-1TEST\n")

    rec = profiles.reuse_key("redteam", "htbfarmer")
    assert rec == "age1testrecipient", rec
    assert (dst / ".chthonios.recipient").read_text() == "age1testrecipient\n"
    assert (dst / ".chthonios.identity").exists(), "identity must be copied too"
    for f in (".chthonios.recipient", ".chthonios.identity"):
        mode = stat.S_IMODE((dst / f).stat().st_mode)
        assert mode == 0o600, f"{f} is {oct(mode)}, must be 0600"
    print("ok: the second profile now points at the same key, 0600")

    # A source with no key must say so, not copy nothing silently.
    (root / "profiles/azure").mkdir(parents=True)
    try:
        profiles.reuse_key("azure", "htbfarmer")
    except sealing.SealError as e:
        assert "no enrolled YubiKey" in str(e), e
        print("ok: refuses when the source has no key")
    else:
        raise AssertionError("should have raised")

    try:
        profiles.reuse_key("redteam", "ghost")
    except sealing.SealError as e:
        assert "not found" in str(e), e
        print("ok: refuses an unknown target profile")
    else:
        raise AssertionError("should have raised")


if __name__ == "__main__":
    main()
