"""_run_on_pty must give age a TERMINAL on stdin, not the ciphertext.

The bug this locks down: passing ciphertext through stdin left age with a
pipe, so it fell back to /dev/tty, which a GUI does not have — the PIN prompt
never appeared and typing the right PIN did nothing.

Uses a fake `age` script, so it runs with no YubiKey and sends no real PIN.
"""
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from chthonios import agefido  # noqa: E402

FAKE_AGE = r"""#!/usr/bin/env python3
import os, sys
# Fail loudly if stdin is not a terminal: that is the whole regression.
if not os.isatty(0):
    sys.stderr.write("stdin is not a tty\n")
    sys.exit(9)
# Ciphertext must arrive as a file argument, and must be readable.
data = open(sys.argv[-1], "rb").read()
sys.stderr.write("Please enter your PIN: ")
sys.stderr.flush()
pin = sys.stdin.readline().strip()
if pin != "1234":
    sys.exit(3)
sys.stdout.buffer.write(b"PLAINTEXT:" + data)
"""


def main() -> None:
    tmp = tempfile.mkdtemp()
    fake = Path(tmp) / "age"
    fake.write_text(FAKE_AGE)
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)

    argv = [str(fake), "-d", "-i", "/dev/null", "-o", "-"]

    out = agefido._run_on_pty(argv, b"SEALED", "1234")
    assert out.startswith(b"PLAINTEXT:SEALED"), out
    print("ok: age got a tty on stdin and the ciphertext as a file")

    try:
        agefido._run_on_pty(argv, b"SEALED", "0000")
    except agefido.AgeError as e:
        assert "wrong PIN" in str(e), e
        print("ok: a wrong PIN is reported as a PIN failure")
    else:
        raise AssertionError("wrong PIN should have raised")

    # The temp ciphertext must not survive the call.
    leftovers = [p for p in Path(tempfile.gettempdir()).glob("*.age")]
    assert not leftovers, f"ciphertext left on disk: {leftovers}"
    print("ok: no ciphertext left behind")


if __name__ == "__main__":
    main()
