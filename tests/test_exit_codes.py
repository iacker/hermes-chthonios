"""The CLI must classify failures by exit code, not by English prose.

The UI reads these codes to tell "wrong passphrase" from "no such profile".
Parsing message text breaks on rewording and does not work in translations.

Runs entirely on temp profiles with a cheap KDF. No YubiKey, no real secrets.
"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from chthonios import cli  # noqa: E402


def run(home: Path, args: list, stdin: str = "") -> int:
    env = dict(os.environ, HERMES_HOME=str(home), CHTHONIOS_SCRYPT_N="16384",
               PYTHONPATH=str(ROOT), NO_COLOR="1")
    p = subprocess.run([sys.executable, "-m", "chthonios.cli"] + args,
                       input=stdin, capture_output=True, text=True, env=env)
    return p.returncode


def main() -> None:
    home = Path(tempfile.mkdtemp())
    d = home / "profiles/demo"
    d.mkdir(parents=True)
    (d / ".env").write_text("K=v\n")

    assert run(home, ["seal", "demo"], "pw\npw\n") == cli.EXIT_OK
    print("ok: seal succeeds ->", cli.EXIT_OK)

    code = run(home, ["unseal", "demo"], "WRONG\n")
    assert code == cli.EXIT_WRONG_SECRET, f"wrong passphrase gave {code}"
    print("ok: wrong passphrase ->", cli.EXIT_WRONG_SECRET)

    code = run(home, ["seal", "demo"], "pw\npw\n")
    assert code == cli.EXIT_STATE, f"already sealed gave {code}"
    print("ok: already sealed ->", cli.EXIT_STATE)

    code = run(home, ["seal", "ghost"], "pw\npw\n")
    assert code == cli.EXIT_NOT_FOUND, f"unknown profile gave {code}"
    print("ok: unknown profile ->", cli.EXIT_NOT_FOUND)

    (home / "profiles/bare").mkdir(parents=True)
    code = run(home, ["seal", "bare", "--fido2"])
    assert code == cli.EXIT_NOT_FOUND, f"no recipient gave {code}"
    print("ok: no recipient enrolled ->", cli.EXIT_NOT_FOUND)

    assert run(home, ["unseal", "demo"], "pw\n") == cli.EXIT_OK
    # `bare` was never sealed, so unsealing it is a state error. (Unsealing
    # `demo` twice is NOT: unseal keeps the sealed copy unless --forget.)
    code = run(home, ["unseal", "bare"], "pw\n")
    assert code == cli.EXIT_STATE, f"not sealed gave {code}"
    print("ok: not sealed ->", cli.EXIT_STATE)

    # Codes must stay distinct, or the UI cannot tell the cases apart.
    codes = [cli.EXIT_OK, cli.EXIT_ERROR, cli.EXIT_WRONG_SECRET,
             cli.EXIT_KEY_FAILED, cli.EXIT_STATE, cli.EXIT_NOT_FOUND,
             cli.EXIT_MISSING_DEP]
    assert len(set(codes)) == len(codes), "exit codes collide"
    assert 2 not in codes, "2 belongs to argparse usage errors"
    print("ok: codes are distinct and avoid argparse's 2")


if __name__ == "__main__":
    main()
