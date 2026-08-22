#!/usr/bin/env python3
"""
chthonios — seal a Hermes profile at rest.

    chthonios seal <profile>      encrypt the profile's .env (key-gating ON)
    chthonios unseal <profile>    decrypt for use (passphrase, or keychain unlock)
    chthonios lock <profile>      drop the plaintext .env, keep the seal
    chthonios status [profile]    show seal/unlock state
    chthonios verify [profile]    validate seal integrity, no key needed
    chthonios rekey <profile>     change the passphrase
    chthonios enroll <profile>    store passphrase in login keychain (convenience unlock)

Sealed => the profile's API keys are unreadable ciphertext => the profile
cannot call any model. The passphrase (or, in hardware mode, the YubiKey) is
the cryptographic root of trust. Keychain/Touch ID is a convenience unlock,
not a second factor: see SECURITY.md.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, auth, profiles, sealing, agefido, pack as packmod, ui


def _resolve_passphrase(profile: str, use_keychain: bool, confirm: bool = False) -> str:
    if use_keychain:
        pw = auth.keychain_fetch(profile)
        if pw:
            if auth.touchid_authenticate(f"unlock profile '{profile}'"):
                return pw
            print("Touch ID / auth failed.", file=sys.stderr)
            sys.exit(1)
        print("No keychain passphrase enrolled; falling back to prompt.",
              file=sys.stderr)
    return auth.prompt_passphrase(confirm=confirm)


def cmd_enroll_key(args) -> int:
    """Print the interactive command the user must run to bind a YubiKey."""
    if not agefido.available():
        print("age + age-plugin-fido2-hmac required "
              "(brew install age; go install ...age-plugin-fido2-hmac).",
              file=sys.stderr)
        return 1
    rec = profiles.profile_dir(args.profile) / ".chthonios.recipient"
    idf = profiles.identity_path(args.profile)
    print("Run THIS in your own terminal (needs the YubiKey + a touch):\n")
    print(f"  {agefido.enroll_command(rec, idf)}\n")
    print("Then seal with:")
    print(f"  chthonios seal {args.profile} --fido2")
    return 0


def cmd_seal(args) -> int:
    if not profiles.profile_exists(args.profile):
        print(f"Profile '{args.profile}' not found.", file=sys.stderr)
        return 1
    if profiles.is_sealed(args.profile):
        print(f"'{args.profile}' is already sealed. Unseal before re-sealing.",
              file=sys.stderr)
        return 1
    if args.fido2:
        rec_file = profiles.profile_dir(args.profile) / ".chthonios.recipient"
        if args.recipient:
            recipient = args.recipient
        elif rec_file.exists():
            recipient = rec_file.read_text().strip()
        else:
            print(f"No recipient found. Run: chthonios enroll-key {args.profile}",
                  file=sys.stderr)
            return 1
        out = profiles.seal_fido2(args.profile, recipient)
        print(ui.sealed(f"Sealed {ui.c(args.profile, 'white', 'bold')} "
                        f"{ui.c('(FIDO2)', 'cyan')}  {ui.c(ui.G.arrow, 'grey')}  "
                        f"{ui.c(str(out), 'dim')}"))
        print(ui.c(f"   decrypts ONLY with the enrolled YubiKey \u2014 "
                   "not the agent, not a thief, not a cloned disk", "grey"))
        return 0
    pw = auth.prompt_passphrase("New passphrase: ", confirm=True)
    out = profiles.seal(args.profile, pw, hint=args.hint,
                        require_touchid=args.touchid)
    print(ui.sealed(f"Sealed {ui.c(args.profile, 'white', 'bold')}  "
                    f"{ui.c(ui.G.arrow, 'grey')}  {ui.c(str(out), 'dim')}"))
    print(ui.c(f"   credentials are now unreadable until unsealed", "grey"))
    if args.touchid:
        if auth.keychain_store(args.profile, pw):
            print(ui.ok(ui.c("passphrase stored in login keychain "
                             "(convenience unlock)", "grey")))
        else:
            print(ui.fail(ui.c("keychain enrollment failed (non-macOS or denied)",
                               "grey")), file=sys.stderr)
    return 0


def cmd_unseal(args) -> int:
    if not profiles.is_sealed(args.profile):
        print(f"'{args.profile}' is not sealed.", file=sys.stderr)
        return 1
    if profiles.seal_backend(args.profile) == "fido2-hmac":
        print(ui.c(f"{ui.G.key} Insert your YubiKey and touch it when it blinks...",
                   "amber"))
        try:
            path = profiles.unseal_fido2(args.profile, keep_sealed=not args.forget)
        except (agefido.AgeError, sealing.SealError) as e:
            print(str(e), file=sys.stderr)
            return 1
        print(ui.opened(f"Unsealed {ui.c(args.profile, 'white', 'bold')} "
                        f"{ui.c('(FIDO2)', 'cyan')}  {ui.c(ui.G.arrow, 'grey')}  "
                        f"{ui.c(str(path), 'dim')}"))
        print(ui.c("   credentials available for this session", "grey"))
        return 0
    pw = _resolve_passphrase(args.profile, args.touchid)
    try:
        path = profiles.unseal(args.profile, pw, keep_sealed=not args.forget)
    except sealing.UnsealError:
        print(ui.fail("Wrong passphrase. Profile stays sealed."), file=sys.stderr)
        return 1
    print(ui.opened(f"Unsealed {ui.c(args.profile, 'white', 'bold')}  "
                    f"{ui.c(ui.G.arrow, 'grey')}  {ui.c(str(path), 'dim')}"))
    print(ui.c("   credentials available for this session", "grey"))
    return 0


def cmd_lock(args) -> int:
    try:
        removed = profiles.relock(args.profile)
    except sealing.SealError as e:
        print(str(e), file=sys.stderr)
        return 1
    print(f"Locked '{args.profile}'." if removed
          else f"'{args.profile}' was already locked.")
    return 0


def cmd_rekey(args) -> int:
    if not profiles.is_sealed(args.profile):
        print(f"'{args.profile}' is not sealed.", file=sys.stderr)
        return 1
    old = auth.prompt_passphrase("Current passphrase: ")
    try:
        profiles.unseal(args.profile, old, keep_sealed=True)
    except sealing.UnsealError:
        print("Wrong passphrase.", file=sys.stderr)
        return 1
    # remove old seal, re-seal with new passphrase
    sealing.sealed_path(profiles.env_path(args.profile)).unlink()
    new = auth.prompt_passphrase("New passphrase: ", confirm=True)
    profiles.seal(args.profile, new, hint=args.hint)
    print(f"Rekeyed '{args.profile}'.")
    return 0


def cmd_enroll(args) -> int:
    pw = auth.prompt_passphrase("Passphrase to enroll: ")
    try:
        profiles.unseal(args.profile, pw, keep_sealed=True)
        profiles.relock(args.profile)
    except sealing.UnsealError:
        print("Wrong passphrase; not enrolling.", file=sys.stderr)
        return 1
    if auth.keychain_store(args.profile, pw):
        st = profiles.load_state(args.profile)
        st["require_touchid"] = True
        profiles.save_state(args.profile, st)
        print(f"Enrolled '{args.profile}' for convenience unlock (keychain).")
        return 0
    print("Keychain enrollment failed.", file=sys.stderr)
    return 1


def cmd_pack(args) -> int:
    """Seal an arbitrary file or directory (not a Hermes profile)."""
    src = args.path
    if args.fido2:
        if not agefido.available():
            print("age + age-plugin-fido2-hmac required for --fido2.",
                  file=sys.stderr)
            return 1
        recipient = args.recipient
        if not recipient and args.recipient_file:
            recipient = Path(args.recipient_file).expanduser().read_text().strip()
        if not recipient:
            print("--fido2 needs --recipient or --recipient-file "
                  "(from `chthonios enroll-key`).", file=sys.stderr)
            return 1
        try:
            out, is_dir = packmod.pack(src, recipient=recipient, remove=args.remove)
        except (packmod.sealing.SealError, agefido.AgeError) as e:
            print(str(e), file=sys.stderr)
            return 1
    else:
        pw = auth.prompt_passphrase("New passphrase: ", confirm=True)
        try:
            out, is_dir = packmod.pack(src, passphrase=pw, remove=args.remove)
        except packmod.sealing.SealError as e:
            print(str(e), file=sys.stderr)
            return 1
    kind = "directory" if is_dir else "file"
    gated = "YubiKey (FIDO2)" if args.fido2 else "passphrase"
    print(ui.sealed(f"Sealed {kind}  {ui.c(ui.G.arrow, 'grey')}  "
                    f"{ui.c(str(out), 'cyan', 'bold')}"))
    print(ui.c(f"   gated by {gated} \u00b7 the agent can seal but cannot open this",
               "grey"))
    if not args.remove:
        print(ui.c(f"   original kept \u2014 re-run with --remove to shred it "
                   "after verifying", "dim"))
    else:
        print(ui.ok(ui.c("original shredded", "grey")))
    return 0


def cmd_unpack(args) -> int:
    sealed = Path(args.artifact)
    if sealed.name.endswith(packmod.AGE_SUFFIX):
        idf = args.identity
        if not idf:
            print("age artifact: pass --identity <file> "
                  "(run unpack in your own terminal; needs the YubiKey + touch).",
                  file=sys.stderr)
            return 1
        try:
            out = packmod.unpack(sealed, identity=idf, dest=args.dest)
        except (packmod.sealing.SealError, agefido.AgeError) as e:
            print(str(e), file=sys.stderr)
            return 1
    else:
        pw = auth.prompt_passphrase()
        try:
            out = packmod.unpack(sealed, passphrase=pw, dest=args.dest)
        except packmod.sealing.UnsealError:
            print("Wrong passphrase.", file=sys.stderr)
            return 1
        except packmod.sealing.SealError as e:
            print(str(e), file=sys.stderr)
            return 1
    print(ui.opened(f"Unsealed  {ui.c(ui.G.arrow, 'grey')}  "
                    f"{ui.c(str(out), 'green', 'bold')}"))
    return 0


def cmd_status(args) -> int:
    if args.profile:
        names = [args.profile]
    else:
        names = profiles.list_profiles()
    rows = []
    for name in names:
        if not profiles.profile_exists(name):
            continue
        managed = profiles.is_managed(name)
        sealed = profiles.is_sealed(name)
        unlocked = profiles.is_unlocked(name)
        if sealed:
            backend = profiles.seal_backend(name)
            rep = profiles.verify(name)
            integrity = rep["ok"]
            when = (rep.get("sealed_at") or profiles.sealed_at(name) or "")[:19]
        else:
            backend = ""
            integrity = None
            when = ""
        rows.append((name, managed, sealed, unlocked, backend, integrity, when))

    cols = f" {'PROFILE':<15}{'STATE':<9} {'BACKEND':<11}{'INTEGRITY':<11}SEALED AT"
    print(ui.c(cols, "grey", "bold"))
    print(ui.c("\u2500" * 62, "grey"))
    for name, managed, sealed, unlocked, backend, integrity, when in rows:
        if not managed:
            state = ui.c(f"{ui.G.chip} unmanaged", "grey")
            state_w = f"{state}{' ' * max(0, 9 - len('  unmanaged'))}"
        elif sealed and unlocked:
            state = f"{ui.c(ui.G.unlock, 'amber')} {ui.c('OPEN', 'amber', 'bold')}"
            state_w = f"{state}{' ' * 4}"
        elif sealed:
            state = f"{ui.c(ui.G.lock, 'violet')} {ui.c('SEALED', 'violet', 'bold')}"
            state_w = f"{state}{' ' * 2}"
        else:
            state = ui.c("  clear", "grey")
            state_w = f"{state}{' ' * 3}"
        integ = ("" if integrity is None
                 else ui.c(f"{ui.G.check} ok", "green") + "     " if integrity
                 else ui.c(f"{ui.G.cross} CORRUPT", "red"))
        bk = ui.c(f"{backend:<10}", "cyan") if backend else " " * 10
        print(f" {ui.c(f'{name:<15}', 'white')}{state_w} {bk} {integ:<11} "
              f"{ui.c(when, 'dim')}")
    return 0


def cmd_verify(args) -> int:
    """Structurally validate seals without any key or passphrase."""
    names = [args.profile] if args.profile else profiles.list_profiles()
    any_sealed = False
    bad = 0
    for name in names:
        if not profiles.profile_exists(name):
            if args.profile:
                print(f"Profile '{name}' not found.", file=sys.stderr)
                return 1
            continue
        rep = profiles.verify(name)
        if not rep["sealed"]:
            if args.profile:
                print(f"{name}: not sealed")
            continue
        any_sealed = True
        if rep["ok"]:
            line = ui.ok(f"{ui.c(name, 'white', 'bold')}  {ui.c(rep['reason'], 'dim')}")
        else:
            line = ui.fail(f"{ui.c(name, 'white', 'bold')}  {ui.c(rep['reason'], 'red')}")
        extra = []
        if rep.get("backend"):
            extra.append(rep["backend"])
        if rep.get("size") is not None:
            extra.append(f"{rep['size']}B")
        if rep.get("sealed_at"):
            extra.append(rep["sealed_at"][:19])
        detail = ui.c(" \u00b7 ".join(extra), "grey")
        print(line + (f"  ({detail})" if extra else ""))
        if not rep["ok"]:
            bad += 1
    if not any_sealed and not args.profile:
        print(ui.c("No sealed profiles.", "grey"))
    return 1 if bad else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="chthonios", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"chthonios {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("seal", help="encrypt a profile's .env")
    s.add_argument("profile")
    s.add_argument("--hint", help="non-secret passphrase reminder")
    s.add_argument("--touchid", action="store_true",
                   help="also store passphrase in keychain for convenience unlock")
    s.add_argument("--fido2", action="store_true",
                   help="seal to an enrolled YubiKey (decrypt needs the key)")
    s.add_argument("--recipient", help="explicit age recipient (with --fido2)")
    s.set_defaults(func=cmd_seal)

    ek = sub.add_parser("enroll-key",
                        help="print the command to bind a YubiKey (FIDO2)")
    ek.add_argument("profile")
    ek.set_defaults(func=cmd_enroll_key)

    u = sub.add_parser("unseal", help="decrypt a profile's .env for use")
    u.add_argument("profile")
    u.add_argument("--touchid", action="store_true",
                   help="unlock via stored keychain passphrase (convenience)")
    u.add_argument("--forget", action="store_true",
                   help="delete the sealed copy after unsealing")
    u.set_defaults(func=cmd_unseal)

    l = sub.add_parser("lock", help="drop the plaintext .env, keep the seal")
    l.add_argument("profile")
    l.set_defaults(func=cmd_lock)

    r = sub.add_parser("rekey", help="change a profile's passphrase")
    r.add_argument("profile")
    r.add_argument("--hint")
    r.set_defaults(func=cmd_rekey)

    e = sub.add_parser("enroll",
                       help="store passphrase in keychain for convenience unlock")
    e.add_argument("profile")
    e.set_defaults(func=cmd_enroll)

    st = sub.add_parser("status", help="show seal/unlock state")
    st.add_argument("profile", nargs="?")
    st.set_defaults(func=cmd_status)

    vf = sub.add_parser("verify",
                        help="validate seal integrity without a key/passphrase")
    vf.add_argument("profile", nargs="?")
    vf.set_defaults(func=cmd_verify)

    pk = sub.add_parser("pack",
                        help="seal ANY file or directory (not just a profile)")
    pk.add_argument("path", help="file or directory to seal")
    pk.add_argument("--fido2", action="store_true",
                    help="seal to a YubiKey recipient instead of a passphrase")
    pk.add_argument("--recipient", help="age recipient (with --fido2)")
    pk.add_argument("--recipient-file",
                    help="file holding the age recipient (with --fido2)")
    pk.add_argument("--remove", action="store_true",
                    help="shred the original after packing (default: keep it)")
    pk.set_defaults(func=cmd_pack)

    up = sub.add_parser("unpack", help="restore a packed file or directory")
    up.add_argument("artifact", help="the .chthonios or .age artifact")
    up.add_argument("--identity", help="age identity file (for .age artifacts)")
    up.add_argument("--dest", help="destination directory (default: alongside)")
    up.set_defaults(func=cmd_unpack)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
