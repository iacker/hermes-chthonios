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

# Exit codes. A caller (the UI) must be able to tell a wrong passphrase from a
# missing profile without parsing English prose, which changes with wording and
# does not exist at all in translated builds.
#
# Numbering starts at 10: argparse already exits 2 on a usage error, and 1 stays
# the catch-all so anything unclassified keeps its old meaning.
EXIT_OK = 0
EXIT_ERROR = 1          # anything not worth its own code
EXIT_WRONG_SECRET = 10  # wrong passphrase or wrong PIN
EXIT_KEY_FAILED = 11    # YubiKey absent, not touched, or refused
EXIT_STATE = 12         # already sealed, not sealed, nothing to seal
EXIT_NOT_FOUND = 13     # no such profile, or not managed by chthonios
EXIT_MISSING_DEP = 14   # age / age-plugin-fido2-hmac not installed


def _resolve_passphrase(profile: str, use_keychain: bool, confirm: bool = False) -> str:
    if use_keychain:
        pw = auth.keychain_fetch(profile)
        if pw:
            if auth.touchid_authenticate(f"unlock profile '{profile}'"):
                return pw
            print("Touch ID / auth failed.", file=sys.stderr)
            sys.exit(EXIT_WRONG_SECRET)
        print("No keychain passphrase enrolled; falling back to prompt.",
              file=sys.stderr)
    return auth.prompt_passphrase(confirm=confirm)


def cmd_enroll_key(args) -> int:
    """Bind a YubiKey to a profile, or reuse one already bound to another."""
    if args.from_profile:
        try:
            rec = profiles.reuse_key(args.from_profile, args.profile)
        except (sealing.SealError, OSError) as e:
            print(str(e), file=sys.stderr)
            return EXIT_NOT_FOUND
        print(ui.ok(f"'{args.profile}' now uses the same YubiKey as "
                    f"'{args.from_profile}'"))
        print(ui.c(f"   recipient {rec[:16]}…  ", "grey"))
        print(f"Seal with:  chthonios seal {args.profile} --fido2")
        return EXIT_OK
    if not agefido.available():
        print("age + age-plugin-fido2-hmac required "
              "(brew install age; go install ...age-plugin-fido2-hmac).",
              file=sys.stderr)
        return EXIT_MISSING_DEP
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
        return EXIT_NOT_FOUND
    if profiles.is_sealed(args.profile):
        print(f"'{args.profile}' is already sealed. Unseal before re-sealing.",
              file=sys.stderr)
        return EXIT_STATE
    if args.fido2:
        rec_file = profiles.profile_dir(args.profile) / ".chthonios.recipient"
        if args.recipient:
            recipient = args.recipient
        elif rec_file.exists():
            recipient = rec_file.read_text().strip()
        else:
            print(f"No recipient found. Run: chthonios enroll-key {args.profile}",
                  file=sys.stderr)
            return EXIT_NOT_FOUND
        try:
            out = profiles.seal_fido2(args.profile, recipient)
        except (sealing.SealError, agefido.AgeError) as e:
            print(str(e), file=sys.stderr)
            return EXIT_STATE
        print(ui.sealed(f"Sealed {ui.c(args.profile, 'white', 'bold')} "
                        f"{ui.c('(FIDO2)', 'cyan')}  {ui.c(ui.G.arrow, 'grey')}  "
                        f"{ui.c(str(out), 'dim')}"))
        print(ui.c(f"   decrypts ONLY with the enrolled YubiKey \u2014 "
                   "not the agent, not a thief, not a cloned disk", "grey"))
        return 0
    pw = auth.prompt_passphrase("New passphrase: ", confirm=True)
    try:
        out = profiles.seal(args.profile, pw, hint=args.hint,
                            require_touchid=args.touchid)
    except sealing.SealError as e:
        # Nothing to seal (no .env) reached the UI as a raw Python traceback.
        print(str(e), file=sys.stderr)
        return EXIT_STATE
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
        return EXIT_STATE
    if profiles.seal_backend(args.profile) == "fido2-hmac":
        # With --pin-stdin the PIN arrives on stdin (a UI has no tty); age is
        # then driven on a pty. Without it, age prompts on /dev/tty as before.
        pin = sys.stdin.readline().rstrip("\n") if args.pin_stdin else None
        print(ui.c(f"{ui.G.key} Insert your YubiKey and touch it when it blinks...",
                   "amber"))
        try:
            path = profiles.unseal_fido2(args.profile, keep_sealed=not args.forget,
                                         pin=pin)
        except (agefido.AgeError, sealing.SealError) as e:
            print(str(e), file=sys.stderr)
            # age cannot tell us which one it was, and guessing would mislabel
            # a wrong PIN as a missing key. One code covers the whole ceremony.
            return EXIT_KEY_FAILED
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
        return EXIT_WRONG_SECRET
    print(ui.opened(f"Unsealed {ui.c(args.profile, 'white', 'bold')}  "
                    f"{ui.c(ui.G.arrow, 'grey')}  {ui.c(str(path), 'dim')}"))
    print(ui.c("   credentials available for this session", "grey"))
    return 0


def cmd_lock(args) -> int:
    try:
        removed = profiles.relock(args.profile)
    except sealing.SealError as e:
        print(str(e), file=sys.stderr)
        return EXIT_STATE
    print(f"Locked '{args.profile}'." if removed
          else f"'{args.profile}' was already locked.")
    return 0


def cmd_rekey(args) -> int:
    if not profiles.is_sealed(args.profile):
        print(f"'{args.profile}' is not sealed.", file=sys.stderr)
        return EXIT_STATE
    old = auth.prompt_passphrase("Current passphrase: ")
    try:
        profiles.unseal(args.profile, old, keep_sealed=True)
    except sealing.UnsealError:
        print("Wrong passphrase.", file=sys.stderr)
        return EXIT_WRONG_SECRET
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
        return EXIT_WRONG_SECRET
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


def cmd_vault_seal_token(args) -> int:
    from . import vault
    if not profiles.profile_exists(args.profile):
        print(ui.fail(f"Profile '{args.profile}' not found."), file=sys.stderr)
        return 1
    # Read the token WITHOUT echoing and WITHOUT putting it in argv/history.
    # Priority: --stdin (pipe), else a hidden prompt.
    if args.stdin:
        token = sys.stdin.readline()
    else:
        import getpass
        token = getpass.getpass("Vault token (input hidden): ")
    try:
        out = vault.seal_token(args.profile, token,
                               recipient=args.recipient, overwrite=args.force)
    except vault.VaultTokenError as e:
        print(ui.fail(str(e)), file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001
        print(ui.fail(f"seal failed: {e}"), file=sys.stderr)
        return 1
    print(ui.sealed(f"Vault token sealed to YubiKey {ui.G.arrow} {out}"),
          file=sys.stderr)
    print(ui.c("  Open a shell session with:", "grey"), file=sys.stderr)
    print(f"    eval \"$(chthonios vault env {args.profile})\"", file=sys.stderr)
    return 0


def cmd_vault_env(args) -> int:
    """Print `export VAULT_TOKEN=...` on stdout for eval. Prompts YubiKey."""
    from . import vault
    try:
        token = vault.unseal_token(args.profile)
    except vault.VaultTokenError as e:
        print(ui.fail(str(e)), file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001 — never leak partial state on stdout
        print(ui.fail(f"unseal failed: {e}"), file=sys.stderr)
        return 1
    # STDOUT: only the export line, single-quoted so shell metachars are inert.
    # A single quote inside the token is escaped the POSIX way ('\'').
    safe = token.replace("'", "'\\''")
    var = args.var or "VAULT_TOKEN"
    sys.stdout.write(f"export {var}='{safe}'\n")
    print(ui.opened(f"{var} exported into this shell (touch accepted)."),
          file=sys.stderr)
    return 0


def cmd_vault_status(args) -> int:
    from . import vault
    profs = [args.profile] if args.profile else profiles.list_profiles()
    lines = []
    for prof in profs:
        sealed = vault.is_token_sealed(prof)
        has_rec = vault.recipient_path(prof).exists()
        mark = ui.c(ui.G.lock, "violet") if sealed else ui.c(ui.G.unlock, "grey")
        state = ui.c("token sealed", "violet") if sealed else ui.c("no sealed token", "grey")
        rec = ui.c("YubiKey enrolled", "green") if has_rec else ui.c("no recipient", "amber")
        lines.append(f"{mark} {ui.c(prof, 'bold')}  {state}  {ui.c('·', 'grey')} {rec}")
    print(ui.box("Chthonios · Vault token", lines, accent="violet"))
    return 0


def cmd_vault_audit(args) -> int:
    from . import audit as auditmod
    rep = auditmod.audit(args.profile)
    lines = []

    # Vault source
    if rep.vault_enabled:
        if rep.vault_reachable:
            loc = ui.c(f"{rep.vault_mount}/{rep.vault_path}", "cyan")
            lines.append(ui.c(ui.G.chip, "cyan") +
                         f" Vault source  {ui.c('on', 'green')}  {loc}  "
                         f"{ui.c(f'{len(rep.vault_keys)} keys', 'bold')}")
        else:
            lines.append(ui.c(ui.G.chip, "amber") +
                         f" Vault source  {ui.c('enabled but unreachable', 'amber')}")
    else:
        lines.append(ui.c(ui.G.chip, "grey") +
                     f" Vault source  {ui.c('off', 'grey')}")

    # Token seal (the Chthonios bridge)
    if rep.token_sealed:
        lines.append(ui.c(ui.G.lock, "violet") +
                     f" Vault token   {ui.c('SEALED behind YubiKey', 'violet')}")
    elif rep.recipient_enrolled:
        lines.append(ui.c(ui.G.unlock, "amber") +
                     f" Vault token   {ui.c('not sealed', 'amber')}  "
                     f"{ui.c('(run: chthonios vault seal-token ' + rep.profile + ')', 'grey')}")
    else:
        lines.append(ui.c(ui.G.unlock, "grey") +
                     f" Vault token   {ui.c('no YubiKey enrolled', 'grey')}")

    # Cleartext exposure
    covered = rep.cleartext_also_in_vault
    only = rep.cleartext_only
    if not rep.env_keys:
        lines.append(ui.c(ui.G.check, "green") +
                     f" Cleartext env {ui.c('empty', 'green')}  "
                     f"{ui.c('(.env carries no keys)', 'grey')}")
    else:
        if covered:
            lines.append(ui.c(ui.G.cross, "amber") +
                         f" Redundant     {ui.c(f'{len(covered)} keys', 'amber')} in .env "
                         f"{ui.c('AND', 'grey')} Vault  "
                         f"{ui.c('(safe to delete from .env)', 'grey')}")
        if only:
            lines.append(ui.c(ui.G.cross, "red") +
                         f" Exposed       {ui.c(f'{len(only)} keys', 'red', 'bold')} "
                         f"ONLY in cleartext .env")

    # Cache leak — the critical check
    if rep.cache_leak_paths:
        lines.append("")
        lines.append(ui.c("⚠ CACHE LEAK", "red", "bold") +
                     ui.c(f"  {len(rep.cache_leak_paths)} vault_cache.json with secret VALUES on disk", "red"))
        for p in rep.cache_leak_paths:
            lines.append(ui.c(f"    {p}", "red"))
        lines.append(ui.c("    fix: set secrets.vault.cache_ttl_seconds: 0, then delete the file", "grey"))

    accent = "red" if rep.cache_leak_paths or only else "violet"
    print(ui.box(f"Chthonios · secret audit · {rep.profile}", lines, accent=accent))

    for note in rep.notes:
        print(ui.c("  " + ui.G.arrow + " " + note, "grey"))

    # Exit non-zero on a real problem so it can gate CI / pre-commit.
    return 1 if (rep.cache_leak_paths or only) else 0


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
    ek.add_argument("--from-profile", metavar="PROFILE",
                    help="reuse the YubiKey already enrolled for PROFILE "
                         "(no touch, no ceremony)")
    ek.set_defaults(func=cmd_enroll_key)

    u = sub.add_parser("unseal", help="decrypt a profile's .env for use")
    u.add_argument("profile")
    u.add_argument("--touchid", action="store_true",
                   help="unlock via stored keychain passphrase (convenience)")
    u.add_argument("--forget", action="store_true",
                   help="delete the sealed copy after unsealing")
    u.add_argument("--pin-stdin", action="store_true",
                   help="read the FIDO2 PIN from stdin (for GUIs with no tty)")
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

    # -- vault: seal the Vault bootstrap token behind the YubiKey ----------
    v = sub.add_parser(
        "vault",
        help="seal/open the Vault token that unlocks the Hermes Vault source")
    vsub = v.add_subparsers(dest="vault_cmd", required=True)

    vseal = vsub.add_parser(
        "seal-token",
        help="seal a Vault token to the profile's YubiKey (no touch to seal)")
    vseal.add_argument("profile")
    vseal.add_argument("--stdin", action="store_true",
                       help="read the token from stdin (pipe) instead of a hidden prompt")
    vseal.add_argument("--recipient", help="explicit age recipient (else the profile's)")
    vseal.add_argument("--force", action="store_true",
                       help="replace an existing sealed token")
    vseal.set_defaults(func=cmd_vault_seal_token)

    venv = vsub.add_parser(
        "env",
        help="print `export VAULT_TOKEN=...` for eval (touch the YubiKey)")
    venv.add_argument("profile")
    venv.add_argument("--var", help="env var name to export (default VAULT_TOKEN)")
    venv.set_defaults(func=cmd_vault_env)

    vst = vsub.add_parser("status", help="show which profiles have a sealed Vault token")
    vst.add_argument("profile", nargs="?")
    vst.set_defaults(func=cmd_vault_status)

    vau = vsub.add_parser(
        "audit",
        help="show where each secret lives: Vault / sealed / cleartext, + cache leaks")
    vau.add_argument("profile")
    vau.set_defaults(func=cmd_vault_audit)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
