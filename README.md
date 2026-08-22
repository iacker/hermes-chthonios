# Hermes Chthonios

**Seal a Hermes profile at rest.** Chthonios (χθόνιος — *"of the underworld, sealed beneath"*)
encrypts a Hermes profile's credentials so that, until you unlock it, the
profile **cannot read any API key and therefore cannot call any model**. Two
locks, independent:

| Lock | What it protects | Mechanism |
|------|------------------|-----------|
| **Key-gating — passphrase** | The profile's *ability to function* | The profile's `.env` is encrypted at rest with **AES-256-GCM**, key derived from a passphrase via **scrypt** (N=2²⁰). |
| **Key-gating — YubiKey (FIDO2)** | Same, but with a *physical* root of trust | The `.env` is encrypted via **`age` + FIDO2 hmac-secret**. Decryption requires the hardware key **physically present + a touch**. Sealing does not — so an unattended agent can lock the profile, but **only a human holding the key can unlock it**. |
| **UI lock** (desktop) | *Casual access* on an unlocked machine | Desktop plugin surfaces seal state and warns when a sealed profile is unlocked. |

Sealed ⇒ the API keys are ciphertext ⇒ no model responds until you unlock.

### YubiKey / FIDO2 mode (hardware-gated)

The strongest mode. The profile can only be decrypted by the enrolled security
key — lose the key from the USB port and the profile is inert. Crucially, the
**seal** step needs no key, so automation can re-lock a profile it must never be
able to re-open on its own.

```bash
# 1. Bind your YubiKey (interactive — run in YOUR terminal, needs a touch):
chthonios enroll-key redteam         # prints the exact command to run

# 2. Seal to the key (no touch needed — encryption only):
chthonios seal redteam --fido2

# 3. Unseal later (REQUIRES the YubiKey plugged in + a touch):
chthonios unseal redteam
```

Requirements: [`age`](https://github.com/FiloSottile/age) ≥ 1.1,
[`age-plugin-fido2-hmac`](https://github.com/olastor/age-plugin-fido2-hmac),
and `libfido2`. Any FIDO2 authenticator with the `hmac-secret` extension works
(tested on a YubiKey Security Key C NFC, firmware 5.4.3).

This is stronger than a UI passcode alone: a passcode only stops someone looking
at the screen and is bypassable from the CLI. Key-gating means the secrets are
genuinely unreadable without the passphrase — there is nothing to bypass.

Tracks upstream feature request
[NousResearch/hermes-agent#81795](https://github.com/NousResearch/hermes-agent/issues/81795).

## Install

```bash
pip install -e .          # provides the `chthonios` CLI
# desktop lock UI (optional):
mkdir -p ~/.hermes/desktop-plugins/chthonios
cp desktop-plugin/plugin.js ~/.hermes/desktop-plugins/chthonios/plugin.js
# then ⌘K → "Reload desktop plugins" in Hermes Desktop
```

## Usage

```bash
chthonios seal   redteam --touchid --hint "the usual"   # encrypt .env, enroll Touch ID
chthonios status                                        # table of all profiles
chthonios unseal redteam --touchid                      # decrypt for a session (Touch ID)
chthonios lock   redteam                                # drop plaintext, keep the seal
chthonios rekey  redteam                                # change passphrase
```

`seal` shreds the plaintext `.env` and leaves only `.env.chthonios`. `unseal`
recreates the plaintext `.env` (mode `600`) for the session; `lock` removes it
again. The sealed copy is kept so re-locking is instant.

### What "sealed" means operationally

A sealed profile has **no readable `.env`**. When its gateway starts it finds no
API key for its pinned provider, so the profile cannot answer with any model
until you `unseal` it. That is the guarantee: *this profile only works after you
unlock it, with the key that lives inside the seal.*

## Security model

- **Cipher:** AES-256-GCM (authenticated — tampering is detected).
- **KDF:** scrypt, N=2²⁰, r=8, p=1 — ~1s/derivation, resists brute force.
- **Root of trust:** the passphrase. Touch ID unlocks a passphrase you chose to
  store in the macOS login keychain (`security`), never the ciphertext key
  directly. Don't enroll Touch ID if you want the passphrase to exist only in
  your head.
- **The renderer never decrypts.** The desktop plugin only reads seal *state*
  and shells you the CLI command; the passphrase and plaintext never touch JS.
- **Shredding** of the plaintext `.env` is best-effort (overwrite+unlink); on
  SSD/copy-on-write filesystems this is not forensic-grade. The seal, not the
  shred, is the protection.

## Layout

```
chthonios/
  sealing.py     AES-GCM + scrypt envelope; file seal/unseal (no Hermes deps)
  profiles.py    Hermes profile path resolution + seal state
  auth.py        passphrase prompt, Touch ID, keychain enroll/fetch
  cli.py         the `chthonios` command
desktop-plugin/
  plugin.js      statusbar lock chip + ⌘K commands
tests/
  test_sealing.py  round-trip, wrong-passphrase, tamper, no-leak
```

## License

MIT © iacker
