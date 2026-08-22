# Hermes Chthonios

> **Seal a Hermes agent profile at rest.** Until you unlock it, the profile
> **cannot read a single API key — so it cannot call any model.**

Chthonios (χθόνιος — *"of the underworld, sealed beneath"*) is the encrypted
basement of Hermes. A profile's credentials live there as ciphertext. Nothing
wakes them but you: a passphrase you know, or — in the strongest mode — a
**hardware security key you physically hold and touch.**

```
   SEALED                                    UNSEALED
   ┌───────────────────┐    unseal (you)     ┌───────────────────┐
   │ .env.chthonios    │  ───────────────▶   │ .env  (mode 600)  │
   │ = ciphertext      │  ◀───────────────   │ = real API keys   │
   │ no key = no model │    lock / seal      │ profile can run   │
   └───────────────────┘                     └───────────────────┘
```

**The guarantee:** a sealed profile has *no readable `.env`*. When its gateway
starts, it finds no API key for its provider and cannot answer with any model
until you unseal it. *This profile only works after you unlock it.*

---

## Why this exists

A UI passcode only stops someone glancing at your screen — it is trivially
bypassed from the CLI, because the secrets are still sitting there in plaintext.
Chthonios removes the plaintext. There is nothing to bypass: the credentials are
genuinely unreadable without the root of trust. An agent's own memory and keys
become inaccessible *without a human deciding to unlock them.*

Tracks upstream feature request
[NousResearch/hermes-agent#81795](https://github.com/NousResearch/hermes-agent/issues/81795).

---

## Two locks, independent

| Lock | Root of trust | What it takes to unlock |
|------|---------------|-------------------------|
| **Passphrase** | Something you *know* | The `.env` is sealed with **AES-256-GCM**, key derived from a passphrase via **scrypt** (N=2²⁰, ~1s/derivation). Optional Touch ID stores that passphrase in the macOS login keychain. |
| **YubiKey / FIDO2** | Something you *hold* | The `.env` is sealed with **`age` + FIDO2 `hmac-secret`**. Decryption requires the enrolled hardware key **physically present + a touch** (and optionally a PIN). |

A third, cosmetic layer — the **desktop UI lock** — surfaces seal state and warns
when a sealed profile has been unlocked. It never decrypts anything.

### The asymmetry that makes it safe for automation

**Sealing needs no key. Unsealing does.**

That is the crucial property: an unattended agent can *re-lock* a profile it must
never be able to re-open on its own. The machine can close the vault; only a
human with the key can open it.

---

## Quickstart

### Install

```bash
pip install -e .          # provides the `chthonios` CLI

# optional desktop lock UI:
mkdir -p ~/.hermes/desktop-plugins/chthonios
cp desktop-plugin/plugin.js ~/.hermes/desktop-plugins/chthonios/plugin.js
# then ⌘K → "Reload desktop plugins" in Hermes Desktop
```

### Mode A — passphrase (works everywhere)

```bash
chthonios seal   redteam --touchid --hint "the usual"  # encrypt .env, enroll Touch ID
chthonios status                                        # table of every profile
chthonios unseal redteam --touchid                      # decrypt for a session
chthonios lock   redteam                                # drop plaintext, keep the seal
chthonios rekey  redteam                                # change the passphrase
```

### Mode B — YubiKey (hardware-gated, strongest)

```bash
# 1. Bind your YubiKey — interactive, run in YOUR terminal (needs a touch):
chthonios enroll-key redteam        # prints the exact command to run

# 2. Seal to the key — no touch needed, encryption only:
chthonios seal redteam --fido2

# 3. Unseal later — REQUIRES the YubiKey plugged in + a touch:
chthonios unseal redteam
```

Lose the key from the USB port and the profile is inert. Nothing and no one —
not the agent, not a thief with your Mac, not a cloned disk — decrypts it
without the physical key.

**Requirements:** [`age`](https://github.com/FiloSottile/age) ≥ 1.1,
[`age-plugin-fido2-hmac`](https://github.com/olastor/age-plugin-fido2-hmac), and
`libfido2`. Any FIDO2 authenticator with the `hmac-secret` extension works
(tested on a YubiKey Security Key C NFC, firmware 5.4.3).

---

## What "sealed" means operationally

`seal` shreds the plaintext `.env` and leaves only `.env.chthonios`. `unseal`
recreates the plaintext `.env` (mode `600`) for the session; `lock` removes it
again while keeping the sealed copy, so re-locking is instant. `status` prints a
table of every profile's `MANAGED / SEALED / UNLOCKED / TOUCHID` state.

---

## Security model

- **Cipher:** AES-256-GCM — authenticated, so tampering with the ciphertext is
  detected on unseal.
- **KDF:** scrypt, N=2²⁰, r=8, p=1 — ~1 s/derivation, resists brute force.
- **Root of trust:**
  - *Passphrase mode* — the passphrase. Touch ID unlocks a passphrase you chose
    to store in the login keychain (`security`), never the ciphertext key
    directly. Skip Touch ID if you want the passphrase to exist only in your head.
  - *FIDO2 mode* — the hardware key's `hmac-secret`. The on-disk `.identity`
    file merely *wraps a credential* to the token; it is useless without the
    physical key. The `.recipient` (an `age1…` public key) is not secret.
- **The renderer never decrypts.** The desktop plugin reads seal *state* only and
  shells you the CLI command; passphrases and plaintext never touch JS.
- **Shredding** of the plaintext `.env` is best-effort (overwrite + unlink); on
  SSD / copy-on-write filesystems this is not forensic-grade. The **seal**, not
  the shred, is the protection.
- **Single point of failure (FIDO2):** lose the only enrolled key and the data
  is gone for good — there is no backdoor. Enroll a **backup key**.

Secrets never enter the repo: `.env*`, `*.chthonios`, `*.identity`, and
`*.recipient` are all git-ignored.

---

## Layout

```
chthonios/
  sealing.py     AES-GCM + scrypt envelope; file seal/unseal (no Hermes deps)
  agefido.py     age + FIDO2 hmac-secret key source (hardware-gated mode)
  profiles.py    Hermes profile path resolution + seal state
  auth.py        passphrase prompt, Touch ID, keychain enroll/fetch
  cli.py         the `chthonios` command
desktop-plugin/
  plugin.js      statusbar lock chip + ⌘K commands
tests/
  test_sealing.py   round-trip, wrong-passphrase, tamper, no-leak
  test_agefido.py   recipient/identity handling, seal-without-key
```

## License

MIT © iacker
