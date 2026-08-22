# Security model

Chthonios encrypts a Hermes profile's `.env` at rest. This document states
precisely what that protects against, what it does not, and where the trust
actually sits. If a claim here and the code ever disagree, the code wins and
this file is a bug.

## What Chthonios is

A tool that turns a profile's plaintext credentials into ciphertext at rest. A
sealed profile's gateway starts, finds no API key, and cannot call any model
until someone unlocks it. It answers one question:

> **when is a profile allowed to hold its credentials at all?**

It is complementary to a secret manager (1Password, Bitwarden), which answers a
different question: *where* the credentials live. You can use both.

## The two locks

| Lock | Root of trust | Key material |
|---|---|---|
| Passphrase | Something you know | AES-256-GCM key derived from your passphrase by scrypt (N=2²⁰, r=8, p=1). The key exists only in memory during a seal/unseal. |
| YubiKey / FIDO2 | Something you hold | `age` with the FIDO2 `hmac-secret` extension. The symmetric key is derived inside the token from a per-credential secret that never leaves the hardware. |

Both use authenticated encryption, so any tampering with the ciphertext is
detected at unseal time (the AES-GCM tag, or age's MAC).

## The asymmetry that matters

Sealing needs only public material:

* passphrase mode: you type the passphrase (there is no separate public part),
* hardware mode: sealing needs only the **public recipient** (`age1…`), which is
  not secret. The token is **not** required to seal.

Unsealing needs the private root of trust: the passphrase, or the physical key
plus a touch. In hardware mode this means an unattended agent can **seal itself
to a recipient it cannot then open**, because it does not hold the token. It
places itself in a state it has no cryptographic means to reverse. That is the
property Chthonios is built to demonstrate.

## Keychain / Touch ID is a convenience, not a factor

This is the most important caveat, and the easiest to overstate.

When you enroll a profile (`--touchid` / `chthonios enroll`), Chthonios stores
the **passphrase** in the macOS login keychain and, on unlock, prompts a system
auth dialog before reading it back. Understand what this is and is not:

* `security find-generic-password -w` returns the stored passphrase **without a
  biometric touch on an already-unlocked Mac**. Anyone sitting at your unlocked
  session, or any process running as you, can read it.
* The Touch ID prompt is an `osascript ... with administrator privileges` gate.
  It honours Touch ID when Touch ID is enabled for `sudo`, and otherwise falls
  back to your **login password**. It gates the *unlock action*; it does not
  derive or protect the encryption key.

Therefore keychain/Touch ID unlock is a **usability convenience** for a machine
only you use. It is explicitly **not** a second factor and does not defend
against an attacker who is already at your unlocked machine. **If that is in
your threat model, use the FIDO2 hardware mode**, where the key material never
leaves the token and no copy of a secret sits in the keychain.

## Threat model

### Protects against

* **Stolen or lost device, powered off or logged out.** A sealed `.env` is
  ciphertext. Passphrase mode resists offline brute force via scrypt; hardware
  mode is unrecoverable without the physical key.
* **Disk image, backup, or repo leak.** The sealed file and the `.identity`
  wrapper are useless without the passphrase or token. `.env*`, `*.chthonios`,
  `*.identity`, `*.recipient` are git-ignored.
* **A profile or agent reading its own secrets while sealed.** There is no
  plaintext to read; the gateway simply has no key.
* **An autonomous agent that must not be able to reopen what it closed**
  (hardware mode): it can seal to a recipient, and only a human with the token
  can unseal.
* **Ciphertext tampering.** Authenticated encryption rejects any modified seal
  at unseal time.

### Does NOT protect against

* **An attacker at your unlocked machine, in convenience mode.** The keychain
  hands back the passphrase. Use hardware mode.
* **A profile that is currently unsealed.** Once unsealed, the `.env` is normal
  plaintext (mode `600`) for the session, exactly as before. Chthonios protects
  data *at rest*, not *in use*. Re-lock (`chthonios lock`) when done.
* **A compromised machine while you unseal** (keylogger, memory scraper, a
  malicious `age`/plugin binary on `$PATH`). The passphrase and plaintext pass
  through RAM by necessity.
* **Forensic recovery of the shredded plaintext.** `_shred` is best-effort
  overwrite-then-unlink and is **not** forensic-grade on SSD or copy-on-write
  filesystems, which may retain old blocks. The protection is the seal, not the
  shred.
* **Losing your only key.** A hardware seal has no backdoor. Lose the only
  enrolled token and the data is gone. Enroll a second YubiKey as a spare.
* **Weak passphrases.** scrypt raises the cost of guessing; it does not save a
  guessable passphrase.

## What `verify` proves, and what it doesn't

`chthonios verify` validates a seal's **structure** without any key: a
well-formed envelope of a known version with valid salt/nonce/ciphertext
(passphrase mode), or a valid `age` ciphertext header (hardware mode). It
catches corruption, truncation to garbage, and tampering with the envelope
shape.

It does **not** run the authentication tag or prove the passphrase, because both
require the key. A ciphertext truncated to a still-valid-base64 length can pass
`verify` and only fail at `unseal`, where the AES-GCM tag is the real integrity
proof. Treat `verify` as a fast pre-check and `unseal` as the cryptographic one.

## Cryptographic parameters

* **Cipher:** AES-256-GCM (12-byte nonce, random per seal), or `age`'s
  ChaCha20-Poly1305 in hardware mode.
* **KDF:** scrypt, N=2²⁰, r=8, p=1 (~1s, ~1 GB RAM per derivation). N is stored
  per envelope, so seals remain self-describing; it can be lowered for tests via
  `CHTHONIOS_SCRYPT_N` but production uses 2²⁰.
* **Salt/nonce:** 16-byte salt and 12-byte nonce from `os.urandom`, unique per
  seal.
* **File permissions:** sealed file, restored `.env`, and state file are all
  written `0600` via a temp-then-atomic-rename.

## The renderer never decrypts

The optional desktop plugin reads seal *state* only and shells the CLI command
for you. No passphrase, key, or plaintext ever passes through the JavaScript
layer.

## Reporting a vulnerability

Open a GitHub security advisory or issue on the repository. This is a personal
project shared in good faith; there is no bounty, but well-described reports are
very welcome.
