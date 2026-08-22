---
name: chthonios-seal-from-chat
description: "Seal (encrypt at rest) a Hermes profile or any file/folder from chat, without the user touching the CLI. Use when the user says seal / lock / encrypt / protect a profile or directory, or asks to unlock/unseal one. Sealing is safe to do for the user; hardware (YubiKey) unsealing must be handed back to the user's own terminal."
version: 1.0.0
author: Erwan Billard
license: MIT
metadata:
  hermes:
    tags: [security, encryption, secrets, yubikey, fido2, age, chthonios, sealing]
    related_skills: [hardware-gated-secret-sealing]
---

# Chthonios: seal secrets from chat

## What this is

[Chthonios](https://github.com/iacker/hermes-chthonios) encrypts secrets at
rest with one hard rule that shapes this whole skill:

> **The agent can SEAL, but is physically unable to UNSEAL a hardware-gated
> artifact.** Unsealing a YubiKey (FIDO2) seal needs the physical key + a touch
> + a PIN, which only the human at the machine can provide.

So this skill lets you do the *easy, safe* half for the user in chat — pick a
target, choose a lock, seal it — and hands the *hardware unlock* half back to
the user's own terminal, on purpose. Never try to defeat that boundary; it is
the entire point of the tool.

## When to use

Trigger when the user asks, in any phrasing, to:
- "seal / lock / encrypt / protect" a Hermes profile (e.g. `redteam`)
- "seal / encrypt" an arbitrary file or folder (e.g. a notes vault, an `.env`)
- "what's sealed?" / "show me the lock status" -> `status` / `verify`
- "unlock / unseal / open" a profile or artifact

If the user has not installed Chthonios yet, point them at the repo and the
`Quickstart` before proceeding. Confirm the `chthonios` CLI is on PATH first
(`chthonios --version`).

## Security boundary (read before acting)

These three rules are non-negotiable. They protect the user; breaking them
defeats Chthonios.

1. **Sealing is safe to do for the user; unsealing may not be.**
   - Sealing a FIDO2 profile needs only the *public recipient* — no key, no
     touch. You can do it end-to-end.
   - Unsealing a FIDO2 profile needs the physical YubiKey + touch + PIN.
     **You cannot and must not attempt it.** Print the exact `unseal` /
     `unpack` command and tell the user to run it in *their own* terminal.

2. **A passphrase typed into chat is weaker.** If the user seals with a
   passphrase they dictate to you, it lands in the conversation transcript.
   Always *recommend the YubiKey (`--fido2`) path* for anything that matters,
   and warn the user before sealing with a chat-supplied passphrase. Prefer
   letting the CLI prompt for the passphrase interactively in the user's
   terminal over accepting it in the chat.

3. **Confirm the target before sealing, and never `--remove` on the first
   pass.** Seal, let the user verify the artifact opens, *then* offer to shred
   the plaintext original. Sealing keeps the original by default — keep it that
   way until the round-trip is proven.

## Flow

### Step 1 — ask what to seal and how

Ask two things (use the clarify/question form), then proceed:

- **Target**: which profile name, or which file/folder path?
- **Lock**: YubiKey (recommended, hardware-gated) or passphrase (works
  everywhere, weaker if dictated in chat)?

If the user chose YubiKey but has not enrolled one yet, they must run
`chthonios enroll-key <profile>` in their own terminal first (it needs a
touch). Surface that command and stop until it is done.

### Step 2 — seal

**Profile, passphrase:**
```bash
chthonios seal <profile>        # CLI prompts for the passphrase
```

**Profile, YubiKey (no key needed to seal):**
```bash
chthonios seal <profile> --fido2
```

**Any file or folder, passphrase:**
```bash
chthonios pack <path>           # -> <name>.tar.chthonios (dir) or <name>.chthonios (file)
```

**Any file or folder, YubiKey:**
```bash
chthonios pack <path> --fido2 \
  --recipient-file <profile>/.chthonios.recipient   # -> <name>.tar.age
```

Report the artifact path back, and state which lock is now guarding it.

### Step 3 — verify, then optionally shred

Prove the round-trip before destroying anything:
```bash
chthonios status                # table of every profile's state
chthonios verify                # structural check, no key needed
```

For passphrase artifacts you can demonstrate the round-trip yourself. For
**FIDO2 artifacts, hand the unseal to the user** (see below). Only once the
user confirms it opens do you offer `--remove` / a secure shred of the
plaintext original.

### Step 4 — unseal

**Passphrase** (you may do this if the user is fine dictating the passphrase,
or better: give them the command):
```bash
chthonios unseal <profile>
chthonios unpack <name>.tar.chthonios --dest <dir>
```

**YubiKey / FIDO2 — ALWAYS hand back to the user.** Print the command; do not
run it for them:
```bash
# Run THIS in your own terminal — needs the YubiKey plugged in + a touch:
chthonios unseal <profile>
# or, for a packed artifact:
chthonios unpack <name>.tar.age \
  --identity <profile>/.chthonios.identity --dest <dir>
```

## Pitfalls

- **Do not** try to script around the touch prompt, export the identity, or
  "temporarily" decrypt a FIDO2 artifact on the user's behalf. It cannot work
  and it signals you misunderstood the tool.
- **Do not** pass `--remove` before the user has verified the seal opens.
- **Do not** echo a user's passphrase back into the transcript.
- A directory becomes `<name>.tar.chthonios` / `.tar.age`; a single file
  becomes `<name>.chthonios` / `.age`. Extraction is path-traversal guarded.
- `status` / `verify` need no key and are always safe to run to reassure the
  user about what is currently locked.

## Verification checklist

- [ ] Target and lock confirmed with the user before sealing
- [ ] YubiKey path recommended for anything sensitive
- [ ] Passphrase never captured in chat unless the user insisted, with a warning
- [ ] Original kept (no `--remove`) until the round-trip is proven
- [ ] FIDO2 unseal handed to the user's own terminal, never attempted by the agent
- [ ] `chthonios status` shown so the user can see the new lock state
