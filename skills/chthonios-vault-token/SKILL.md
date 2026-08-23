---
name: chthonios-vault-token
description: "Use when sealing a HashiCorp Vault token behind a YubiKey."
version: 1.0.0
author: Erwan Billard
license: MIT
metadata:
  hermes:
    tags: [security, secrets, vault, hashicorp, yubikey, fido2, chthonios, audit]
    related_skills: [chthonios-seal-from-chat]
---

# Chthonios: HashiCorp Vault + hardware-sealed token

## What this is

Hermes has a built-in **HashiCorp Vault secret source** (`hermes-hashicorp-vault`
plugin, entry point `hermes_vault_secret_source`). It reads a KV v2 path at
startup and injects every field as an environment variable, so API keys live in
Vault instead of a plaintext `.env`.

That source needs exactly **one** bootstrap credential in the environment first:
`VAULT_TOKEN`. That single token is the whole game — with it, all the keys in
Vault are reachable; without it, nothing is. Chthonios seals *that one token*
behind a YubiKey, collapsing the attack surface from "N keys in .env" to "one
token, openable only with the hardware key + touch + PIN".

```
YubiKey (touch+PIN)  ->  unseal VAULT_TOKEN  ->  Vault serves N API keys  ->  Hermes
```

Also use this skill when the user wants to move keys out of `.env` into Vault,
or to audit where secrets live (Vault vs cleartext) and catch on-disk cache
leaks.

## Security boundary (read before acting)

Same hard rule as all of Chthonios: **the agent can SEAL and AUDIT, but cannot
UNSEAL a hardware-gated token.** Opening the sealed token needs the physical
YubiKey + touch + PIN. Print the command; hand it to the user's own terminal.

Two more non-negotiables specific to Vault:

1. **Never read or echo secret values.** The audit and status commands print
   only key NAMES, counts, and locations. Do not `vault kv get` values into the
   transcript, and do not read a profile's plaintext `.env` contents aloud.
2. **`cache_ttl_seconds` MUST be `0`.** The Vault plugin has a disk cache that
   writes secret VALUES to `vault_cache.json` when the TTL is positive. That
   defeats the entire point. Always configure `0`, and use the audit to prove
   no leak file exists.

## When to use

Trigger when the user wants to:
- "move my keys out of .env into Vault" / "use HashiCorp Vault for secrets"
- "seal / protect the Vault token with my YubiKey"
- "where do my secrets actually live?" / "audit my secrets" / "am I leaking
  anything to disk?"
- "open a shell with the Vault token" (hardware unseal, handed to the user)

Confirm prerequisites first: `chthonios --version`, a running Vault
(`vault status`), and the plugin (`hermes plugins list | grep vault`).

## Flow

### Step 1 — enable the Vault source (once)

The plugin ships installed. Enable it and point it at the KV v2 path:

```bash
hermes plugins enable hermes-hashicorp-vault
```

`config.yaml` must carry, with the cache OFF:

```yaml
secrets:
  vault:
    enabled: true
    path: env               # KV path whose fields become env vars
    mount_point: hermes     # your KV v2 mount
    auth_method: token
    addr_env: VAULT_ADDR
    token_env: VAULT_TOKEN
    cache_ttl_seconds: 0    # CRITICAL: keep secrets off disk
```

### Step 2 — audit the current posture (safe, no key)

Show the user exactly where each secret lives before changing anything:

```bash
chthonios vault audit <profile>
```

It reports: Vault source on/off + key count, whether the token is sealed,
how many `.env` keys are **redundant** (also in Vault → safe to delete) vs
**exposed** (only in cleartext), and — critically — any `vault_cache.json`
that wrote secret values to disk. Exit code is non-zero on a real problem, so
it can gate a pre-commit hook or CI.

### Step 3 — seal the Vault token (agent can do this)

Sealing needs only the profile's YubiKey *recipient* — no touch. Read the token
without putting it in shell history:

```bash
# from a pipe (never echoed into argv):
printf '%s' "$VAULT_TOKEN" | chthonios vault seal-token <profile> --stdin
# or an interactive hidden prompt:
chthonios vault seal-token <profile>
```

The token is stored as age FIDO2 ciphertext at
`<profile>/.chthonios.vault-token` (0600). If no YubiKey is enrolled yet, the
user must run `chthonios enroll-key <profile>` in their own terminal first
(needs a touch).

### Step 4 — open a shell with the token (HAND TO THE USER)

This triggers the YubiKey touch + PIN, so the agent cannot run it. Print it:

```bash
# Run THIS in your own terminal — needs the YubiKey plugged in + a touch:
eval "$(chthonios vault env <profile>)"
```

`vault env` prints ONLY `export VAULT_TOKEN='...'` on stdout (safe to `eval`);
all messages go to stderr; the token never lands on disk in cleartext. After
the eval, `VAULT_TOKEN` is set and Hermes will read every key from Vault.

### Step 5 — retire the cleartext keys

Once the audit shows keys as "redundant" (in `.env` AND Vault), the user can
delete them from `.env`. Re-run `chthonios vault audit` until "Exposed" is 0.
Do not shred anything until the round-trip (token unseal → Vault read) is proven.

## Pitfalls

- **Do not** attempt `chthonios vault env` yourself — it needs the touch.
- **Do not** leave `cache_ttl_seconds` positive; it writes secrets to disk.
  If the audit flags a `vault_cache.json` leak, set the TTL to 0 and delete
  the file.
- **Do not** pass the token as a CLI argument (`seal-token <token>`) — it would
  land in shell history. Use `--stdin` or the hidden prompt.
- **Do not** print secret values. Names and counts only.
- The sealed token is per-profile and per-YubiKey: the key that sealed it is
  the only key that opens it. A second enrolled key needs its own seal.

## Verification checklist

- [ ] `cache_ttl_seconds: 0` confirmed in config.yaml
- [ ] `chthonios vault audit` shows no CACHE LEAK
- [ ] Token sealed to the YubiKey recipient (no touch needed to seal)
- [ ] `vault env` handed to the user's terminal, never run by the agent
- [ ] Round-trip proven (unseal → Vault reachable) before deleting any .env key
- [ ] Audit re-run until "Exposed" cleartext count is 0
