#!/usr/bin/env python3
"""Render a representative `chthonios vault audit` capture for the README/post.

Uses the real ui.box renderer so the capture matches actual output. Neutral
profile name, no real keys, tells the before/after story plus the cache-leak
catch that is the standout feature.
"""
import os
os.environ["CHTHONIOS_FORCE_COLOR"] = "1"
from chthonios import ui

def box_before():
    lines = [
        ui.c(ui.G.chip, "cyan") + f" Vault source  {ui.c('on', 'green')}  {ui.c('kv/apps/agent', 'cyan')}  {ui.c('31 keys', 'bold')}",
        ui.c(ui.G.unlock, "amber") + f" Vault token   {ui.c('not sealed', 'amber')}  {ui.c('(run: chthonios vault seal-token agent)', 'grey')}",
        ui.c(ui.G.cross, "amber") + f" Redundant     {ui.c('28 keys', 'amber')} in .env {ui.c('AND', 'grey')} Vault  {ui.c('(safe to delete from .env)', 'grey')}",
        ui.c(ui.G.cross, "red") + f" Exposed       {ui.c('4 keys', 'red', 'bold')} ONLY in cleartext .env",
        "",
        ui.c("\u26a0 CACHE LEAK", "red", "bold") + ui.c("  1 vault_cache.json with secret VALUES on disk", "red"),
        ui.c("    ~/.hermes/profiles/agent/cache/vault_cache.json", "red"),
        ui.c("    fix: set secrets.vault.cache_ttl_seconds: 0, then delete the file", "grey"),
    ]
    return ui.box("Chthonios \u00b7 secret audit \u00b7 agent", lines, accent="red")

def box_after():
    lines = [
        ui.c(ui.G.chip, "cyan") + f" Vault source  {ui.c('on', 'green')}  {ui.c('kv/apps/agent', 'cyan')}  {ui.c('31 keys', 'bold')}",
        ui.c(ui.G.lock, "violet") + f" Vault token   {ui.c('SEALED behind YubiKey', 'violet')}",
        ui.c(ui.G.check, "green") + f" Cleartext env {ui.c('empty', 'green')}  {ui.c('(.env carries no keys)', 'grey')}",
    ]
    return ui.box("Chthonios \u00b7 secret audit \u00b7 agent", lines, accent="violet")

print(ui.c("$ chthonios vault audit agent", "grey"))
print(box_before())
print()
print(ui.c("# seal the token, drop the cleartext, re-audit", "grey"))
print(ui.c("$ chthonios vault audit agent", "grey"))
print(box_after())
