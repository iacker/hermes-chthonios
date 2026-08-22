/**
 * Hermes Chthonios — desktop lock UI.
 *
 * Install to:
 *   ~/.hermes/desktop-plugins/chthonios/plugin.js   (folder name == id)
 * then run "Reload desktop plugins" from ⌘K.
 *
 * This plugin is the UI half of Chthonios. The cryptographic seal/unseal
 * lives in the `chthonios` CLI (AES-256-GCM + scrypt). Here we:
 *   - show a statusbar chip with the active profile's seal state,
 *   - warn when a sealed profile is unlocked (credentials in plaintext),
 *   - expose ⌘K commands to reveal the exact CLI action to lock/unseal.
 *
 * We deliberately do NOT hold the passphrase or decrypt in the renderer —
 * the root of trust stays in the CLI + OS keychain / Touch ID.
 */

import { cn, haptic, host, Tip, useValue } from '@hermes/plugin-sdk'
import { jsx, jsxs } from 'react/jsx-runtime'

const PALETTE_AREA = 'commandPalette'

// Read the per-profile chthonios.json + presence of .env / .env.chthonios
// through the gateway's file RPC. Returns { managed, sealed, unlocked }.
async function readSealState(profile) {
  const p = profile || host.state.profile.get() || 'default'
  try {
    const res = await host.request('fs.stat', { paths: chthPaths(p) })
    const has = (suffix) => res?.some?.((e) => e.path.endsWith(suffix) && e.exists)
    return {
      profile: p,
      sealed: has('.env.chthonios'),
      unlocked: has('/.env'),
      managed: has('.env.chthonios') || has('chthonios.json')
    }
  } catch {
    return { profile: p, sealed: false, unlocked: true, managed: false }
  }
}

function chthPaths(profile) {
  const base = profile === 'default'
    ? '~/.hermes'
    : `~/.hermes/profiles/${profile}`
  return [`${base}/.env`, `${base}/.env.chthonios`, `${base}/chthonios.json`]
}

function stateLabel(s) {
  if (!s.managed) return { text: 'unmanaged', tone: 'quaternary' }
  if (s.sealed && !s.unlocked) return { text: '🔒 sealed', tone: 'accent' }
  if (s.sealed && s.unlocked) return { text: '🔓 unlocked', tone: 'warning' }
  return { text: 'open', tone: 'tertiary' }
}

function LockChip() {
  const profile = useValue(host.state.profile)
  // lightweight polling — seal state changes rarely
  const [s, setS] = usePolled(() => readSealState(profile), [profile], 4000)
  const label = stateLabel(s || {})
  const cli = s?.sealed && s?.unlocked
    ? `chthonios lock ${s.profile}`
    : s?.sealed
      ? `chthonios unseal ${s?.profile}`
      : `chthonios seal ${s?.profile || profile}`

  return jsx(Tip, {
    label: `Chthonios: ${label.text} — copies "${cli}"`,
    children: jsx('button', {
      className: cn(
        'inline-flex h-full items-center gap-1 px-1.5 text-[0.6875rem] transition-colors',
        'text-(--ui-text-tertiary) hover:bg-(--chrome-action-hover) hover:text-foreground'
      ),
      type: 'button',
      onClick: () => {
        haptic('tap')
        navigator?.clipboard?.writeText?.(cli)
        host.notify({
          kind: label.tone === 'warning' ? 'warning' : 'info',
          message: `${label.text} — run in a terminal: ${cli}`
        })
      },
      children: `chthonios ${label.text}`
    })
  })
}

// tiny polling hook without extra imports
import { useEffect, useState } from 'react'
function usePolled(fn, deps, ms) {
  const [v, setV] = useState(null)
  useEffect(() => {
    let alive = true
    const tick = async () => { const r = await fn(); if (alive) setV(r) }
    tick()
    const id = setInterval(tick, ms)
    return () => { alive = false; clearInterval(id) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  return [v, setV]
}

export default {
  id: 'chthonios',
  name: 'Chthonios Lock',
  register(ctx) {
    ctx.register({
      id: 'chip',
      area: 'statusBar.right',
      order: 90,
      render: () => jsx(LockChip, {})
    })

    ctx.register({
      id: 'cmd-lock',
      area: PALETTE_AREA,
      data: { title: 'Chthonios: lock current profile', codicon: 'lock' },
      run: async () => {
        const s = await readSealState(host.state.profile.get())
        const cli = `chthonios lock ${s.profile}`
        navigator?.clipboard?.writeText?.(cli)
        host.notify({ kind: 'info', message: `Copied: ${cli}` })
      }
    })

    ctx.register({
      id: 'cmd-status',
      area: PALETTE_AREA,
      data: { title: 'Chthonios: show seal status', codicon: 'shield' },
      run: async () => {
        const s = await readSealState(host.state.profile.get())
        host.notify({
          kind: 'info',
          message: `${s.profile}: ${stateLabel(s).text}`
        })
      }
    })
  }
}
