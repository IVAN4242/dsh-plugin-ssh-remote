/**
 * Host-key trust helpers.
 *
 * OpenSSH refuses an unknown host key outright under `StrictHostKeyChecking=yes`,
 * which is the plugin's deliberate policy: a server is never trusted because it
 * answered. That left one honest step the human still has to take — confirm a
 * fingerprint once. This module holds the pure half of that step, so the
 * decision can be tested without a network:
 *
 *  - `fingerprintOf` — the `SHA256:…` form `ssh-keygen -lf` prints, computed
 *    from the base64 key blob;
 *  - `parseKnownHosts` — read `host type blob` lines back into records;
 *  - `mergeKnownHosts` — decide what to append, refusing to paper over a key
 *    that CHANGED, because that case must go through the human's `ssh-keygen -R`,
 *    not through a button labelled "trust".
 *
 * Nothing here opens a connection or touches a file; `index.js` owns the probe
 * and the write.
 *
 * @module dsh-plugin-ssh-remote/hostkey
 */

import { createHash } from 'node:crypto'

/** Key types a `known_hosts` line may carry. */
export const HOST_KEY_TYPES = Object.freeze([
  'ssh-ed25519',
  'ssh-rsa',
  'ecdsa-sha2-nistp256',
  'ecdsa-sha2-nistp384',
  'ecdsa-sha2-nistp521',
  'sk-ssh-ed25519@openssh.com',
  'sk-ecdsa-sha2-nistp256@openssh.com',
])

/**
 * The `SHA256:…` fingerprint OpenSSH prints for one key blob.
 *
 * Hashing the DECODED blob is what makes this comparable with
 * `ssh-keygen -lf`; hashing the base64 text instead would produce a different,
 * useless value that looked plausible.
 *
 * @param blob - the base64 key blob from a known_hosts line.
 * @returns the fingerprint, or undefined when the blob is not base64.
 */
export function fingerprintOf(blob) {
  const value = String(blob ?? '').trim()
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return undefined
  const bytes = Buffer.from(value, 'base64')
  if (bytes.length === 0) return undefined
  return `SHA256:${createHash('sha256').update(bytes).digest('base64').replace(/=+$/, '')}`
}

/**
 * Read `known_hosts` text into key records.
 *
 * Comment lines, blank lines and lines whose shape is not understood are
 * skipped: a file that also holds hashed entries or hand-made notes must not
 * make the parser fail.
 *
 * @param text - the file contents.
 * @returns one record per usable line.
 */
export function parseKnownHosts(text) {
  const keys = []
  for (const raw of String(text ?? '').split(/\r?\n/)) {
    const line = raw.trim()
    if (line.length === 0 || line.startsWith('#')) continue
    const parts = line.split(/\s+/)
    if (parts.length < 3) continue
    const [hostField, type, blob] = parts
    if (!HOST_KEY_TYPES.includes(type)) continue
    const fingerprint = fingerprintOf(blob)
    if (fingerprint === undefined) continue
    keys.push({ hostField, type, blob, fingerprint })
  }
  return keys
}

/**
 * Decide what an approved key set appends to `known_hosts`.
 *
 * Three outcomes matter, and they are different statements:
 *
 *  - already recorded → nothing to do;
 *  - a DIFFERENT key of the same type for the same address → refuse and report
 *    the conflict, because that is the changed-key case and accepting it from a
 *    "trust" button would defeat the warning;
 *  - otherwise → append.
 *
 * @param existing - the current file contents, possibly empty.
 * @param approved - records the human confirmed by fingerprint.
 * @returns the resulting text, the exact string to append, and any conflict.
 */
export function mergeKnownHosts(existing, approved) {
  const current = String(existing ?? '')
  const recorded = new Set(
    current
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith('#')),
  )
  const added = []
  for (const key of approved) {
    const line = `${key.hostField} ${key.type} ${key.blob}`
    if (recorded.has(line)) continue
    const conflict = [...recorded].some((candidate) => {
      const parts = candidate.split(/\s+/)
      return parts.length >= 3 && parts[0] === key.hostField && parts[1] === key.type
    })
    if (conflict) return { text: current, append: '', added, conflict: { hostField: key.hostField, type: key.type } }
    recorded.add(line)
    added.push(line)
  }
  if (added.length === 0) return { text: current, append: '', added }
  const separator = current.length === 0 || current.endsWith('\n') ? '' : '\n'
  const append = `${separator}${added.join('\n')}\n`
  return { text: `${current}${append}`, append, added }
}
