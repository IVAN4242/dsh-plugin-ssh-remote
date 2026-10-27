/**
 * The server registry: durable list of VPS entries, plus a parser for the
 * user's existing `~/.ssh/config` so servers can be imported instead of retyped.
 *
 * The registry is the ONLY source of connectable addresses. Nothing is
 * hard-coded, and an unknown name is refused rather than guessed at.
 *
 * Storage rules:
 *  - The file is written atomically (temp + rename) so a crash cannot leave a
 *    half-written registry that would silently drop every server.
 *  - A corrupt file is reported, never silently replaced: losing a registry is
 *    recoverable, but silently discarding it while the user believes their
 *    servers are gone is worse than failing loudly.
 *  - Credentials are never stored. Only the path to a key file is kept, and the
 *    key material itself stays wherever OpenSSH expects it.
 *
 * @module dsh-plugin-ssh-remote/registry
 */

import { randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { mkdir, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { replaceFile } from './atomic.js'

/** Current on-disk shape version, so a future change can migrate deliberately. */
export const REGISTRY_VERSION = 1

/**
 * Resolve the DeepSeek Harness home, mirroring the other plugins' precedence:
 * an explicit setting wins, then `$DSH_HOME`, then `~/.dsh`.
 *
 * @param explicit - configured directory, if any.
 * @returns an absolute directory path.
 */
export function resolveHome(explicit) {
  for (const candidate of [explicit, process.env.DSH_HOME]) {
    if (typeof candidate === 'string' && candidate.trim().length > 0) return candidate
  }
  const osHome = process.env.USERPROFILE ?? process.env.HOME ?? '.'
  return join(osHome, '.dsh')
}

/** The default registry location inside the Harness home. */
export function defaultRegistryPath(home) {
  return join(home, 'ssh-remote-hosts.json')
}

/** Human-readable reasons a server name or field is unusable. */
export class RegistryError extends Error {
  /**
   * @param message - user-facing explanation.
   * @param code - stable machine-readable reason.
   */
  constructor(message, code) {
    super(message)
    this.name = 'RegistryError'
    this.code = code
  }
}

/**
 * Reject a value that cannot plausibly be a private-key path.
 *
 * Why this exists: `/ssh add` asks for a key path, and a user who has no key yet
 * naturally types an explanation there instead — "no key, use a password". That
 * value then reaches `ssh -i`, which fails with a confusing authentication error
 * far from the real cause. Catching it at entry keeps the mistake beside the
 * field that caused it.
 *
 * The rule is deliberately narrow, so no legitimate path is rejected:
 *  - A value containing a path separator is accepted, spaces included, because a
 *    Windows profile directory may contain spaces.
 *  - Without a separator, a file extension (`id_ed25519.pem`) or the conventional
 *    `id_` prefix is accepted.
 *  - Anything else — a sentence, or a note — is refused.
 *
 * @param value - the candidate key path.
 * @returns the trimmed path.
 * @throws {RegistryError} when the value reads as prose rather than a path.
 */
export function validateIdentityFile(value) {
  const path = String(value).trim()
  if (path.length === 0) return path
  if (/[/\\]/.test(path)) return path
  if (/\.[A-Za-z0-9]+$/.test(path) || /^id_/.test(path)) return path
  throw new RegistryError(
    `"${path}" does not look like a path to a private key. Give a path such as ~/.ssh/id_ed25519, ` +
      'leave the field empty so OpenSSH finds the key itself, or put the remark in the description field.',
    'IDENTITY_FILE_INVALID',
  )
}

/**
 * Validate one candidate entry.
 *
 * The name doubles as the selection key, so it must be a short token with no
 * whitespace: it is typed after `/ssh` and printed in listings.
 *
 * @param input - a candidate entry.
 * @returns the normalized entry.
 * @throws {RegistryError} when a required field is missing or malformed.
 */
export function normalizeEntry(input) {
  const name = typeof input?.name === 'string' ? input.name.trim() : ''
  if (name.length === 0) throw new RegistryError('A server needs a name.', 'NAME_REQUIRED')
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(name)) {
    throw new RegistryError(`Server name "${name}" is invalid. Use letters, digits, dot, dash or underscore.`, 'NAME_INVALID')
  }
  const host = typeof input?.host === 'string' ? input.host.trim() : ''
  if (host.length === 0) throw new RegistryError(`Server "${name}" needs a host address.`, 'HOST_REQUIRED')
  if (/\s/.test(host)) throw new RegistryError(`Server "${name}" has an invalid host address.`, 'HOST_INVALID')

  /** @type {{name: string, host: string, user?: string, port?: number, identityFile?: string, workspace?: string, description?: string, addedAt?: string, addedBy?: string, locked?: boolean}} */
  const entry = { name, host }

  if (typeof input.user === 'string' && input.user.trim().length > 0) entry.user = input.user.trim()
  if (typeof input.description === 'string' && input.description.trim().length > 0) entry.description = input.description.trim()
  if (typeof input.workspace === 'string' && input.workspace.trim().length > 0) entry.workspace = input.workspace.trim()
  // A locked server stays listed but refuses every operation. It is the honest
  // "stop touching this machine" switch: removing the entry would also lose its
  // address and settings, and forgetting the password would lose the credential.
  if (input.locked === true) entry.locked = true
  if (typeof input.identityFile === 'string' && input.identityFile.trim().length > 0) {
    entry.identityFile = validateIdentityFile(input.identityFile)
  }
  if (input.port !== undefined && input.port !== null && input.port !== '') {
    const port = Number(input.port)
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new RegistryError(`Server "${name}" has an invalid port: ${input.port}.`, 'PORT_INVALID')
    }
    entry.port = port
  }
  if (typeof input.addedAt === 'string') entry.addedAt = input.addedAt
  if (typeof input.addedBy === 'string') entry.addedBy = input.addedBy
  return entry
}

/**
 * Read the registry from disk.
 *
 * Two severities are reported separately, because conflating them breaks the
 * plugin: a whole-file failure means nothing can be trusted and callers must
 * refuse, while a single unreadable row is repairable and every other server
 * must keep working. Treating the second as the first made `/ssh` refuse to list
 * a registry that was perfectly usable apart from one entry.
 *
 * @param path - the registry file.
 * @returns entries, the default name, a fatal `problem`, and non-fatal `warnings`.
 */
export function readRegistry(path) {
  let raw
  try {
    raw = readFileSync(path, 'utf-8')
  } catch (error) {
    // A missing file is the normal first run, not a problem to report.
    if (error?.code === 'ENOENT') return { hosts: [], default: undefined, warnings: [] }
    return {
      hosts: [],
      default: undefined,
      warnings: [],
      problem: `The registry could not be read: ${String(error?.message ?? error)}`,
    }
  }
  let parsed
  try {
    parsed = JSON.parse(raw)
  } catch (error) {
    return {
      hosts: [],
      default: undefined,
      warnings: [],
      problem: `The registry at ${path} is not valid JSON (${String(error?.message ?? error)}), so it was left untouched. Fix or delete the file, then try again.`,
    }
  }
  const hosts = []
  const warnings = []
  const list = Array.isArray(parsed?.hosts) ? parsed.hosts : []
  for (const candidate of list) {
    try {
      hosts.push(normalizeEntry(candidate))
    } catch (error) {
      // A bad key path is the one field worth salvaging around: the address and
      // user are still correct, and dropping the whole server would lose a
      // working entry over a mistyped note. Everything else skips the row.
      if (error?.code === 'IDENTITY_FILE_INVALID' && candidate !== null && typeof candidate === 'object') {
        const { identityFile: _ignored, ...rest } = candidate
        try {
          const repaired = normalizeEntry(rest)
          hosts.push(repaired)
          warnings.push(`"${repaired.name}" had a value that is not a key path, so it was loaded without its key.`)
          continue
        } catch {
          // Fall through to the general skip below.
        }
      }
      // One bad row must not hide the good ones.
      const name = typeof candidate?.name === 'string' ? candidate.name : '(unnamed)'
      warnings.push(`Entry ${name} was skipped: ${String(error?.message ?? error)}`)
    }
  }
  return { hosts, default: typeof parsed?.default === 'string' ? parsed.default : undefined, warnings }
}

/**
 * Persist the registry atomically.
 *
 * The temporary name carries the pid and a random id. A fixed `${path}.tmp` was
 * shared between the desktop and web profiles (or two Harness instances), so one
 * rename carried away the other's write and a registry entry silently vanished.
 *
 * `rename` is atomic on one volume, so a reader sees either the old file or the
 * new one. An `fsync` before the rename would also survive a power loss; it is
 * deliberately omitted, because the registry is small, rewritable through `/ssh`,
 * and reopening it is not worth the extra call on every add.
 *
 * @param path - the registry file.
 * @param hosts - entries to store.
 * @param preferred - the default server name, when set.
 */
export async function writeRegistry(path, hosts, preferred) {
  await mkdir(dirname(path), { recursive: true })
  const document = { version: REGISTRY_VERSION, hosts }
  if (typeof preferred === 'string' && preferred.length > 0) document.default = preferred
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`
  await writeFile(temporary, `${JSON.stringify(document, null, 2)}\n`, 'utf-8')
  await replaceFile(temporary, path)
}

/**
 * Add or replace one entry in place.
 *
 * @param hosts - existing entries.
 * @param entry - the normalized entry to store.
 * @param replace - whether an existing name may be overwritten.
 * @returns the updated list.
 */
export function upsertEntry(hosts, entry, replace) {
  const index = hosts.findIndex((candidate) => candidate.name === entry.name)
  if (index >= 0 && replace !== true) {
    throw new RegistryError(`A server named "${entry.name}" already exists. Choose another name or pass replace: true.`, 'NAME_TAKEN')
  }
  if (index >= 0) {
    const next = hosts.slice()
    next[index] = entry
    return next
  }
  return [...hosts, entry]
}

/**
 * Remove one entry by name.
 *
 * @param hosts - existing entries.
 * @param name - the entry to drop.
 * @returns the updated list.
 * @throws {RegistryError} when the name is unknown.
 */
export function removeEntry(hosts, name) {
  if (!hosts.some((candidate) => candidate.name === name)) {
    throw new RegistryError(`No server named "${name}" is registered.`, 'NAME_UNKNOWN')
  }
  return hosts.filter((candidate) => candidate.name !== name)
}

/**
 * Find one entry by name, case-insensitively.
 *
 * Case-insensitive lookup is a convenience for a typed selection; it never
 * invents an entry, so an unknown name still fails.
 *
 * @param hosts - existing entries.
 * @param name - the requested name.
 * @returns the matching entry, or undefined.
 */
export function findEntry(hosts, name) {
  const wanted = String(name ?? '').trim().toLowerCase()
  return hosts.find((candidate) => candidate.name.toLowerCase() === wanted)
}

/**
 * Parse `~/.ssh/config` into candidate entries.
 *
 * Scope: the common single-level `Host` form with `HostName`, `User`, `Port` and
 * `IdentityFile`. Deliberately NOT supported: `Include`, `Match`, and wildcard
 * patterns. Those are reported as skipped rather than half-applied, because a
 * silently wrong address is worse than an honest omission.
 *
 * @param text - the config file contents.
 * @returns discovered entries and the names that were skipped.
 */
export function parseSshConfig(text) {
  const found = []
  const skipped = []
  let current = undefined

  /** Finish the block being read, keeping only blocks that name a real host. */
  const flush = () => {
    if (current === undefined) return
    if (current.patterns.length !== 1) {
      // A multi-pattern or wildcard block cannot be reduced to one server.
      skipped.push(current.patterns.join(' '))
    } else {
      const pattern = current.patterns[0]
      if (/[*?!]/.test(pattern)) {
        skipped.push(pattern)
      } else {
        const entry = { name: pattern, host: current.hostName ?? pattern }
        if (current.user !== undefined) entry.user = current.user
        if (current.port !== undefined) entry.port = current.port
        if (current.identityFile !== undefined) entry.identityFile = current.identityFile
        found.push(entry)
      }
    }
    current = undefined
  }

  for (const rawLine of String(text ?? '').split(/\r?\n/)) {
    const line = rawLine.trim()
    if (line.length === 0 || line.startsWith('#')) continue
    // `Key value` or `Key=value`; both are accepted by OpenSSH.
    const match = /^([A-Za-z]+)\s*(?:=|\s)\s*(.*)$/.exec(line)
    if (match === null) continue
    const key = match[1].toLowerCase()
    const value = match[2].trim()
    if (key === 'host') {
      flush()
      current = { patterns: value.split(/\s+/).filter((part) => part.length > 0) }
      continue
    }
    if (current === undefined) continue
    if (key === 'hostname') current.hostName = value
    else if (key === 'user') current.user = value
    else if (key === 'port') {
      const port = Number(value)
      if (Number.isInteger(port) && port > 0 && port <= 65535) current.port = port
    } else if (key === 'identityfile') current.identityFile = value
    else if (key === 'include' || key === 'match') skipped.push(`${key} ${value}`)
  }
  flush()
  return { found, skipped }
}

/**
 * Merge discovered config entries into the registry without overwriting.
 *
 * Existing names are preserved: `sync` is a discovery convenience, and silently
 * changing a working server's address because a config file changed would be a
 * surprise.
 *
 * @param hosts - existing entries.
 * @param discovered - entries parsed from a config file.
 * @returns the merged list and the names actually added.
 */
export function mergeDiscovered(hosts, discovered) {
  const taken = new Set(hosts.map((entry) => entry.name))
  const added = []
  const next = hosts.slice()
  for (const entry of discovered) {
    if (taken.has(entry.name)) continue
    taken.add(entry.name)
    next.push(normalizeEntry({ ...entry, addedBy: 'ssh-config' }))
    added.push(entry.name)
  }
  return { hosts: next, added }
}
