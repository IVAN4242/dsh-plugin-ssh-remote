/**
 * SSH Remote — the settings page's HTTP face.
 *
 * The browser half renders a Terminus-like host manager, but every operation it
 * offers is an operation the plugin already performs for the agent: read the
 * registry, add or edit a server, forget one, choose the default, lock or unlock
 * a host, test a connection, import from `~/.ssh/config`, store a password.
 * This module is the one place those calls arrive from the page; it owns no
 * policy of its own, so the UI and `/ssh` cannot drift apart.
 *
 * Transport: an exact route on `@deepseek-ai/dsh-client-connection`'s Fetch
 * handler (`ctx.connection.fetch.register`). That seat is the important design
 * decision, not an implementation detail:
 *
 *  - it sits BEHIND the host's own trust and login fence, so this file writes no
 *    authentication of its own. A raw `webServer.register` route would skip the
 *    fence entirely, and re-implementing Host/Origin and token checks here would
 *    be a second security surface to keep correct.
 *  - it is refused to every non-owner Peer, which is what a host manager wants:
 *    only the owner's browser may edit the allowlist.
 *
 * The route deliberately answers `200` with `{ ok: false, error }` for a
 * refused operation (a bad name, a server that will not connect): those are
 * ordinary outcomes a human must read, not transport faults. Real transport
 * faults (bad JSON, unknown action) keep 4xx.
 *
 * No credential is ever sent to the page. A stored password is reported as
 * `hasPassword: true` and nothing more.
 *
 * @module dsh-plugin-ssh-remote/ui-api
 */

/** The exact path the Connection Fetch handler mounts this route on. */
export const UI_PATH = '/api/ssh-remote'

/** Largest accepted request body; the UI sends one small JSON object. */
const MAX_BODY_BYTES = 64 * 1024

/**
 * Every action this route accepts.
 *
 * Declared as data so an unknown verb is a 400 rather than a silent no-op, and
 * so `handle()` never grows an accidental catch-all.
 */
export const UI_ACTIONS = Object.freeze([
  'state',
  'save',
  'remove',
  'default',
  'lock',
  'unlock',
  'test',
  'import',
  'password',
  'clearPassword',
  'keyScan',
  'keyTrust',
])

/** Read a string field from an untrusted body, trimmed, or undefined. */
function text(value) {
  if (typeof value !== 'string') return undefined
  const trimmed = value.trim()
  return trimmed.length === 0 ? undefined : trimmed
}

/** Read a required string field, raising a readable message when absent. */
function required(value, label) {
  const parsed = text(value)
  if (parsed === undefined) throw new Error(`${label} is required.`)
  return parsed
}

/** Read a boolean field with an explicit fallback. */
function flag(value, fallback) {
  return typeof value === 'boolean' ? value : fallback
}

/** Read a port-like field, leaving validation to `normalizeEntry`. */
function port(value) {
  if (value === undefined || value === null || value === '') return undefined
  return value
}

/** Answer with JSON and no caching. */
function send(payload, status = 200) {
  return Response.json(payload, {
    status,
    headers: { 'cache-control': 'no-store' },
  })
}

/**
 * Build the UI API around the operations the Host half already implements.
 *
 * Every dependency is injected rather than imported: the registry, the
 * password store and the `ssh` probe all live inside `apply()`'s closures, and
 * routing them through this object is what keeps one implementation of each.
 *
 * @param deps - registry accessors, the password store, the probe and the import.
 */
export function createUiApi(deps) {
  const {
    registryPath, sshConfigPath, sshClient, knownHostsPath,
    readHosts, saveHosts, removeServer,
    findEntry, normalizeEntry, upsertEntry,
    hasPassword, readPassword, storePassword, forgetPassword,
    testEntry, importFromConfig, scanHostKey, trustHostKey,
  } = deps

  /**
   * The page-facing shape of one server.
   *
   * `identityFile` is shown because it is a path the user configured, not a
   * secret; the password itself is reduced to a boolean.
   */
  const viewOf = (entry, preferred) => ({
    name: entry.name,
    host: entry.host,
    user: entry.user ?? null,
    port: entry.port ?? 22,
    identityFile: entry.identityFile ?? null,
    workspace: entry.workspace ?? null,
    description: entry.description ?? null,
    addedAt: entry.addedAt ?? null,
    addedBy: entry.addedBy ?? null,
    locked: entry.locked === true,
    isDefault: preferred === entry.name,
    hasPassword: hasPassword(entry.name),
  })

  /**
   * Read the registry and project it for the page.
   *
   * A read that repairs a bad row returns warnings; they are passed through so
   * the page can show the same remarks `/ssh` prints instead of hiding them.
   */
  const snapshot = () => {
    const state = readHosts()
    return {
      servers: state.hosts.map((entry) => viewOf(entry, state.default)),
      default: state.default ?? null,
      warnings: state.warnings ?? [],
      paths: {
        registry: registryPath,
        sshConfig: sshConfigPath,
        sshClient,
        knownHosts: knownHostsPath,
      },
    }
  }

  /** Answer with the current snapshot after a change. */
  const answered = (extra = {}) => ({ ok: true, ...extra, ...snapshot() })

  /** Find a server by name or raise the message the page will show. */
  const requireEntry = (state, name) => {
    const entry = findEntry(state.hosts, name)
    if (entry === undefined) {
      const known = state.hosts.map((candidate) => candidate.name).join(', ')
      throw new Error(`Unknown server "${name}". Registered: ${known.length === 0 ? 'none' : known}.`)
    }
    return entry
  }

  /** Create or update one server from the editor form. */
  const save = (body) => {
    const state = readHosts()
    const entry = normalizeEntry({
      name: required(body.name, 'Name'),
      host: required(body.host, 'Address'),
      user: text(body.user),
      port: port(body.port),
      identityFile: text(body.identityFile),
      workspace: text(body.workspace),
      description: text(body.description),
      // Provenance is rewritten on every save: an entry edited in the UI is a
      // user edit even if an agent created it first, and the registry should
      // say so rather than keep a stale trail.
      addedAt: new Date().toISOString(),
      addedBy: 'ui',
      locked: flag(body.locked, false),
    })

    const originalName = text(body.originalName)
    // The destination name and the row the editor opened are two different
    // lookups: renaming is a move between them, and only an unchanged pair is an
    // ordinary in-place update.
    const target = findEntry(state.hosts, entry.name)
    const previous = originalName === undefined ? undefined : findEntry(state.hosts, originalName)
    // A name another server already holds is refused, not overwritten: the
    // editor says which entry it opened, so a different destination is a request
    // for a NEW name that happens to collide, and an add collides the same way.
    if (target !== undefined && (previous === undefined || target.name !== previous.name)) {
      throw new Error(`A server named "${entry.name}" already exists. Choose another name.`)
    }
    // A same-name save preserves the stored password and the provenance: the
    // editor never receives the password, so rewriting the entry must not be
    // read as "the password was cleared". The lock is carried over only when the
    // form did not say otherwise, so an edit cannot unlock a server the user
    // locked from `/ssh`.
    const current = previous ?? target
    if (current !== undefined) {
      entry.addedAt = current.addedAt ?? entry.addedAt
      entry.addedBy = current.addedBy ?? entry.addedBy
      if (flag(body.locked, current.locked === true)) entry.locked = true
      else delete entry.locked
    }
    const renamed = previous !== undefined && previous.name !== entry.name
    // A rename keeps the entry's position in the list, so the order the user
    // arranged by adding servers survives an edit.
    const next = renamed
      ? state.hosts.map((candidate) => (candidate.name === previous.name ? entry : candidate))
      : upsertEntry(state.hosts, entry, current !== undefined)
    const wasDefault = renamed && state.default === previous.name
    return {
      next,
      entry,
      wasDefault,
      previousDefault: state.default,
      // The credential is keyed by name, so a rename has to carry it: otherwise
      // the password silently disappears from the entry AND the old secret stays
      // on disk under a name nothing lists any more.
      renamedFrom: renamed ? previous.name : undefined,
    }
  }

  /**
   * Dispatch one action.
   *
   * @param body - the parsed request object with `action`.
   * @returns the payload to answer with.
   */
  const dispatch = async (body) => {
    const action = text(body.action)
    if (action === undefined || !UI_ACTIONS.includes(action)) {
      return { status: 400, payload: { ok: false, error: `Unknown action "${String(body.action ?? '')}".` } }
    }

    if (action === 'state') return { status: 200, payload: answered() }

    if (action === 'save') {
      const prepared = save(body)
      await saveHosts(prepared.next, prepared.wasDefault ? prepared.entry.name : prepared.previousDefault)
      // A password typed in the same form as the entry is stored now, not on a
      // second visit: adding a server that needs a password and then being told
      // to save it first was exactly the round trip this page exists to remove.
      // An empty field means "leave whatever is stored", so an edit that does
      // not touch the credential cannot clear it.
      const password = typeof body.password === 'string' ? body.password : ''
      if (password.length > 0) {
        await storePassword(prepared.entry.name, password)
      } else if (prepared.renamedFrom !== undefined) {
        // A rename with no new password moves the stored one with the entry.
        const moved = readPassword(prepared.renamedFrom)
        if (moved !== undefined) {
          await storePassword(prepared.entry.name, moved)
          await forgetPassword(prepared.renamedFrom)
        }
      }
      if (password.length > 0 || prepared.renamedFrom !== undefined) {
        return {
          status: 200,
          payload: answered({ saved: prepared.entry.name, password: { name: prepared.entry.name, saved: password.length > 0 } }),
        }
      }
      return { status: 200, payload: answered({ saved: prepared.entry.name }) }
    }

    if (action === 'remove') {
      const state = readHosts()
      const entry = requireEntry(state, required(body.name, 'Name'))
      const wasDefault = state.default === entry.name
      await saveHosts(removeServer(state.hosts, entry.name), wasDefault ? '' : state.default)
      return { status: 200, payload: answered({ removed: entry.name, defaultCleared: wasDefault }) }
    }

    if (action === 'default') {
      const state = readHosts()
      const name = text(body.name)
      if (name === undefined) {
        await saveHosts(state.hosts, '')
        return { status: 200, payload: answered({ default: null }) }
      }
      const entry = requireEntry(state, name)
      await saveHosts(state.hosts, entry.name)
      return { status: 200, payload: answered({ default: entry.name }) }
    }

    if (action === 'lock' || action === 'unlock') {
      const state = readHosts()
      const entry = requireEntry(state, required(body.name, 'Name'))
      const locked = action === 'lock'
      // `locked` is added or removed rather than set to a value, so an unlocked
      // entry stays byte-identical to what it was before.
      const next = { ...entry }
      if (locked) next.locked = true
      else delete next.locked
      await saveHosts(state.hosts.map((candidate) => (candidate.name === entry.name ? next : candidate)))
      return { status: 200, payload: answered({ locked: { name: entry.name, locked } }) }
    }

    if (action === 'test') {
      const state = readHosts()
      const entry = requireEntry(state, required(body.name, 'Name'))
      const tested = await testEntry(entry)
      return { status: 200, payload: answered({ test: { name: entry.name, ok: tested.code === undefined, code: tested.code ?? null, text: tested.text } }) }
    }

    if (action === 'import') {
      const imported = await importFromConfig()
      if (imported.error !== undefined) return { status: 200, payload: { ok: false, error: imported.error } }
      return {
        status: 200,
        payload: answered({ imported: { added: imported.added, skipped: imported.skipped, found: imported.found } }),
      }
    }

    if (action === 'password') {
      const state = readHosts()
      const entry = requireEntry(state, required(body.name, 'Name'))
      // The password keeps every byte the user typed except the field's own
      // surrounding whitespace: trimming a credential changes it silently.
      const password = typeof body.password === 'string' ? body.password : ''
      if (password.length === 0) throw new Error('The password is empty.')
      await storePassword(entry.name, password)
      const tested = await testEntry(entry)
      return {
        status: 200,
        payload: answered({ password: { name: entry.name, saved: true, test: { ok: tested.code === undefined, code: tested.code ?? null, text: tested.text } } }),
      }
    }

    if (action === 'keyScan' || action === 'keyTrust') {
      const state = readHosts()
      const entry = requireEntry(state, required(body.name, 'Name'))
      // The lock means "do not touch this machine", and asking it for its key
      // opens a connection like any other operation.
      if (entry.locked === true) {
        return {
          status: 200,
          payload: { ok: false, error: `Server "${entry.name}" is locked; unlock it before confirming its host key.` },
        }
      }
      if (action === 'keyScan') {
        const scanned = await scanHostKey(entry)
        if (scanned.error !== undefined) return { status: 200, payload: { ok: false, error: scanned.error } }
        // Only what the page renders: the key type and its fingerprint. The blob
        // stays on the Host, where the trust decision writes it.
        return {
          status: 200,
          payload: { ok: true, name: entry.name, keys: scanned.keys.map(({ type, fingerprint }) => ({ type, fingerprint })) },
        }
      }
      const fingerprints = Array.isArray(body.fingerprints) ? body.fingerprints : []
      const trusted = await trustHostKey(entry, fingerprints)
      const tested = await testEntry(entry)
      return {
        status: 200,
        payload: answered({
          trusted: { name: entry.name, path: trusted.path, added: trusted.added },
          test: { name: entry.name, ok: tested.code === undefined, code: tested.code ?? null, text: tested.text },
        }),
      }
    }

    // clearPassword
    const state = readHosts()
    const entry = requireEntry(state, required(body.name, 'Name'))
    await forgetPassword(entry.name)
    return { status: 200, payload: answered({ password: { name: entry.name, saved: false } }) }
  }

  /**
   * Serve one authenticated request from the settings page.
   *
   * @param request - the Fetch request the Connection handler admitted.
   * @returns the JSON response.
   */
  const handle = async (request) => {
    try {
      if (request.method === 'GET' || request.method === 'HEAD') {
        return send({ ok: true, ...snapshot() })
      }
      if (request.method !== 'POST') return send({ ok: false, error: 'Method not allowed.' }, 405)

      const raw = await request.text()
      if (raw.length > MAX_BODY_BYTES) return send({ ok: false, error: 'The request is too large.' }, 413)
      let body
      try {
        body = JSON.parse(raw.length === 0 ? '{}' : raw)
      } catch {
        return send({ ok: false, error: 'The request body is not valid JSON.' }, 400)
      }
      if (body === null || typeof body !== 'object' || Array.isArray(body)) {
        return send({ ok: false, error: 'The request body must be an object.' }, 400)
      }

      const result = await dispatch(body)
      return send(result.payload, result.status)
    } catch (error) {
      // A refusal is a normal answer here: the page shows the sentence and the
      // user fixes the field. Only an unforeseen fault is a 500.
      const message = String(error?.message ?? error)
      const code = typeof error?.code === 'string' ? error.code : undefined
      const ordinary = code !== undefined || /^(Name|Address)\b/.test(message) || /^(Unknown server|A server named|The password is empty)/.test(message)
      return send({ ok: false, error: message, ...(code === undefined ? {} : { code }) }, ordinary ? 200 : 500)
    }
  }

  return { handle, snapshot }
}
