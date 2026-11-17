/**
 * Integration tests for the Settings page API (`/api/ssh-remote`).
 *
 * The route is driven through the same `apply()` the runtime mounts, with a fake
 * connection service standing in for the Fetch handler: the test exercises the
 * real action handlers, the real registry, and the real password store, and then
 * asserts on what the page would receive as JSON.
 *
 * Nothing here touches a network or a real server. The fake subprocess answers
 * like an OpenSSH client that refuses a key, which is the case the page has to
 * report honestly.
 */
import assert from 'node:assert/strict'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Isolate every run: the registry must never touch the real $DSH_HOME.
const home = await mkdtemp(join(tmpdir(), 'ssh-remote-ui-'))
process.env.DSH_HOME = home

// GitHub's published host key: an external authority for the fingerprint the
// page will show, so the assertion is not a snapshot of our own arithmetic.
const GITHUB_BLOB = 'AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'
const GITHUB_SHA256 = 'SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU'

const registryPath = join(home, 'ssh-remote-hosts.json')
const secretsPath = join(home, 'ssh-remote-secrets.json')
const askpassDir = join(home, 'askpass')
const auditPath = join(home, 'ssh-remote-audit.jsonl')
const sshConfigPath = join(home, 'ssh-config')
const knownHostsPath = join(home, 'known_hosts')

await writeFile(
  registryPath,
  JSON.stringify({
    version: 1,
    default: 'good',
    hosts: [
      { name: 'good', host: '10.0.0.1', user: 'root' },
      { name: 'locked', host: '10.0.0.2', user: 'root', locked: true },
    ],
  }),
  'utf-8',
)

await writeFile(
  sshConfigPath,
  [
    'Host imported1',
    '  HostName 192.0.2.10',
    '  User deploy',
    '  Port 2222',
    '  IdentityFile ~/.ssh/id_ed25519',
    '',
    'Host wildcard*',
    '  HostName 192.0.2.11',
    '',
  ].join('\n'),
  'utf-8',
)

// ---------- fake runtime ----------

/** The exact route the plugin registers on the connection service. */
let route

/** A subprocess that refuses authentication, like a server without our key. */
const subprocess = {
  spawn({ argv }) {
    assert.ok(Array.isArray(argv) && argv.length > 0)
    // The host-key probe runs `ssh` with a throwaway UserKnownHostsFile. The
    // fake plays the server: it records the key the probe would have learned, so
    // the scan and trust paths exercise the real parsing and merge code.
    const knownHostsOption = argv.find((argument) => argument.startsWith('UserKnownHostsFile='))
    if (knownHostsOption !== undefined) {
      const file = knownHostsOption.slice('UserKnownHostsFile='.length).replace(/^"|"$/g, '')
      const destination = argv[argv.length - 2]
      const host = destination.includes('@') ? destination.slice(destination.indexOf('@') + 1) : destination
      writeFileSync(file, `${host} ssh-ed25519 ${GITHUB_BLOB}\n`, 'utf8')
    }
    const reader = (text) => ({ readFrom: () => ({ text, lossy: false }) })
    return {
      collected: {
        stdout: reader(''),
        stderr: reader('root@10.0.0.1: Permission denied (publickey).'),
      },
      terminate() {},
      done: Promise.resolve({ exitCode: 255, signal: undefined }),
    }
  },
}

const ctx = {
  logger: {
    info: () => {},
    warn: () => {},
    error: () => {},
    debug: () => {},
  },
  get: (name) => (name === 'subprocess' ? subprocess : undefined),
  tools: {
    register: () => () => {},
    guard: () => () => {},
  },
  effect(callback) {
    const dispose = callback()
    return dispose ?? (() => {})
  },
  inject(services, callback) {
    if (services.includes('commands')) {
      callback({ commands: { register: () => () => {} } })
    }
    if (services.includes('connection')) {
      callback({
        connection: {
          fetch: {
            register(definition) {
              route = definition
              return async () => {
                route = undefined
              }
            },
          },
        },
        effect: ctx.effect,
      })
    }
  },
}

const { apply, name } = await import('./index.js')

apply(ctx, {
  registryPath,
  secretsPath,
  askpassDir,
  sshConfigPath,
  knownHostsPath,
  sshPath: 'C:/fake/ssh',
  scpPath: 'C:/fake/scp',
  connectTimeoutMs: 1_000,
  serverAliveIntervalMs: 15,
  defaultTimeoutMs: 5_000,
  maxTimeoutMs: 10_000,
  maxOutputChars: 1_000,
  multiplex: false,
  auditLogPath: auditPath,
})

/** Call one action through the registered Fetch route. */
async function call(action, args) {
  assert.equal(route?.path, '/api/ssh-remote', 'the page route must be registered')
  const request = new Request('http://127.0.0.1/api/ssh-remote', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ action, ...(args ?? {}) }),
  })
  const response = await route.fetch(request)
  const text = await response.text()
  return { status: response.status, payload: JSON.parse(text), text }
}

/** Read the registry file as the plugin wrote it. */
async function registry() {
  return JSON.parse(await readFile(registryPath, 'utf-8'))
}

let passed = 0
const failures = []

/** Run one named check, collecting failures instead of stopping the run. */
async function ok(label, body) {
  try {
    await body()
    passed += 1
  } catch (error) {
    failures.push({ label, error })
  }
}

await ok('the plugin still carries its row name', async () => {
  assert.equal(name, 'ssh-remote')
})

await ok('the route is registered on the connection service', async () => {
  assert.ok(route !== undefined, 'no route was registered')
  assert.equal(route.path, '/api/ssh-remote')
  assert.deepEqual(route.methods, ['GET', 'POST'])
  assert.equal(route.requestBody, 'buffered')
})

await ok('GET answers the projected registry', async () => {
  const request = new Request('http://127.0.0.1/api/ssh-remote', { method: 'GET' })
  const response = await route.fetch(request)
  const payload = await response.json()
  assert.equal(response.status, 200)
  assert.equal(payload.ok, true)
  assert.equal(payload.default, 'good')
  assert.deepEqual(payload.servers.map((server) => server.name), ['good', 'locked'])
  assert.equal(payload.servers[0].isDefault, true)
  assert.equal(payload.servers[1].locked, true)
  assert.equal(payload.servers[0].port, 22)
  assert.equal(payload.paths.registry, registryPath)
  assert.equal(payload.paths.sshConfig, sshConfigPath)
})

await ok('state carries no credential', async () => {
  const { text } = await call('state')
  assert.ok(!/password"\s*:\s*"/.test(text), 'a password value leaked into the response')
})

await ok('save adds a server and the page sees it', async () => {
  const { payload } = await call('save', {
    name: 'web1',
    host: '203.0.113.9',
    user: 'deploy',
    port: 2222,
    identityFile: '~/.ssh/id_ed25519',
    workspace: '/srv/app',
    description: 'production',
  })
  assert.equal(payload.ok, true)
  assert.equal(payload.saved, 'web1')
  const saved = payload.servers.find((server) => server.name === 'web1')
  assert.equal(saved.host, '203.0.113.9')
  assert.equal(saved.port, 2222)
  assert.equal(saved.addedBy, 'ui')
  const document = await registry()
  assert.equal(document.hosts.length, 3)
  assert.equal(document.hosts.find((entry) => entry.name === 'web1').workspace, '/srv/app')
})

await ok('save refuses a name another server already holds', async () => {
  const { payload, status } = await call('save', { name: 'good', host: '203.0.113.99' })
  assert.equal(status, 200)
  assert.equal(payload.ok, false)
  assert.match(payload.error, /already exists/)
})

await ok('save renames an edited entry without touching the old one', async () => {
  const first = await call('save', { name: 'renamed', host: '203.0.113.9', originalName: 'web1' })
  assert.equal(first.payload.ok, true)
  const names = first.payload.servers.map((server) => server.name)
  assert.ok(names.includes('renamed'))
  assert.ok(!names.includes('web1'))
})

await ok('save keeps a server locked unless the form unlocks it', async () => {
  const locked = await call('save', { name: 'locked', host: '10.0.0.2', user: 'root', originalName: 'locked' })
  assert.equal(locked.payload.ok, true)
  assert.equal(locked.payload.servers.find((server) => server.name === 'locked').locked, true)
})

await ok('save unlocks only when the form says so', async () => {
  const unlocked = await call('save', { name: 'locked', host: '10.0.0.2', user: 'root', originalName: 'locked', locked: false })
  assert.equal(unlocked.payload.ok, true)
  assert.equal(unlocked.payload.servers.find((server) => server.name === 'locked').locked, false)
  const relocked = await call('lock', { name: 'locked' })
  assert.equal(relocked.payload.ok, true)
})

await ok('save validates the port', async () => {
  const { payload } = await call('save', { name: 'badport', host: '203.0.113.7', port: 70000 })
  assert.equal(payload.ok, false)
  assert.match(payload.error, /invalid port/i)
})

await ok('default selects and clears the preferred server', async () => {
  const set = await call('default', { name: 'renamed' })
  assert.equal(set.payload.default, 'renamed')
  assert.equal((await registry()).default, 'renamed')
  const cleared = await call('default', {})
  assert.equal(cleared.payload.default, null)
  assert.equal((await registry()).default, undefined)
})

await ok('lock and unlock flip the flag on disk', async () => {
  const unlocked = await call('unlock', { name: 'locked' })
  assert.equal(unlocked.payload.ok, true)
  assert.equal(unlocked.payload.servers.find((server) => server.name === 'locked').locked, false)
  assert.equal((await registry()).hosts.find((entry) => entry.name === 'locked').locked, undefined)

  const locked = await call('lock', { name: 'locked' })
  assert.equal(locked.payload.servers.find((server) => server.name === 'locked').locked, true)
  assert.equal((await registry()).hosts.find((entry) => entry.name === 'locked').locked, true)
})

await ok('remove forgets the entry and clears a default that named it', async () => {
  await call('default', { name: 'renamed' })
  const { payload } = await call('remove', { name: 'renamed' })
  assert.equal(payload.ok, true)
  assert.equal(payload.defaultCleared, true)
  assert.equal(payload.default, null)
  assert.ok(!payload.servers.some((server) => server.name === 'renamed'))
})

await ok('remove refuses an unknown name', async () => {
  const { payload } = await call('remove', { name: 'nope' })
  assert.equal(payload.ok, false)
  assert.match(payload.error, /Unknown server/)
})

await ok('import adds hosts from the SSH config and skips patterns', async () => {
  const { payload } = await call('import')
  assert.equal(payload.ok, true)
  assert.deepEqual(payload.imported.added, ['imported1'])
  assert.ok(payload.imported.skipped.includes('wildcard*'))
  const imported = payload.servers.find((server) => server.name === 'imported1')
  assert.equal(imported.host, '192.0.2.10')
  assert.equal(imported.user, 'deploy')
  assert.equal(imported.port, 2222)
})

await ok('password is stored write-only and reported as a boolean', async () => {
  const { payload, text } = await call('password', { name: 'good', password: '  s3cret  ' })
  assert.equal(payload.ok, true)
  assert.equal(payload.password.saved, true)
  assert.equal(payload.servers.find((server) => server.name === 'good').hasPassword, true)
  assert.ok(!text.includes('s3cret'), 'the stored password was echoed back')
  const secrets = JSON.parse(await readFile(secretsPath, 'utf-8'))
  // The credential keeps the bytes the user typed; only the page's transport is
  // trusted to decide what a surrounding space means.
  assert.equal(secrets.passwords.good, '  s3cret  ')
})

await ok('password action reports the probe outcome', async () => {
  const { payload } = await call('password', { name: 'good', password: 'x' })
  assert.equal(payload.ok, true)
  assert.equal(payload.password.test.ok, false)
  assert.equal(payload.password.test.code, 'AUTH_FAILED')
  assert.match(payload.password.test.text, /пароль/i)
})

await ok('clearPassword forgets the credential', async () => {
  const { payload } = await call('clearPassword', { name: 'good' })
  assert.equal(payload.ok, true)
  assert.equal(payload.servers.find((server) => server.name === 'good').hasPassword, false)
  const secrets = JSON.parse(await readFile(secretsPath, 'utf-8'))
  assert.equal(secrets.passwords.good, undefined)
})

await ok('test reports the classified refusal instead of throwing', async () => {
  const { payload, status } = await call('test', { name: 'good' })
  assert.equal(status, 200)
  assert.equal(payload.ok, true)
  assert.equal(payload.test.ok, false)
  assert.equal(payload.test.code, 'AUTH_FAILED')
  assert.match(payload.test.text, /Сервер good/)
})

await ok('test refuses without opening a connection to a locked server', async () => {
  const { payload } = await call('test', { name: 'locked' })
  assert.equal(payload.test.ok, false)
  assert.equal(payload.test.code, 'HOST_LOCKED')
})

await ok('an unknown action is a 400', async () => {
  const { status, payload } = await call('nonsense')
  assert.equal(status, 400)
  assert.equal(payload.ok, false)
})

await ok('a malformed body is a 400', async () => {
  const request = new Request('http://127.0.0.1/api/ssh-remote', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{',
  })
  const response = await route.fetch(request)
  assert.equal(response.status, 400)
})

await ok('an unsupported method is a 405', async () => {
  const request = new Request('http://127.0.0.1/api/ssh-remote', { method: 'DELETE' })
  const response = await route.fetch(request)
  assert.equal(response.status, 405)
})

await ok('save stores a password in the same call', async () => {
  // Adding a server that needs a password used to take two visits: save, then
  // edit, then set the password. The form sends both at once now.
  const { payload, text } = await call('save', {
    name: 'withpass',
    host: '198.51.100.7',
    user: 'root',
    password: 'hunter2',
  })
  assert.equal(payload.ok, true)
  assert.equal(payload.password?.saved, true)
  assert.equal(payload.servers.find((server) => server.name === 'withpass').hasPassword, true)
  assert.ok(!text.includes('hunter2'), 'the password echoed back')
  const secrets = JSON.parse(await readFile(secretsPath, 'utf-8'))
  assert.equal(secrets.passwords.withpass, 'hunter2')
})

await ok('a save without a password leaves the stored one alone', async () => {
  const { payload } = await call('save', {
    name: 'withpass',
    host: '198.51.100.7',
    user: 'deploy',
    originalName: 'withpass',
  })
  assert.equal(payload.ok, true)
  assert.equal(payload.servers.find((server) => server.name === 'withpass').hasPassword, true)
})

await ok('a rename carries the stored password with the entry', async () => {
  const renamed = await call('save', {
    name: 'withpass renamed',
    host: '198.51.100.7',
    user: 'deploy',
    originalName: 'withpass',
  })
  assert.equal(renamed.payload.ok, true)
  assert.equal(renamed.payload.servers.find((server) => server.name === 'withpass renamed').hasPassword, true)
  const secrets = JSON.parse(await readFile(secretsPath, 'utf-8'))
  assert.equal(secrets.passwords.withpass, undefined, 'the old name kept the secret')
  assert.equal(secrets.passwords['withpass renamed'], 'hunter2')
})

await ok('a server name may be several words', async () => {
  const { payload } = await call('save', { name: 'Example  VPS Server', host: '198.51.100.8' })
  assert.equal(payload.ok, true)
  // Runs of whitespace collapse, so the name is one identity.
  assert.equal(payload.saved, 'Example VPS Server')
  assert.ok(payload.servers.some((server) => server.name === 'Example VPS Server'))
})

await ok('keyScan reports the key the server presents', async () => {
  const { payload } = await call('keyScan', { name: 'good' })
  assert.equal(payload.ok, true)
  assert.equal(payload.keys.length, 1)
  assert.equal(payload.keys[0].type, 'ssh-ed25519')
  assert.equal(payload.keys[0].fingerprint, GITHUB_SHA256)
})

await ok('keyTrust records only the approved fingerprint', async () => {
  const { payload } = await call('keyTrust', { name: 'good', fingerprints: [GITHUB_SHA256] })
  assert.equal(payload.ok, true)
  assert.deepEqual(payload.trusted.added, ['ssh-ed25519'])
  assert.equal(payload.trusted.path, knownHostsPath)
  const written = await readFile(knownHostsPath, 'utf-8')
  assert.ok(written.includes(`10.0.0.1 ssh-ed25519 ${GITHUB_BLOB}`), `known_hosts did not get the key: ${written}`)
  // Trusting a key is not "connected": the probe still reports the auth failure.
  assert.equal(payload.test.code, 'AUTH_FAILED')
})

await ok('keyTrust refuses a fingerprint the server does not present', async () => {
  const { payload } = await call('keyTrust', { name: 'good', fingerprints: ['SHA256:somethingelse'] })
  assert.equal(payload.ok, false)
  assert.equal(payload.code, 'KEY_MISMATCH')
})

await ok('keyTrust refuses a changed key instead of appending it', async () => {
  // The changed-key case must stay the human's ssh-keygen -R, never a button.
  await call('unlock', { name: 'locked' })
  await writeFile(knownHostsPath, `10.0.0.2 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherKey000000000000000000000000000\n`, 'utf-8')
  const { payload } = await call('keyTrust', { name: 'locked', fingerprints: [GITHUB_SHA256] })
  assert.equal(payload.ok, false)
  assert.equal(payload.code, 'KEY_CONFLICT')
  assert.match(payload.error, /changed-key case/)
})

await ok('a locked server is not asked for its key', async () => {
  await call('lock', { name: 'locked' })
  const scanned = await call('keyScan', { name: 'locked' })
  assert.equal(scanned.payload.ok, false)
  assert.match(scanned.payload.error, /locked/)
  const trusted = await call('keyTrust', { name: 'locked', fingerprints: [GITHUB_SHA256] })
  assert.equal(trusted.payload.ok, false)
  assert.match(trusted.payload.error, /locked/)
})

for (const failure of failures) {
  console.error(`✗ ${failure.label}`)
  console.error(failure.error)
}
console.log(`\n${passed} passed, ${failures.length} failed`)
if (failures.length > 0) process.exitCode = 1
