/**
 * Integration tests for the Host half, driven through a fake Cordis context and
 * a fake `ssh` executable.
 *
 * The point is to exercise the real tool bodies — argument validation, registry
 * resolution, confirmation, and failure mapping — without a network or a real
 * server. The fake client is a Node script that replays canned outcomes, so the
 * test controls exactly what the plugin sees.
 */
import assert from 'node:assert/strict'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { shellQuote, detachedBody } from './args.js'

// Isolate every run: the registry must never touch the real $DSH_HOME.
const home = await mkdtemp(join(tmpdir(), 'ssh-remote-host-'))
process.env.DSH_HOME = home

const registryPath = join(home, 'ssh-remote-hosts.json')
const secretsPath = join(home, 'ssh-remote-secrets.json')
const askpassDir = join(home, 'askpass')
const auditPath = join(home, 'ssh-remote-audit.jsonl')
await writeFile(
  registryPath,
  JSON.stringify({
    version: 1,
    hosts: [
      { name: 'good', host: '10.0.0.1', user: 'root' },
      { name: 'dead', host: '10.0.0.2', user: 'root' },
    ],
  }),
  'utf-8',
)

const { apply, describeWriteFailure, GREP_STATUS, PIPE_STATUS } = await import('./index.js')

/** Configuration shared by every activation in this test. */
const baseConfig = {
  registryPath,
  secretsPath,
  askpassDir,
  sshPath: 'C:/fake/ssh',
  scpPath: 'C:/fake/scp',
  connectTimeoutMs: 1_000,
  serverAliveIntervalSec: 15,
  serverAliveCountMax: 3,
  defaultTimeoutMs: 5_000,
  maxTimeoutMs: 10_000,
  maxOutputChars: 1_000,
  multiplex: false,
  auditLogPath: auditPath,
}

// ---------- fake runtime ----------

let tools = new Map()
let guards = []
let command
const logs = []
/** The answers the human "gives" during a test. */
let answers = {}
/** Knobs controlling how the fake question service behaves. */
const questionControl = { present: true, throw: undefined }

const ctx = {
  logger: {
    info: (message, ...rest) => logs.push(['info', message, ...rest]),
    warn: (message, ...rest) => logs.push(['warn', message, ...rest]),
    error: () => {},
    debug: () => {},
  },
  get: (name) => {
    if (name === 'subprocess') return subprocess
    if (name === 'userQuestions') {
      if (!questionControl.present) return undefined
      return {
        ask: async (request) => {
          if (questionControl.throw !== undefined) throw new Error(questionControl.throw)
          // Record what was asked so a test can assert the confirmation content.
          ctx.asked = request.questions
          return {
            answers: request.questions.map((question) => ({
              id: question.id,
              selected: [answers[question.id] ?? question.options?.[0]?.label ?? ''],
            })),
          }
        },
      }
    }
    return undefined
  },
  tools: {
    register(definition) {
      tools.set(definition.name, definition)
      return () => {}
    },
    guard(fn) {
      guards.push(fn)
      return () => {}
    },
  },
  inject(services, callback) {
    if (services.includes('commands')) {
      callback({
        commands: {
          register: (definition) => {
            command = definition
            recordInput = definition.recordInput
            return () => {}
          },
        },
      })
    }
  },
  effect: () => () => {},
}

// A fake subprocess, entirely in-process.
//
// It deliberately spawns nothing: the DSH sandbox forbids piped stdio across a
// process boundary, and this test needs to capture output. The plugin still goes
// through the real `subprocess.spawn` contract — argv in, collected readers and
// `done` out — so every branch of the plugin is exercised. The real binary was
// validated separately against OpenSSH itself.
const scenarioResult = (argv) => {
  const scenario = process.env.FAKE_SCENARIO ?? 'ok'
  const last = argv[argv.length - 1]
  if (scenario === 'ok') return { exitCode: 0, stdout: 'Linux vps 6.1.0 x86_64\n', stderr: '' }
  if (scenario === 'remote-fail') {
    return { exitCode: 127, stdout: 'partial output\n', stderr: 'bash: nope: command not found\n' }
  }
  if (scenario === 'nokey') {
    return { exitCode: 255, stdout: '', stderr: 'root@10.0.0.1: Permission denied (publickey,password).\n' }
  }
  if (scenario === 'changed-key') {
    return { exitCode: 255, stdout: '', stderr: 'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n' }
  }
  if (scenario === 'echo-argv') {
    return { exitCode: 0, stdout: `${JSON.stringify(argv)}\n`, stderr: '' }
  }
  if (scenario === 'redact') {
    // The output of `cat ~/.ssh/id_rsa` and of `env`, which must not reach the
    // model verbatim.
    return {
      exitCode: 0,
      stdout: '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3NzaC1yc2E\n-----END OPENSSH PRIVATE KEY-----\n',
      stderr: 'DB_PASSWORD=hunter2\n',
    }
  }
  if (scenario === 'long-output') {
    // 6000 characters, so the per-stream ceiling of 1000 has to keep both ends.
    return { exitCode: 0, stdout: `${'H'.repeat(4_000)}${'T'.repeat(2_000)}`, stderr: '' }
  }
  if (scenario === 'many-lines') {
    return { exitCode: 0, stdout: `${Array.from({ length: 250 }, (_, index) => `entry-${index + 1}`).join('\n')}\n`, stderr: '' }
  }
  if (scenario === 'many-matches') {
    return {
      exitCode: 0,
      stdout: `${Array.from({ length: 150 }, (_, index) => `src/app.js:${index + 1}:ERROR here`).join('\n')}\n`,
      stderr: '',
    }
  }
  if (scenario === 'read-window') {
    // One line more than the requested window: proof that more lines follow.
    return { exitCode: 0, stdout: `${Array.from({ length: 201 }, (_, index) => `line ${index + 1}`).join('\n')}\n`, stderr: '' }
  }
  if (scenario === 'no-matches') {
    return { exitCode: 0, stdout: 'no matches\n', stderr: '' }
  }
  if (scenario === 'detached') {
    return { exitCode: 0, stdout: '4242\n', stderr: '' }
  }
  return { exitCode: 0, stdout: '', stderr: '' }
}

/** Terms the plugin explicitly requested, so a test can assert real termination. */
const terminated = []
/** The env of the most recent spawn, so a test can inspect askpass delivery. */
let lastSpawnEnv
/** Every spawn env for one call, since a multi-host probe spawns once per host. */
let spawnEnvs = []
/** The `/ssh` command's `recordInput` flag, asserted to be false. */
let recordInput
const subprocess = {
  spawn(spec) {
    const [program, ...rest] = spec.argv
    assert.ok(typeof program === 'string' && program.length > 0, 'a program must be supplied')
    assert.ok(typeof spec.cwd === 'string' && spec.cwd.length > 0, 'spawn requires a real cwd')
    lastSpawnEnv = spec.env
    spawnEnvs.push({ argv: spec.argv, env: spec.env })

    let outcome
    let settle
    const done = new Promise((resolve) => { settle = resolve })
    // `hang` never settles on its own; only terminate() releases it.
    if ((process.env.FAKE_SCENARIO ?? 'ok') !== 'hang') {
      outcome = scenarioResult(spec.argv)
      queueMicrotask(() => settle({ exitCode: outcome.exitCode, signal: null }))
    }
    const collected = {
      stdout: outcome?.stdout ?? '',
      stderr: outcome?.stderr ?? '',
    }
    const reader = (key) => ({ readFrom: () => ({ text: collected[key], nextOffset: 0, lossy: false }) })
    return {
      collected: { stdout: reader('stdout'), stderr: reader('stderr') },
      done,
      terminate() {
        terminated.push(spec.argv)
        // A terminated process still resolves with its exit facts.
        if (outcome === undefined) {
          outcome = { exitCode: null, signal: 'SIGTERM' }
          collected.stdout = ''
          collected.stderr = ''
        }
        settle({ exitCode: outcome.exitCode, signal: outcome.signal ?? 'SIGTERM' })
      },
      waitForExit: () => done.then(() => true),
    }
  },
  resolveExecutable: async (name) => name,
}

apply(ctx, baseConfig)

let checks = 0
/** Run one async assertion group with a readable label. */
const ok = async (label, fn) => {
  await fn()
  checks += 1
  console.log(`  ok  ${label}`)
}

/** Invoke a registered tool the way the registry would. */
const call = (name, args, workspace) => {
  const tool = tools.get(name)
  assert.ok(tool, `tool ${name} must be registered`)
  return tool.execute(args, {
    agent: { id: 'session-1', session: { header: { cwd: workspace ?? process.cwd() } } },
    signal: new AbortController().signal,
  })
}

/** The last argv the fake client received, decoded from an `echo-argv` report. */
const lastArgv = () => {
  const spawns = spawnEnvs.at(-1)
  assert.ok(spawns !== undefined, 'a spawn must have happened')
  return spawns.argv
}

// ---------- registration ----------

await ok('all ten tools and the /ssh command are registered', () => {
  for (const name of [
    'ssh_hosts',
    'ssh_host_add',
    'ssh_host_remove',
    'ssh_run',
    'ssh_put',
    'ssh_get',
    'ssh_read',
    'ssh_ls',
    'ssh_grep',
    'ssh_glob',
  ]) {
    assert.ok(tools.has(name), `${name} must be registered`)
  }
  assert.equal(command.name, 'ssh')
})

await ok('a guard restricts unregistered servers', () => {
  assert.ok(guards.length > 0)
  const guard = guards[0]
  assert.equal(guard({ name: 'ssh_run', arguments: { host: 'good', command: 'true' } }), undefined)
  assert.match(guard({ name: 'ssh_run', arguments: { host: 'evil', command: 'true' } }), /Unknown server/)
  // The guard must not interfere with unrelated tools.
  assert.equal(guard({ name: 'read', arguments: {} }), undefined)
})

// ---------- ssh_run ----------

await ok('a successful run reports the exit code and stdout', async () => {
  process.env.FAKE_SCENARIO = 'ok'
  const report = await call('ssh_run', { host: 'good', command: 'uname -a' })
  assert.match(report, /exit=0/)
  assert.match(report, /Linux vps/)
})

await ok('an empty command is refused before spawning', async () => {
  await assert.rejects(() => call('ssh_run', { host: 'good', command: '   ' }), /non-empty/)
})

await ok('an unregistered server is refused', async () => {
  await assert.rejects(() => call('ssh_run', { host: 'evil', command: 'true' }), /Unknown server/)
})

await ok('a failing remote command surfaces an error, not success', async () => {
  process.env.FAKE_SCENARIO = 'remote-fail'
  await assert.rejects(
    () => call('ssh_run', { host: 'good', command: 'nope' }),
    (error) => {
      assert.equal(error.code, 'REMOTE_EXIT')
      // The captured output must travel with the failure so the model can see it.
      assert.match(error.message, /command not found/)
      assert.match(error.message, /exit=127/)
      return true
    },
  )
})

await ok('a missing key reports an actionable message', async () => {
  process.env.FAKE_SCENARIO = 'nokey'
  await assert.rejects(
    () => call('ssh_run', { host: 'good', command: 'true' }),
    (error) => {
      assert.equal(error.code, 'AUTH_FAILED')
      // It must name the password route now that one exists.
      assert.match(error.message, /public key/)
      assert.match(error.message, /\/ssh pass/)
      return true
    },
  )
})

await ok('with a stored password the invocation switches auth mode', async () => {
  // Store a password directly for the "good" server, bypassing the command.
  await writeFile(
    secretsPath,
    JSON.stringify({ version: 1, passwords: { good: 'stored-secret' } }),
    'utf-8',
  )
  process.env.FAKE_SCENARIO = 'echo-argv'
  const report = await call('ssh_run', { host: 'good', command: 'true' })
  const argv = JSON.parse(/\[[\s\S]*\]/.exec(report)[0])
  // BatchMode would make SSH_ASKPASS unreachable, so it must be gone.
  assert.ok(!argv.includes('BatchMode=yes'), 'BatchMode must be relaxed for a password')
  assert.ok(argv.includes('BatchMode=no'))
  assert.ok(argv.includes('NumberOfPasswordPrompts=1'), 'still exactly one attempt')
  assert.ok(argv.includes('StrictHostKeyChecking=yes'), 'host-key checking must stay strict')
  // The secret must never be on the command line.
  assert.ok(!argv.some((part) => part.includes('stored-secret')), 'the password must not be an argument')
})

await ok('a password is delivered through the askpass environment, then removed', async () => {
  process.env.FAKE_SCENARIO = 'ok'
  await call('ssh_run', { host: 'good', command: 'true' })
  // The child env carries the helper, and the plugin must clean up afterwards.
  assert.ok(lastSpawnEnv?.SSH_ASKPASS, 'the helper path must be exported to the child')
  assert.equal(lastSpawnEnv.SSH_ASKPASS_REQUIRE, 'force')
  assert.ok(lastSpawnEnv.DSH_SSH_ASKPASS_FILE, 'the secret file must be exported')
  await assert.rejects(
    () => readFile(lastSpawnEnv.DSH_SSH_ASKPASS_FILE, 'utf-8'),
    'the secret file must be deleted after the call',
  )
  await assert.rejects(() => readFile(lastSpawnEnv.SSH_ASKPASS, 'utf-8'), 'the helper must be deleted after the call')
})

await ok('an entry with its own key never falls back to a stored password', async () => {
  // A key is strictly better than a password, so a stored password must not
  // silently override an explicit identityFile.
  answers = { 'confirm-add': 'Add server' }
  await call('ssh_host_add', { name: 'keyed', host: '10.0.0.5', identityFile: 'C:/keys/id_ed25519' })
  await writeFile(
    secretsPath,
    JSON.stringify({ version: 1, passwords: { keyed: 'ignored-secret' } }),
    'utf-8',
  )
  process.env.FAKE_SCENARIO = 'echo-argv'
  const report = await call('ssh_run', { host: 'keyed', command: 'true' })
  const argv = JSON.parse(/\[[\s\S]*\]/.exec(report)[0])
  assert.ok(argv.includes('BatchMode=yes'), 'key auth must stay non-interactive')
  assert.ok(argv.includes('-i'), 'the configured key must be used')
  assert.ok(!argv.some((part) => part.includes('ignored-secret')))
})

await ok('a rejected password is explained as a password problem', async () => {
  await writeFile(secretsPath, JSON.stringify({ version: 1, passwords: { good: 'wrong' } }), 'utf-8')
  process.env.FAKE_SCENARIO = 'nokey'
  const result = await call('ssh_run', { host: 'good', command: 'true' }).then(
    () => undefined,
    (error) => error,
  )
  assert.ok(result, 'a rejected password must fail')
  assert.match(result.message, /rejected the password/)
  assert.doesNotMatch(result.message, /Install your public key/)
  // Leave no password behind for later checks.
  await writeFile(secretsPath, JSON.stringify({ version: 1, passwords: {} }), 'utf-8')
})

await ok('/ssh pass stores a password without echoing it', async () => {
  const result = await command.handler({
    agent: { id: 'session-1' },
    rawInput: 'pass good my-secret-pw',
    signal: new AbortController().signal,
  })
  assert.equal(result.kind, 'success')
  assert.ok(!result.text.includes('my-secret-pw'), 'the password must never be echoed back')
  const document = JSON.parse(await readFile(secretsPath, 'utf-8'))
  assert.equal(document.passwords.good, 'my-secret-pw')
})

await ok('/ssh pass keeps a password containing spaces intact', async () => {
  const result = await command.handler({
    agent: { id: 'session-1' },
    rawInput: 'pass good  pass with  spaces ',
    signal: new AbortController().signal,
  })
  assert.equal(result.kind, 'success')
  const document = JSON.parse(await readFile(secretsPath, 'utf-8'))
  // Everything after the separator is the password, verbatim. Interior runs of
  // spaces and a trailing space survive; only the separator itself is consumed,
  // because a leading space cannot be told apart from it.
  assert.equal(document.passwords.good, 'pass with  spaces ')
})

await ok('/ssh pass refuses an unknown server and an empty password', async () => {
  const unknown = await command.handler({
    agent: { id: 'session-1' },
    rawInput: 'pass nosuch pw',
    signal: new AbortController().signal,
  })
  assert.equal(unknown.kind, 'error')
  const empty = await command.handler({
    agent: { id: 'session-1' },
    rawInput: 'pass good',
    signal: new AbortController().signal,
  })
  assert.equal(empty.kind, 'error')
})

await ok('/ssh nopass removes a stored password', async () => {
  const result = await command.handler({
    agent: { id: 'session-1' },
    rawInput: 'nopass good',
    signal: new AbortController().signal,
  })
  assert.equal(result.kind, 'success')
  const document = JSON.parse(await readFile(secretsPath, 'utf-8'))
  assert.equal(document.passwords.good, undefined)
})

await ok('the command declares recordInput: false so a password stays out of the log', async () => {
  // A `userQuestions` answer becomes a model-readable message, so the password
  // path must be this command's own input, and that input must not be logged.
  assert.equal(recordInput, false, 'the /ssh command must not record its input')
})

await ok('a changed host key is never auto-accepted', async () => {
  process.env.FAKE_SCENARIO = 'changed-key'
  await assert.rejects(
    () => call('ssh_run', { host: 'good', command: 'true' }),
    (error) => {
      assert.equal(error.code, 'HOST_KEY_CHANGED')
      assert.doesNotMatch(error.message, /StrictHostKeyChecking=no/)
      return true
    },
  )
})

await ok('an over-deadline command is terminated and reported', async () => {
  process.env.FAKE_SCENARIO = 'hang'
  terminated.length = 0
  await assert.rejects(
    () => call('ssh_run', { host: 'good', command: 'sleep 999', timeoutMs: 700 }),
    (error) => {
      assert.equal(error.code, 'TIMEOUT')
      assert.match(error.message, /deadline/)
      return true
    },
  )
  // The managed range must actually have been signalled, not merely reported.
  assert.equal(terminated.length, 1, 'the process must be terminated on timeout')
})

await ok('the timeout ceiling is enforced and a bad value refused', async () => {
  process.env.FAKE_SCENARIO = 'ok'
  await assert.rejects(() => call('ssh_run', { host: 'good', command: 'true', timeoutMs: -5 }), /positive number/)
  // A huge request is clamped rather than rejected, so the call still succeeds.
  const report = await call('ssh_run', { host: 'good', command: 'true', timeoutMs: 9_999_999 })
  assert.match(report, /exit=0/)
})

await ok('the remote command is passed as a single argument', async () => {
  process.env.FAKE_SCENARIO = 'echo-argv'
  const report = await call('ssh_run', { host: 'good', command: 'echo "a b" | wc -l' })
  // The fake echoes the exact argv the plugin built, so these are real argv
  // assertions rather than a paraphrase of them.
  const argv = JSON.parse(/\[[\s\S]*\]/.exec(report)[0])
  assert.equal(argv[0], 'C:/fake/ssh', 'the configured client is used')
  assert.equal(argv[1], '-T', 'no pseudo-terminal')
  assert.ok(argv.includes('BatchMode=yes'))
  assert.ok(argv.includes('StrictHostKeyChecking=yes'))
  // One argv element, AND quoted for the remote shell: `ssh` joins everything
  // after the destination with spaces and the server re-parses it, so an
  // unquoted body arrived as `bash -lc echo "a b" | wc -l` and ran a bare `echo`.
  assert.deepEqual(argv.slice(-3), ['bash', '-lc', `'echo "a b" | wc -l'`], 'the command is one quoted element')
  assert.ok(argv.includes('root@10.0.0.1'), 'the registered user and host are used')
})

// ---------- ssh_hosts ----------

await ok('ssh_hosts lists the registry', async () => {
  process.env.FAKE_SCENARIO = 'ok'
  const report = await call('ssh_hosts', {})
  assert.match(report, /good/)
  assert.match(report, /dead/)
  assert.match(report, /10\.0\.0\.1/)
})

await ok('a probe distinguishes reachable from unreachable', async () => {
  process.env.FAKE_SCENARIO = 'ok'
  const report = await call('ssh_hosts', { probe: true })
  assert.match(report, /reachable: yes/)
})

await ok('a probe uses the stored password, so it cannot contradict a real call', async () => {
  // Regression: the probe ran with key-only auth, so a server that works by
  // password was reported unreachable - the diagnostic contradicted the very
  // connection it was meant to verify. Observed live as "reachable: no
  // (AUTH_FAILED)" while ssh_run on the same server succeeded as root.
  await writeFile(secretsPath, JSON.stringify({ version: 1, passwords: { good: 'stored-secret' } }), 'utf-8')
  process.env.FAKE_SCENARIO = 'ok'
  spawnEnvs = []
  const report = await call('ssh_hosts', { probe: true })
  // The report must say the password path was used for the password server.
  assert.match(report, /reachable: yes \(password\)/)
  // A probe runs once per host, so find the ones that carried a password rather
  // than assuming the last spawn is the interesting one.
  const withPassword = spawnEnvs.filter((spawn) => spawn.env?.SSH_ASKPASS !== undefined)
  assert.ok(withPassword.length > 0, 'the probe must deliver a password through askpass')
  for (const spawn of withPassword) {
    assert.equal(spawn.env.SSH_ASKPASS_REQUIRE, 'force')
    // The secret must never be an argument.
    assert.ok(!spawn.argv.some((part) => part.includes('stored-secret')))
    assert.ok(spawn.argv.includes('BatchMode=no'), 'BatchMode must be relaxed for a password')
  }
  await writeFile(secretsPath, JSON.stringify({ version: 1, passwords: {} }), 'utf-8')
})

// ---------- registry changes need confirmation ----------

await ok('adding a server without approval changes nothing', async () => {
  answers = { 'confirm-add': 'Cancel' }
  const before = await readFile(registryPath, 'utf-8')
  const report = await call('ssh_host_add', { name: 'new1', host: '10.0.0.9' })
  assert.match(report, /Cancelled/)
  assert.equal(await readFile(registryPath, 'utf-8'), before, 'the registry must be untouched')
})

await ok('an approved add is stored and confirmed with its details', async () => {
  answers = { 'confirm-add': 'Add server' }
  ctx.asked = undefined
  const report = await call('ssh_host_add', { name: 'new1', host: '10.0.0.9', user: 'deploy', port: 2222 })
  assert.match(report, /Registered "new1"/)
  // The confirmation must show exactly what will be stored.
  const question = ctx.asked[0].question
  assert.match(question, /10\.0\.0\.9/)
  assert.match(question, /deploy/)
  assert.match(question, /2222/)
  const document = JSON.parse(await readFile(registryPath, 'utf-8'))
  const added = document.hosts.find((entry) => entry.name === 'new1')
  assert.equal(added.host, '10.0.0.9')
  assert.equal(added.addedBy, 'agent-confirmed')
  // And it is immediately usable.
  process.env.FAKE_SCENARIO = 'ok'
  assert.match(await call('ssh_run', { host: 'new1', command: 'true' }), /exit=0/)
})

await ok('a duplicate name is refused without touching the file', async () => {
  answers = { 'confirm-add': 'Add server' }
  await assert.rejects(() => call('ssh_host_add', { name: 'good', host: '10.0.0.99' }), /already exists/)
})

await ok('removal needs confirmation too', async () => {
  answers = { 'confirm-remove': 'Cancel' }
  assert.match(await call('ssh_host_remove', { name: 'new1' }), /Cancelled/)
  let document = JSON.parse(await readFile(registryPath, 'utf-8'))
  assert.ok(document.hosts.some((entry) => entry.name === 'new1'), 'a cancelled removal must keep the entry')

  answers = { 'confirm-remove': 'Remove' }
  assert.match(await call('ssh_host_remove', { name: 'new1' }), /Removed/)
  document = JSON.parse(await readFile(registryPath, 'utf-8'))
  assert.ok(!document.hosts.some((entry) => entry.name === 'new1'))
})

await ok('with no answerer a registry change fails closed', async () => {
  questionControl.present = false
  try {
    await assert.rejects(() => call('ssh_host_add', { name: 'nope', host: '10.0.0.8' }), /confirmation/)
  } finally {
    questionControl.present = true
  }
})

await ok('a thrown confirmation rejects instead of silently applying', async () => {
  questionControl.throw = 'user unavailable'
  try {
    await assert.rejects(() => call('ssh_host_add', { name: 'nope2', host: '10.0.0.8' }), /confirmation could not be obtained/)
  } finally {
    questionControl.throw = undefined
  }
  const document = JSON.parse(await readFile(registryPath, 'utf-8'))
  assert.ok(!document.hosts.some((entry) => entry.name === 'nope2'))
})

// ---------- ssh_put / ssh_get ----------

await ok('a copy reports the direction and both paths', async () => {
  process.env.FAKE_SCENARIO = 'ok'
  const put = await call('ssh_put', { host: 'good', localPath: 'package.json', remotePath: '/srv/app/package.json' })
  assert.match(put, /->/)
  assert.match(put, /good:\/srv\/app\/package.json/)
  const get = await call('ssh_get', { host: 'good', remotePath: '/etc/hostname', localPath: 'hostname.txt' })
  assert.match(get, /->/)
})

await ok('a missing required path is refused', async () => {
  await assert.rejects(() => call('ssh_put', { host: 'good', localPath: '  ', remotePath: '/x' }), /non-empty/)
  await assert.rejects(() => call('ssh_get', { host: 'good', remotePath: '/x', localPath: '' }), /non-empty/)
})

await ok('a relative localPath resolves against the session workspace, not process.cwd()', async () => {
  // Regression: `resolvePath(localPath)` alone resolves from the plugin host's
  // own working directory, so a relative put/get pointed at the wrong place and
  // failed with an unexplained scp exit 1. The tool description promises the
  // session workspace, which is what a real call supplies as `localCwd`.
  const workspace = await mkdtemp(join(tmpdir(), 'ssh-remote-ws-'))
  process.env.FAKE_SCENARIO = 'ok'
  await call('ssh_put', { host: 'good', localPath: 'notes/a.txt', remotePath: '/srv/a.txt' }, workspace)
  const putArgv = lastArgv()
  assert.equal(
    putArgv.at(-2).toLowerCase(),
    join(workspace, 'notes', 'a.txt').toLowerCase(),
    'the local side of the copy must be inside the workspace',
  )

  await call('ssh_get', { host: 'good', remotePath: '/etc/hostname', localPath: 'sub/b.txt' }, workspace)
  const getArgv = lastArgv()
  assert.equal(getArgv.at(-1).toLowerCase(), join(workspace, 'sub', 'b.txt').toLowerCase())
})

await ok('an absolute localPath is used unchanged', async () => {
  process.env.FAKE_SCENARIO = 'ok'
  const absolute = join(tmpdir(), 'ssh-remote-absolute.txt')
  await call('ssh_put', { host: 'good', localPath: absolute, remotePath: '/srv/x' }, join(tmpdir(), 'elsewhere'))
  assert.equal(lastArgv().at(-2), absolute)
})

await ok('a failed copy carries the remote stderr, not just an exit code', async () => {
  // Regression: `copyFile` threw `failure.message` alone, and the REMOTE_EXIT
  // message was a bare "exited with code 1" — no path, no command, and no sign of
  // scp's own diagnostic, so the failure could not even be reproduced.
  process.env.FAKE_SCENARIO = 'remote-fail'
  await assert.rejects(
    () => call('ssh_put', { host: 'good', localPath: 'absent.txt', remotePath: '/srv/absent.txt' }),
    (error) => {
      assert.equal(error.code, 'REMOTE_EXIT')
      assert.match(error.message, /command not found/, 'the remote stderr must travel with the error')
      assert.match(error.message, /exit=127/, 'the report must be attached')
      return true
    },
  )
})

await ok('a timed-out copy names the command that hung', async () => {
  process.env.FAKE_SCENARIO = 'hang'
  await assert.rejects(
    () => call('ssh_get', { host: 'good', remotePath: '/srv/big', localPath: 'big.bin', timeoutMs: 300 }),
    (error) => {
      assert.equal(error.code, 'TIMEOUT')
      // Without the command line a hang is indistinguishable from a slow server.
      assert.match(error.message, /fake[\/\\]scp/)
      assert.match(error.message, /:\/srv\/big/, 'the remote path must be visible')
      return true
    },
  )
})

await ok('a timed-out command names the command that hung', async () => {
  process.env.FAKE_SCENARIO = 'hang'
  terminated.length = 0
  await assert.rejects(
    () => call('ssh_run', { host: 'good', command: 'sleep 999', timeoutMs: 300 }),
    (error) => {
      assert.equal(error.code, 'TIMEOUT')
      assert.match(error.message, /Command: sleep 999/)
      return true
    },
  )
})

// ---------- /ssh command ----------

await ok('/ssh with no argument shows the server list', async () => {
  answers = {}
  const result = await command.handler({
    agent: { id: 'session-1' },
    rawInput: '',
    signal: new AbortController().signal,
  })
  assert.equal(result.kind, 'success')
  assert.ok(result.text.length > 0)
})

await ok('/ssh test reports a reachable server in plain language', async () => {
  process.env.FAKE_SCENARIO = 'ok'
  const result = await command.handler({
    agent: { id: 'session-1' },
    rawInput: 'test good',
    signal: new AbortController().signal,
  })
  assert.equal(result.kind, 'success')
  assert.match(result.text, /good/)
})

await ok('/ssh test names the cure in one short line, without raw stderr', async () => {
  process.env.FAKE_SCENARIO = 'nokey'
  const result = await command.handler({
    agent: { id: 'session-1' },
    rawInput: 'test good',
    signal: new AbortController().signal,
  })
  assert.equal(result.kind, 'success')
  // The user must see the state and the exact fix, not OpenSSH's English wall.
  assert.match(result.text, /нужен вход по паролю/)
  assert.match(result.text, /\/ssh pass good <пароль>/, 'the exact command must be ready to copy')
  // Raw stderr must NOT appear in the visible output: it made a routine setup
  // step look like a crash.
  assert.doesNotMatch(result.text, /Permission denied/)
  assert.doesNotMatch(result.text, /Install your public key/)
  // The advice must not be duplicated, which is what the user complained about.
  assert.equal((result.text.match(/\/ssh pass/g) ?? []).length, 1, 'advice must appear exactly once')
})

await ok('a rejected password is reported as a password problem', async () => {
  await writeFile(secretsPath, JSON.stringify({ version: 1, passwords: { good: 'wrong' } }), 'utf-8')
  process.env.FAKE_SCENARIO = 'nokey'
  const result = await command.handler({
    agent: { id: 'session-1' },
    rawInput: 'test good',
    signal: new AbortController().signal,
  })
  assert.equal(result.kind, 'success')
  // With a password already stored, the advice must be about the password, not keys.
  assert.match(result.text, /пароль не принят/)
  assert.doesNotMatch(result.text, /ключ на сервере не установлен/)
  await writeFile(secretsPath, JSON.stringify({ version: 1, passwords: {} }), 'utf-8')
})

await ok('/ssh with an unknown name is an error, not a silent success', async () => {
  const result = await command.handler({
    agent: { id: 'session-1' },
    rawInput: 'nosuchserver',
    signal: new AbortController().signal,
  })
  assert.equal(result.kind, 'error')
})

await ok('/ssh sync imports from a real config file', async () => {
  const configPath = join(home, 'config')
  await writeFile(
    configPath,
    'Host imported\n  HostName 203.0.113.7\n  User root\nHost *\n  ForwardAgent no\n',
    'utf-8',
  )
  // Re-activate with the test config path so the import source is controlled.
  command = undefined
  tools = new Map()
  guards = []
  apply(ctx, {
    ...baseConfig,
    sshConfigPath: configPath,
  })
  const result = await command.handler({
    agent: { id: 'session-1' },
    rawInput: 'sync',
    signal: new AbortController().signal,
  })
  assert.equal(result.kind, 'success')
  assert.match(result.text, /imported/)
  const document = JSON.parse(await readFile(registryPath, 'utf-8'))
  assert.ok(document.hosts.some((entry) => entry.name === 'imported'), 'the config host must be imported')
})

await ok('a corrupt registry stops tools with a clear reason', async () => {
  const brokenPath = join(home, 'broken.json')
  await writeFile(brokenPath, 'not json at all', 'utf-8')
  tools = new Map()
  guards = []
  command = undefined
  apply(ctx, {
    ...baseConfig,
    registryPath: brokenPath,
  })
  await assert.rejects(() => call('ssh_hosts', {}), /not valid JSON/)
})

await ok('subprocess is a DECLARED dependency, not merely fetched', async () => {
  // Regression: `apply` used to read ctx.get('subprocess') without declaring it.
  // At application start the provider was not up yet, so apply threw and the
  // whole plugin failed activation - which also removed /ssh, since the command
  // lives in this same plugin. Live bundle toggling hid the bug, because by then
  // every service was already running.
  const { inject } = await import('./index.js')
  assert.ok(inject.includes('tools'), 'tools must be declared')
  assert.ok(
    inject.includes('subprocess'),
    'subprocess must be declared so Cordis waits for it instead of failing activation',
  )
})

await ok('apply still refuses to run without a subprocess provider', async () => {
  // The declared inject makes this unreachable in the real runtime, but the
  // guard must stay, so a future inject change fails loudly at activation
  // instead of at the first tool call.
  const { apply: freshApply } = await import('./index.js')
  const bare = {
    logger: { info() {}, warn() {}, error() {}, debug() {} },
    get: () => undefined,
    tools: { register() {}, guard() {} },
    inject() {},
    effect: () => () => {},
  }
  assert.throws(() => freshApply(bare, {}), /subprocess service is required/)
})

await ok('/ssh test uses the stored password, exactly like a real call', async () => {
  // Regression: testHost called runProcess without a password, so a server that
  // works by password was always reported unreachable - and the confirmation
  // printed by /ssh pass then contradicted what had just been stored.
  //
  // Re-activate against the REAL registry first: an earlier test deliberately
  // pointed the plugin at a corrupt file, and this test needs the normal one.
  await writeFile(
    registryPath,
    JSON.stringify({ version: 1, hosts: [{ name: 'good', host: '10.0.0.1', user: 'root' }], default: 'good' }),
    'utf-8',
  )
  tools = new Map()
  guards = []
  command = undefined
  apply(ctx, baseConfig)
  await writeFile(secretsPath, JSON.stringify({ version: 1, passwords: { good: 'stored-secret' } }), 'utf-8')
  process.env.FAKE_SCENARIO = 'ok'
  const result = await command.handler({
    agent: { id: 'session-1' },
    rawInput: 'test good',
    signal: new AbortController().signal,
  })
  assert.equal(result.kind, 'success')
  assert.match(result.text, /по паролю/, 'the test must report that it used the password')
  await writeFile(secretsPath, JSON.stringify({ version: 1, passwords: {} }), 'utf-8')
})

await ok('the command declares `input`, without which arguments never arrive', async () => {
  // Regression: the descriptor was omitted, so the Web client ran /ssh detached
  // with no input. `/ssh` alone worked, but every subcommand (/ssh pass, /ssh add)
  // was sent to the model as an ordinary chat message instead of reaching the
  // handler. The client's own rule is: `input` present -> claim the composer and
  // accept arguments; absent -> run detached with no arguments at all.
  assert.ok(command.input, 'the command must declare an input descriptor')
  assert.equal(typeof command.input.hint, 'string', 'the hint is what the menu shows after the name')
  assert.ok(command.input.hint.length > 0, 'an empty hint would be useless to the user')
  // The password path depends on this descriptor existing.
  assert.match(command.input.hint, /pass/, 'the hint must mention the password subcommand')
  // And the input must still be kept out of the session log.
  assert.equal(recordInput, false, 'a password must not be written to the session log')
})

await ok('a denied registry write is reported, never thrown out of the handler', async () => {
  // Regression: a registry write that failed with EPERM threw out of the handler.
  // The Host validates the returned shape, so a throw became a failed command with
  // no explanation - it looked like `/ssh sync` did nothing at all.
  const cases = [
    [{ code: 'EPERM', message: 'operation not permitted' }, /доступ запрещён/],
    [{ code: 'EACCES', message: 'permission denied' }, /доступ запрещён/],
    [{ code: 'EBUSY', message: 'resource busy' }, /занят/],
    [{ code: 'EWHATEVER', message: 'odd failure' }, /odd failure/],
  ]
  for (const [error, pattern] of cases) {
    const text = describeWriteFailure(error)
    assert.match(text, pattern, `should explain ${error.code}`)
  }
})

await ok('every handler branch returns a valid CommandResult', async () => {
  // The Host rejects an invalid result shape; a bare `/ssh`, an unknown verb and
  // an unknown server must all settle as a proper result rather than throwing.
  const validate = (r) => {
    assert.ok(r && typeof r === 'object', 'a result object is required')
    if (r.kind === 'success') return
    assert.equal(r.kind, 'error')
    assert.equal(typeof r.text, 'string')
    assert.ok(r.text.trim().length > 0, 'an error result needs non-empty text')
  }
  for (const raw of ['', ' test nosuchserver', ' nopass nosuchserver', ' bogus']) {
    const result = await command.handler({
      agent: { id: 'session-1' },
      rawInput: raw,
      signal: new AbortController().signal,
    })
    validate(result)
  }
})

// ---------- lock / unlock ----------

await ok('/ssh lock stops operations and /ssh unlock restores them', async () => {
  // The user asked for a real off switch. Locking must stop the operation
  // itself, not merely hide the server from a default-name lookup, or passing an
  // explicit host would walk straight past it.
  await writeFile(
    registryPath,
    JSON.stringify({ version: 1, hosts: [{ name: 'good', host: '10.0.0.1', user: 'root' }], default: 'good' }),
    'utf-8',
  )
  tools = new Map()
  guards = []
  command = undefined
  apply(ctx, baseConfig)
  process.env.FAKE_SCENARIO = 'ok'

  // Works before locking.
  assert.match(await call('ssh_run', { host: 'good', command: 'true' }), /exit=0/)

  const locked = await command.handler({ agent: { id: 's' }, rawInput: 'lock good', signal: new AbortController().signal })
  assert.equal(locked.kind, 'success')
  assert.match(locked.text, /заблокирован/)
  assert.equal(JSON.parse(await readFile(registryPath, 'utf-8')).hosts[0].locked, true, 'the lock must persist')

  // Every operation path must now refuse: the tool, an explicit host, a
  // transfer, and the connection test.
  await assert.rejects(() => call('ssh_run', { host: 'good', command: 'true' }), (error) => {
    assert.equal(error.code, 'HOST_LOCKED')
    return true
  })
  await assert.rejects(() => call('ssh_put', { host: 'good', localPath: 'a', remotePath: '/b' }), /locked/i)
  const tested = await command.handler({ agent: { id: 's' }, rawInput: 'test good', signal: new AbortController().signal })
  assert.match(tested.text, /заблокирован/)

  // The synchronous guard must refuse too, before the call even starts.
  const guard = guards.find((fn) => fn({ name: 'ssh_run', arguments: { host: 'good' } }) !== undefined)
  assert.ok(guard, 'the guard must refuse a locked server')
  assert.match(guard({ name: 'ssh_run', arguments: { host: 'good' } }), /locked/)

  // Unlocking restores use, and must not leave a stray `locked: false`.
  const unlocked = await command.handler({ agent: { id: 's' }, rawInput: 'unlock good', signal: new AbortController().signal })
  assert.equal(unlocked.kind, 'success')
  const stored = JSON.parse(await readFile(registryPath, 'utf-8')).hosts[0]
  assert.equal('locked' in stored, false, 'unlocking removes the flag rather than setting it false')
  assert.match(await call('ssh_run', { host: 'good', command: 'true' }), /exit=0/)
})

await ok('/ssh status reports what the agent may actually use', async () => {
  await writeFile(secretsPath, JSON.stringify({ version: 1, passwords: { good: 'pw' } }), 'utf-8')
  const result = await command.handler({ agent: { id: 's' }, rawInput: 'status', signal: new AbortController().signal })
  assert.equal(result.kind, 'success')
  assert.match(result.text, /разрешён/)
  assert.match(result.text, /пароль/)
  assert.doesNotMatch(result.text, /lXiS|pw\b/, 'status must never print a credential')
  await writeFile(secretsPath, JSON.stringify({ version: 1, passwords: {} }), 'utf-8')
})

await ok('lock and unlock report an unknown server', async () => {
  for (const verb of ['lock', 'unlock']) {
    const result = await command.handler({ agent: { id: 's' }, rawInput: `${verb} nosuch`, signal: new AbortController().signal })
    assert.equal(result.kind, 'error')
  }
})

// ---------- default server ----------

await ok('/ssh default sets and clears the default explicitly', async () => {
  await writeFile(
    registryPath,
    JSON.stringify({ version: 1, hosts: [{ name: 'one', host: '10.0.0.1' }, { name: 'two', host: '10.0.0.2' }] }),
    'utf-8',
  )
  tools = new Map()
  guards = []
  command = undefined
  apply(ctx, baseConfig)
  process.env.FAKE_SCENARIO = 'ok'

  const set = await command.handler({ agent: { id: 's' }, rawInput: 'default one', signal: new AbortController().signal })
  assert.equal(set.kind, 'success')
  assert.match(set.text, /по умолчанию/)
  assert.equal(JSON.parse(await readFile(registryPath, 'utf-8')).default, 'one')

  // A tool with no `host` must now use it.
  const viaDefault = await call('ssh_run', { command: 'true' })
  assert.match(viaDefault, /exit=0/)

  // Clearing removes the key rather than storing an empty string.
  const cleared = await command.handler({ agent: { id: 's' }, rawInput: 'default', signal: new AbortController().signal })
  assert.equal(cleared.kind, 'success')
  assert.equal('default' in JSON.parse(await readFile(registryPath, 'utf-8')), false)

  // And with no default, a host-less call must explain itself instead of guessing.
  await assert.rejects(() => call('ssh_run', { command: 'true' }), /no default is set/i)
})

await ok('a bare /ssh <name> checks without silently changing the default', async () => {
  // Selection and "make default" used to be one implicit step, so merely testing
  // a server redirected every later host-less tool call. They are now separate.
  await command.handler({ agent: { id: 's' }, rawInput: 'default one', signal: new AbortController().signal })
  const checked = await command.handler({ agent: { id: 's' }, rawInput: 'two', signal: new AbortController().signal })
  assert.equal(checked.kind, 'success')
  // The default must be untouched, and the reply must offer the explicit command.
  assert.equal(JSON.parse(await readFile(registryPath, 'utf-8')).default, 'one', 'checking must not change the default')
  assert.match(checked.text, /\/ssh default two/)
})

await ok('removing the default server clears the stale default', async () => {
  // Leaving it behind made the plugin claim "no default is set" while a dead name
  // sat in the file - a misleading message the user actually hit.
  await command.handler({ agent: { id: 's' }, rawInput: 'default one', signal: new AbortController().signal })
  const removed = await command.handler({ agent: { id: 's' }, rawInput: 'remove one', signal: new AbortController().signal })
  assert.equal(removed.kind, 'success')
  assert.match(removed.text, /умолчание сброшено/)
  const document = JSON.parse(await readFile(registryPath, 'utf-8'))
  assert.equal('default' in document, false, 'the stale default must not survive the removal')
})

await ok('a stale default is described truthfully, not as a missing one', async () => {
  // Force the stale state directly, so the message is what is under test.
  await writeFile(
    registryPath,
    JSON.stringify({ version: 1, hosts: [{ name: 'two', host: '10.0.0.2' }], default: 'ghost' }),
    'utf-8',
  )
  tools = new Map()
  guards = []
  command = undefined
  apply(ctx, baseConfig)
  await assert.rejects(
    () => call('ssh_run', { command: 'true' }),
    (error) => {
      // It must name the stale default and the real fix.
      assert.match(error.message, /"ghost" is no longer registered/)
      assert.match(error.message, /\/ssh default/)
      return true
    },
  )
})

await ok('/ssh status shows which server is the default', async () => {
  await writeFile(
    registryPath,
    JSON.stringify({ version: 1, hosts: [{ name: 'one', host: '10.0.0.1' }, { name: 'two', host: '10.0.0.2' }], default: 'two' }),
    'utf-8',
  )
  tools = new Map()
  guards = []
  command = undefined
  apply(ctx, baseConfig)
  const result = await command.handler({ agent: { id: 's' }, rawInput: 'status', signal: new AbortController().signal })
  assert.equal(result.kind, 'success')
  assert.match(result.text, /two.*по умолчанию|по умолчанию.*two/s)
})

// ---------- command policy --------------------------------------------------

await ok('the guard refuses a catastrophic command before any process starts', async () => {
  // Earlier tests deliberately pointed the plugin at a corrupt registry, so the
  // normal one is restored before this section.
  await writeFile(
    registryPath,
    JSON.stringify({ version: 1, hosts: [{ name: 'good', host: '10.0.0.1', user: 'root' }], default: 'good' }),
    'utf-8',
  )
  tools = new Map()
  guards = []
  command = undefined
  apply(ctx, baseConfig)
  const guard = guards[0]
  const before = spawnEnvs.length
  const refused = guard({ name: 'ssh_run', arguments: { host: 'good', command: 'rm -rf /' } })
  assert.match(refused, /Refused by the SSH command guard/)
  assert.match(refused, /rm -rf \//, 'the refusal names the command')
  assert.match(refused, /whole filesystem tree/, 'the refusal names the reason')
  // Routine work is not slowed down: the guard lets it through unchanged.
  assert.equal(guard({ name: 'ssh_run', arguments: { host: 'good', command: 'uname -a' } }), undefined)
  assert.equal(spawnEnvs.length, before, 'a guard is synchronous and spawns nothing')
})

await ok('execution blocks independently of the guard', async () => {
  // A guard is a fast refusal over a snapshot; execution must still be safe if a
  // future call path skips it.
  process.env.FAKE_SCENARIO = 'ok'
  const before = spawnEnvs.length
  await assert.rejects(
    () => call('ssh_run', { host: 'good', command: 'mkfs.ext4 /dev/sda1' }),
    (error) => {
      assert.equal(error.code, 'COMMAND_BLOCKED')
      assert.match(error.message, /mkfs\.ext4/)
      return true
    },
  )
  assert.equal(spawnEnvs.length, before, 'a blocked command must never spawn ssh')
})

await ok('a risky command without an answerer is refused, not run', async () => {
  questionControl.present = false
  process.env.FAKE_SCENARIO = 'ok'
  const before = spawnEnvs.length
  try {
    await assert.rejects(
      () => call('ssh_run', { host: 'good', command: 'rm -rf /var/www/app' }),
      (error) => {
        // Fail-closed: no question service means no irreversible command.
        assert.equal(error.code, 'NO_ANSWERER')
        return true
      },
    )
  } finally {
    questionControl.present = true
  }
  assert.equal(spawnEnvs.length, before)
})

await ok('a risky command asks with the command, server and working directory', async () => {
  process.env.FAKE_SCENARIO = 'ok'
  ctx.asked = undefined
  answers = { 'confirm-command': 'Cancel' }
  const before = spawnEnvs.length
  const result = await call('ssh_run', { host: 'good', command: 'rm -rf /var/www/app', cwd: '/srv/app' })
  assert.match(result, /Cancelled/)
  assert.equal(spawnEnvs.length, before, 'Cancel must run nothing')
  const question = ctx.asked[0]
  assert.equal(question.id, 'confirm-command')
  assert.match(question.question, /rm -rf \/var\/www\/app/)
  assert.match(question.question, /"good"/)
  assert.match(question.question, /\/srv\/app/)
  assert.match(question.question, /recursive delete/, 'the question says why it asks')
  assert.deepEqual(question.options.map((option) => option.label), ['Run it', 'Cancel'])
})

await ok('answering Run it executes exactly once', async () => {
  process.env.FAKE_SCENARIO = 'ok'
  answers = { 'confirm-command': 'Run it' }
  const before = spawnEnvs.length
  const report = await call('ssh_run', { host: 'good', command: 'rm -rf /var/www/app' })
  assert.match(report, /exit=0/)
  assert.equal(spawnEnvs.length, before + 1)
})

await ok('commandPolicy off skips the question but never the block', async () => {
  tools = new Map()
  guards = []
  command = undefined
  logs.length = 0
  apply(ctx, { ...baseConfig, commandPolicy: 'off' })
  assert.ok(
    logs.some(([level, message]) => level === 'warn' && /commandPolicy=off/.test(message)),
    'a downgraded policy must be visible in the log',
  )
  process.env.FAKE_SCENARIO = 'ok'
  ctx.asked = undefined
  const before = spawnEnvs.length
  const report = await call('ssh_run', { host: 'good', command: 'rm -rf /var/www/app' })
  assert.match(report, /exit=0/)
  assert.equal(ctx.asked, undefined, 'off means no confirmation')
  assert.equal(spawnEnvs.length, before + 1)
  await assert.rejects(() => call('ssh_run', { host: 'good', command: 'rm -rf /' }), /whole filesystem tree/)
  // Restore the standard policy for the remaining tests.
  tools = new Map()
  guards = []
  command = undefined
  apply(ctx, baseConfig)
})

// ---------- redaction and truncation through a real call --------------------

await ok('secrets are cut from a run report before the model sees them', async () => {
  process.env.FAKE_SCENARIO = 'redact'
  const report = await call('ssh_run', { host: 'good', command: 'cat ~/.ssh/id_rsa; env' })
  assert.doesNotMatch(report, /AAAAB3NzaC1yc2E/, 'the key body must not travel')
  assert.doesNotMatch(report, /hunter2/, 'the password must not travel')
  assert.match(report, /«redacted:private-key»/)
  assert.match(report, /вырезано 2 секрета/)
})

await ok('a long report keeps the tail, where the failure actually is', async () => {
  process.env.FAKE_SCENARIO = 'long-output'
  const report = await call('ssh_run', { host: 'good', command: 'make' })
  assert.ok(report.includes('H'.repeat(100)), 'the head must be visible')
  assert.ok(report.includes('T'.repeat(100)), 'the tail must be visible too')
  assert.match(report, /пропущено 5000 символов/)
})

// ---------- audit log -------------------------------------------------------

await ok('each invocation leaves one audit line, success or failure alike', async () => {
  await writeFile(auditPath, '', 'utf-8')
  process.env.FAKE_SCENARIO = 'ok'
  await call('ssh_run', { host: 'good', command: 'id' })
  process.env.FAKE_SCENARIO = 'remote-fail'
  await call('ssh_run', { host: 'good', command: 'nope' }).catch(() => {})
  const lines = (await readFile(auditPath, 'utf-8')).trim().split('\n').filter(Boolean)
  assert.equal(lines.length, 2, 'one call, one record')
  const [success, failed] = lines.map((line) => JSON.parse(line))
  assert.equal(success.tool, 'ssh_run')
  assert.equal(success.server, 'good')
  assert.equal(success.host, '10.0.0.1')
  assert.equal(success.command, 'id')
  assert.equal(success.exitCode, 0)
  assert.ok(success.durationMs >= 0)
  // A failing command is recorded with its exit code, not dropped.
  assert.equal(failed.exitCode, 127)
  assert.equal(failed.timedOut, false)
})

await ok('the audit log never holds a secret, and an unwritable log is not fatal', async () => {
  await writeFile(auditPath, '', 'utf-8')
  process.env.FAKE_SCENARIO = 'ok'
  await call('ssh_run', { host: 'good', command: 'curl -H "Authorization: Bearer abc.def"' })
  const record = JSON.parse((await readFile(auditPath, 'utf-8')).trim())
  assert.match(record.command, /«redacted:bearer»/)
  assert.doesNotMatch(record.command, /abc\.def/)
  // A directory that cannot be created must not turn a working command into an
  // error: the log is an audit aid, not a gate.
  const blocker = join(home, 'not-a-directory')
  await writeFile(blocker, 'plain file', 'utf-8')
  tools = new Map()
  guards = []
  command = undefined
  logs.length = 0
  apply(ctx, { ...baseConfig, auditLogPath: join(blocker, 'audit.jsonl') })
  const report = await call('ssh_run', { host: 'good', command: 'id' })
  assert.match(report, /exit=0/)
  assert.ok(logs.some(([level, message]) => level === 'warn' && /audit log/.test(message)))
  tools = new Map()
  guards = []
  command = undefined
  apply(ctx, baseConfig)
})

// ---------- read-only tools -------------------------------------------------

await ok('ssh_read quotes the path and reports the window honestly', async () => {
  const path = "/srv/it's $(rm -rf /).log"
  process.env.FAKE_SCENARIO = 'read-window'
  const report = await call('ssh_read', { host: 'good', path, offset: 101, limit: 200 })
  // The command body is one quoted argument whose sed script and path are quoted
  // for the remote shell, so a path with quotes or $( ) cannot break out.
  assert.equal(lastArgv().at(-1), shellQuote(`sed -n '101,301p' -- ${shellQuote(path)}`))
  assert.match(report, /lines 101-300/)
  assert.match(report, /more lines follow/)
  assert.match(report, /offset=301/)
  // A short file carries no "more lines" claim.
  process.env.FAKE_SCENARIO = 'ok'
  const whole = await call('ssh_read', { host: 'good', path: '/etc/hostname' })
  assert.doesNotMatch(whole, /more lines follow/)
  await assert.rejects(() => call('ssh_read', { host: 'good', path: '   ' }), /path must be a non-empty string/)
  await assert.rejects(() => call('ssh_read', { host: 'good', path: '/x', limit: 0 }), /positive integer/)
})

await ok('ssh_ls caps the listing and marks it truncated', async () => {
  process.env.FAKE_SCENARIO = 'many-lines'
  const report = await call('ssh_ls', { host: 'good', path: '/var/www' })
  assert.equal(
    lastArgv().at(-1),
    shellQuote(`set -o pipefail; ls -la -- ${shellQuote('/var/www')} | head -n 201; ${PIPE_STATUS}`),
  )
  assert.match(report, /entry-200/)
  assert.doesNotMatch(report, /entry-201/)
  assert.match(report, /truncated: showing the first 200 entries/)
  process.env.FAKE_SCENARIO = 'ok'
  const short = await call('ssh_ls', { host: 'good', path: '/var/www', long: false })
  assert.equal(
    lastArgv().at(-1),
    shellQuote(`set -o pipefail; ls -a -- ${shellQuote('/var/www')} | head -n 201; ${PIPE_STATUS}`),
  )
  assert.doesNotMatch(short, /truncated/)
})

await ok('ssh_grep quotes the pattern, honours the glob and caps matches', async () => {
  process.env.FAKE_SCENARIO = 'many-matches'
  const report = await call('ssh_grep', {
    host: 'good',
    pattern: 'ERROR "x"',
    path: '/var/log',
    glob: '*.js',
    maxMatches: 100,
  })
  assert.equal(
    lastArgv().at(-1),
    shellQuote(
      `set -o pipefail; grep -rnH --binary-files=without-match --include=${shellQuote('*.js')} ` +
        `-- ${shellQuote('ERROR "x"')} ${shellQuote('/var/log')} | head -n 101; ${GREP_STATUS}`,
    ),
  )
  assert.match(report, /app\.js:1:ERROR/)
  assert.doesNotMatch(report, /app\.js:101:/)
  assert.match(report, /truncated: showing the first 100 matching lines/)
  // "No matches" is a normal answer, not a failed command.
  process.env.FAKE_SCENARIO = 'no-matches'
  const none = await call('ssh_grep', { host: 'good', pattern: 'nothing', path: '/var/log' })
  assert.match(none, /no matches/)
})

await ok('ssh_glob uses find -name and caps the paths', async () => {
  process.env.FAKE_SCENARIO = 'many-lines'
  const report = await call('ssh_glob', { host: 'good', pattern: '*.log', path: '/var/log' })
  assert.equal(
    lastArgv().at(-1),
    shellQuote(`set -o pipefail; find ${shellQuote('/var/log')} -name ${shellQuote('*.log')} -print | head -n 201; ${PIPE_STATUS}`),
  )
  assert.match(report, /truncated: showing the first 200 paths/)
})

// ---------- tty and detached ------------------------------------------------

await ok('tty and detached reach the client, and a detached start reports the pid', async () => {
  process.env.FAKE_SCENARIO = 'echo-argv'
  await call('ssh_run', { host: 'good', command: 'top -b -n1', tty: true })
  assert.equal(lastArgv()[1], '-tt')
  assert.ok(!lastArgv().includes('-T'), 'a duplicate -T would cancel the request')

  process.env.FAKE_SCENARIO = 'detached'
  const report = await call('ssh_run', { host: 'good', command: 'apt upgrade -y', detached: true, logPath: '/tmp/upgrade.log' })
  assert.match(report, /pid 4242/)
  assert.match(report, /Log: \/tmp\/upgrade\.log/)
  assert.match(report, /tail -n 50 '\/tmp\/upgrade\.log'/)
  // The command is wrapped, not concatenated: the wrapper must not be fooled by
  // the command's own quotes.
  assert.equal(lastArgv().at(-1), shellQuote(detachedBody('apt upgrade -y', '/tmp/upgrade.log', undefined)))
  await assert.rejects(
    () => call('ssh_run', { host: 'good', command: 'true', tty: true, detached: true }),
    /cannot be combined/,
  )
})

console.log(`\n${checks} checks passed.`)
