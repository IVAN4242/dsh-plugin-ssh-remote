/**
 * The report's post-fix checklist, run against a real SSH server.
 *
 * This is the companion of `e2e-live.mjs`: that one proves the password helper is
 * consumed by the real `ssh.exe`, this one proves the COMMAND CONTRACT — that a
 * command with flags, `&&`, `;`, pipes, loops, quotes, non-ASCII text and a `cwd`
 * actually arrives intact, and that relative local paths in put/get resolve
 * against the session workspace.
 *
 * Usage:
 *   node test-live.mjs [host] [user]
 *
 * The host defaults to the registry's default server and the password to the one
 * stored for it; the secret is only ever moved through files, never printed.
 *
 * The child's streams go to FILES rather than pipes: the DSH sandbox denies
 * piped stdio for spawned processes, and an inherited pipe would deadlock here.
 */
import { spawn } from 'node:child_process'
import { closeSync, openSync, readFileSync, writeFileSync } from 'node:fs'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir, homedir } from 'node:os'
import { join, dirname } from 'node:path'

const dshHome = process.env.DSH_HOME ?? join(homedir(), '.dsh')
const hostArg = process.argv[2]
const userArg = process.argv[3]

/** Read the real registry, so the test talks to the server the plugin knows. */
const registry = JSON.parse(readFileSync(join(dshHome, 'ssh-remote-hosts.json'), 'utf-8'))
const entry = hostArg === undefined ? registry.hosts.find((item) => item.name === registry.default) ?? registry.hosts[0] : registry.hosts.find((item) => item.host === hostArg || item.name === hostArg) ?? { name: hostArg, host: hostArg, user: userArg }
if (entry === undefined) {
  console.error('no server: pass a host name as the first argument')
  process.exit(2)
}

/** The stored password, when the entry has one. Read, never echoed. */
let password
try {
  const secrets = JSON.parse(readFileSync(join(dshHome, 'ssh-remote-secrets.json'), 'utf-8'))
  password = secrets.passwords?.[entry.name]
} catch {
  password = undefined
}

const home = await mkdtemp(join(tmpdir(), 'ssh-live-'))
const registryPath = join(home, 'hosts.json')
const secretsPath = join(home, 'secrets.json')
const askpassDir = join(home, 'askpass')
await writeFile(registryPath, JSON.stringify({ version: 1, hosts: [entry], default: entry.name }), 'utf-8')
await writeFile(
  secretsPath,
  JSON.stringify({ version: 1, passwords: password === undefined ? {} : { [entry.name]: password } }),
  'utf-8',
)

// The session workspace, exactly what a real `ssh_put` call resolves against.
const workspace = join(home, 'workspace')
await mkdir(join(workspace, 'sub'), { recursive: true })

/** A subprocess provider whose children write to files instead of pipes. */
const subprocess = {
  spawn(spec) {
    const [program, ...rest] = spec.argv
    const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    const outPath = join(home, `out-${stamp}.txt`)
    const errPath = join(home, `err-${stamp}.txt`)
    const inPath = join(home, `in-${stamp}.txt`)
    const outFd = openSync(outPath, 'w')
    const errFd = openSync(errPath, 'w')
    const stdio = ['ignore', outFd, errFd]
    // A real stdin file, so `cat` receives exactly the bytes the tool was given.
    if (typeof spec.stdio?.stdin === 'object' && spec.stdio.stdin?.data !== undefined) {
      writeFileSync(inPath, spec.stdio.stdin.data)
      stdio[0] = openSync(inPath, 'r')
    }
    const child = spawn(program, rest, { cwd: spec.cwd, env: spec.env ?? process.env, stdio })
    closeSync(outFd)
    closeSync(errFd)
    if (stdio[0] !== 'ignore') closeSync(stdio[0])
    const done = new Promise((resolve) => {
      child.on('error', (error) => resolve({ exitCode: null, signal: null, error }))
      child.on('close', (code, signal) => resolve({ exitCode: code, signal: signal ?? null }))
    })
    return {
      collected: {
        // The plugin reads collected output after `done` resolves, by which time
        // the child's files are complete.
        stdout: { readFrom: () => ({ text: readFileSync(outPath, 'utf-8') }) },
        stderr: { readFrom: () => ({ text: readFileSync(errPath, 'utf-8') }) },
      },
      done,
      terminate: () => child.kill(),
      waitForExit: () => done.then(() => true),
    }
  },
}

const tools = new Map()
const ctx = {
  logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
  get: (name) => (name === 'subprocess' ? subprocess : undefined),
  tools: { register: (definition) => tools.set(definition.name, definition), guard: () => {} },
  inject: () => {},
  effect: () => () => {},
}

const { apply } = await import('./index.js')
apply(ctx, {
  registryPath,
  secretsPath,
  askpassDir,
  // Keep the live run out of the real action log: the plugin would otherwise
  // append to $DSH_HOME/ssh-remote-audit.jsonl from a throwaway registry.
  auditLogPath: join(home, 'audit.jsonl'),
  sshPath: 'C:/Windows/System32/OpenSSH/ssh.exe',
  scpPath: 'C:/Windows/System32/OpenSSH/scp.exe',
  connectTimeoutMs: 15_000,
  defaultTimeoutMs: 60_000,
  maxOutputChars: 8_000,
})

const exec = { agent: { id: 'live', session: { header: { cwd: workspace } } }, signal: new AbortController().signal }
const call = (name, args) => {
  const tool = tools.get(name)
  if (tool === undefined) throw new Error(`tool ${name} is not registered`)
  return tool.execute(args, exec)
}

let checks = 0
let failed = 0
/** Run one case; print PASS/FAIL and keep going so one failure shows the rest. */
const check = async (label, fn) => {
  try {
    await fn()
    checks += 1
    console.log(`  ok   ${label}`)
  } catch (error) {
    checks += 1
    failed += 1
    console.log(`  FAIL ${label}`)
    for (const line of String(error?.message ?? error).split('\n').slice(0, 12)) console.log(`       ${line}`)
  }
}

/** The stdout body of a successful run report. */
const stdoutOf = (report) => {
  const match = /--- stdout ---\n([\s\S]*?)\n--- stderr ---/.exec(report)
  if (match === null) throw new Error(`no stdout section in report:\n${report}`)
  return match[1]
}

const server = `${entry.name} (${entry.user === undefined ? '' : `${entry.user}@`}${entry.host})`
console.log(`\nLive checklist against ${server}${password === undefined ? ', key auth' : ', password auth'}\n`)

// ---------- the command must arrive intact ----------

await check('uname -m keeps its argument', async () => {
  const out = stdoutOf(await call('ssh_run', { command: 'uname -m' }))
  if (out.trim() !== 'x86_64') throw new Error(`expected x86_64, got ${JSON.stringify(out)}`)
})

await check('echo AAA prints AAA', async () => {
  const out = stdoutOf(await call('ssh_run', { command: 'echo AAA' }))
  if (out !== 'AAA\n') throw new Error(`expected "AAA\\n", got ${JSON.stringify(out)}`)
})

await check('a second command after ";" is not swallowed', async () => {
  const out = stdoutOf(await call('ssh_run', { command: 'echo FIRST; echo SECOND' }))
  if (out !== 'FIRST\nSECOND\n') throw new Error(`got ${JSON.stringify(out)}`)
})

await check('ls -la /etc/hostname lists the file, not a random directory', async () => {
  const out = stdoutOf(await call('ssh_run', { command: 'ls -la /etc/hostname' }))
  if (!/hostname/.test(out) || !/^-/.test(out)) throw new Error(`got ${JSON.stringify(out)}`)
})

await check('cwd really changes the working directory', async () => {
  const out = stdoutOf(await call('ssh_run', { command: 'pwd', cwd: '/etc/nginx' }))
  if (out.trim() !== '/etc/nginx') throw new Error(`expected /etc/nginx, got ${JSON.stringify(out)}`)
})

await check('a cwd containing a single quote survives quoting', async () => {
  // A real directory whose name contains a quote: if the quoting leaked, the
  // remote shell would see `cd '/tmp/it'` + a stray `s here` and fail.
  const tricky = `/tmp/it's here`
  await call('ssh_run', { command: `mkdir -p "${tricky}"` })
  try {
    const out = stdoutOf(await call('ssh_run', { command: 'pwd', cwd: tricky }))
    if (out.trim() !== tricky) throw new Error(`expected ${tricky}, got ${JSON.stringify(out)}`)
  } finally {
    await call('ssh_run', { command: `rmdir "${tricky}"` }).catch(() => {})
  }
})

await check('set -e is silent and exits 0', async () => {
  const report = await call('ssh_run', { command: 'set -e' })
  // The formatter renders an empty stream as "(empty)"; what matters is that no
  // environment dump came back (`set` with no arguments printed every variable).
  const out = stdoutOf(report)
  if (out.trim() !== '(empty)') throw new Error(`expected empty stdout, got ${JSON.stringify(out).slice(0, 120)}`)
  if (!/exit=0/.test(report)) throw new Error(`expected exit=0, got ${report.split('\n')[0]}`)
})

await check('test -d && echo runs the second half', async () => {
  const out = stdoutOf(await call('ssh_run', { command: 'test -d /var/www && echo yes-dir' }))
  if (out.trim() !== 'yes-dir') throw new Error(`got ${JSON.stringify(out)}`)
})

await check('a pipeline works', async () => {
  const out = stdoutOf(await call('ssh_run', { command: 'printf "b\\na\\n" | sort | tr "\\n" " "' }))
  if (out.trim() !== 'a b') throw new Error(`got ${JSON.stringify(out)}`)
})

await check('a for loop is not a syntax error', async () => {
  const out = stdoutOf(await call('ssh_run', { command: 'for i in 1 2 3; do echo "iter$i"; done' }))
  if (out !== 'iter1\niter2\niter3\n') throw new Error(`got ${JSON.stringify(out)}`)
})

await check('an if block is not a syntax error', async () => {
  const out = stdoutOf(await call('ssh_run', { command: 'if [ -d /var/www ]; then echo httpd-ok; fi' }))
  if (out.trim() !== 'httpd-ok') throw new Error(`got ${JSON.stringify(out)}`)
})

await check('sh -c with a quoted payload returns at once', async () => {
  const out = stdoutOf(await call('ssh_run', { command: "sh -c 'echo quoted-ok'" }))
  if (out.trim() !== 'quoted-ok') throw new Error(`got ${JSON.stringify(out)}`)
})

await check('bash -lc with a quoted payload returns at once', async () => {
  const out = stdoutOf(await call('ssh_run', { command: "bash -lc 'uname -m'" }))
  if (out.trim() !== 'x86_64') throw new Error(`got ${JSON.stringify(out)}`)
})

await check('node -v returns a version instead of hanging in a REPL', async () => {
  const out = stdoutOf(await call('ssh_run', { command: 'node -v', timeoutMs: 20_000 }))
  if (!/^v\d+\./.test(out.trim())) throw new Error(`got ${JSON.stringify(out)}`)
})

await check('a login shell still provides the distro PATH', async () => {
  const out = stdoutOf(await call('ssh_run', { command: 'command -v node' }))
  if (out.trim().length === 0) throw new Error('node is not on PATH in the login shell')
})

await check('curl keeps all of its flags', async () => {
  const out = stdoutOf(await call('ssh_run', { command: "curl -s -m 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/api/health" }))
  if (out.trim() !== '200') throw new Error(`got ${JSON.stringify(out)}`)
})

await check('systemctl cat prints the unit, not the unit list', async () => {
  const out = stdoutOf(await call('ssh_run', { command: 'systemctl cat gaymers-server.service' }))
  if (!/ExecStart/.test(out)) throw new Error(`got ${JSON.stringify(out).slice(0, 200)}`)
})

await check('single quotes in the command are passed literally', async () => {
  const out = stdoutOf(await call('ssh_run', { command: "printf '%s' 'одинарные кавычки'" }))
  if (out !== 'одинарные кавычки') throw new Error(`got ${JSON.stringify(out)}`)
})

await check('a double-quoted single quote survives', async () => {
  const out = stdoutOf(await call('ssh_run', { command: 'echo "кавычки \'внутри\'"' }))
  if (out !== "кавычки 'внутри'\n") throw new Error(`got ${JSON.stringify(out)}`)
})

await check('$VAR is expanded remotely, not locally', async () => {
  const out = stdoutOf(await call('ssh_run', { command: 'X=remote-value; echo "$X"' }))
  if (out.trim() !== 'remote-value') throw new Error(`got ${JSON.stringify(out)}`)
})

await check('stdin still reaches the remote command', async () => {
  const out = stdoutOf(await call('ssh_run', { command: 'cat', stdin: 'hello-stdin' }))
  if (out !== 'hello-stdin') throw new Error(`got ${JSON.stringify(out)}`)
})

await check('a long argument list survives the Windows argv limit', async () => {
  // ~8 KB of arguments, well under the 32 KB Windows limit but far beyond a
  // single short word, so a re-split would be visible.
  const words = Array.from({ length: 400 }, (_, index) => `w${index}`).join(' ')
  const out = stdoutOf(await call('ssh_run', { command: `printf '%s' "${words}" | wc -w` }))
  if (out.trim() !== '400') throw new Error(`got ${JSON.stringify(out)}`)
})

// ---------- exit codes and diagnostics ----------

await check('the remote exit code is preserved', async () => {
  try {
    await call('ssh_run', { command: 'exit 42' })
    throw new Error('the call should have rejected')
  } catch (error) {
    if (!/exit=42/.test(error.message)) throw new Error(`got ${error.message}`)
    if (error.code !== 'REMOTE_EXIT') throw new Error(`code was ${error.code}`)
  }
})

await check('a failing command reports its stderr', async () => {
  try {
    await call('ssh_run', { command: 'ls /definitely/not/here' })
    throw new Error('the call should have rejected')
  } catch (error) {
    if (!/No such file or directory/.test(error.message)) throw new Error(`stderr was lost: ${error.message}`)
  }
})

await check('an over-deadline command times out and names the command', async () => {
  try {
    await call('ssh_run', { command: 'sleep 30', timeoutMs: 1_500 })
    throw new Error('the call should have rejected')
  } catch (error) {
    if (error.code !== 'TIMEOUT') throw new Error(`code was ${error.code}`)
    if (!/sleep 30/.test(error.message)) throw new Error(`the command is missing from the message: ${error.message}`)
  }
})

// ---------- put / get with relative local paths ----------

const marker = `dsh-live-${process.pid}`
const remotePath = `/tmp/${marker}.txt`
const localRelative = `sub/${marker}.txt`

await check('ssh_put accepts a relative localPath (resolved from the workspace)', async () => {
  await writeFile(join(workspace, localRelative), `uploaded ${marker}\n`, 'utf-8')
  // The copy is issued from the workspace with a relative path, exactly as the
  // tool documents. A resolve from process.cwd() would look in the wrong place.
  const report = await call('ssh_put', { localPath: localRelative, remotePath })
  if (!/->/.test(report)) throw new Error(`unexpected report: ${report}`)
  const content = stdoutOf(await call('ssh_run', { command: `cat ${remotePath}` }))
  if (content.trim() !== `uploaded ${marker}`) throw new Error(`remote content was ${JSON.stringify(content)}`)
})

await check('ssh_get accepts a relative localPath and writes the file', async () => {
  const destination = `sub/downloaded-${marker}.txt`
  const report = await call('ssh_get', { remotePath, localPath: destination })
  if (!/->/.test(report)) throw new Error(`unexpected report: ${report}`)
  const content = await readFile(join(workspace, destination), 'utf-8')
  if (content.trim() !== `uploaded ${marker}`) throw new Error(`local content was ${JSON.stringify(content)}`)
  await rm(join(workspace, destination), { force: true })
})

await check('a failed copy reports the command line and stderr', async () => {
  try {
    await call('ssh_get', { remotePath: '/tmp/does-not-exist-anywhere', localPath: `sub/missing-${marker}.txt` })
    throw new Error('the call should have rejected')
  } catch (error) {
    // Silence here was the P2 defect: a bare "exited with code 1" is unactionable.
    if (!/scp|No such file|not found|lost connection/i.test(error.message)) {
      throw new Error(`the failure carries no diagnostic: ${error.message}`)
    }
  }
})

// ---------- command policy, redaction, truncation ----------

await check('a catastrophic command is refused before ssh is started', async () => {
  try {
    await call('ssh_run', { command: 'rm -rf /' })
    throw new Error('the call should have rejected')
  } catch (error) {
    if (error.code !== 'COMMAND_BLOCKED') throw new Error(`code was ${error.code}`)
    if (!/rm -rf \//.test(error.message)) throw new Error(`the command is missing: ${error.message}`)
    if (!/whole filesystem tree/.test(error.message)) throw new Error(`the reason is missing: ${error.message}`)
  }
})

await check('a risky command without an answerer is refused, not run', async () => {
  try {
    await call('ssh_run', { command: `rm -rf /tmp/${marker}-should-not-exist` })
    throw new Error('the call should have rejected')
  } catch (error) {
    // Fail closed: this harness has no question service, and the tool must prefer
    // a refusal over an irreversible delete.
    if (error.code !== 'NO_ANSWERER') throw new Error(`code was ${error.code}`)
  }
})

await check('secrets are removed from a live report', async () => {
  const report = await call('ssh_run', {
    command: "printf 'password=live-secret-1234\\ntoken: sk-abcdefghijklmnopqrstuvwx\\n'",
  })
  if (report.includes('live-secret-1234')) throw new Error('the password reached the report')
  if (/sk-abcdefghijklmnopqrstuvwx/.test(report)) throw new Error('the token reached the report')
  if (!/«redacted:credential»/.test(report)) throw new Error(`no redaction marker:\n${report}`)
  if (!/вырезано 2 секрета/.test(report)) throw new Error(`unexpected counter line:\n${report}`)
})

await check('a long report keeps its tail', async () => {
  // `seq 1 3000` is ~14 KB, well over the 8 KB ceiling set above: the failing end
  // of a build log is what a head-only cut used to hide.
  const report = await call('ssh_run', { command: 'seq 1 3000' })
  const body = stdoutOf(report)
  const lines = body.split('\n')
  if (lines[0] !== '1') throw new Error('the head was lost')
  if (!lines.includes('3000')) throw new Error('the tail was lost')
  if (!/… пропущено \d+ символов \(из \d+\) …/.test(body)) throw new Error('no truncation marker')
})

// ---------- read-only tools ----------

await check('ssh_read returns a quoted window and names the next offset', async () => {
  const window = await call('ssh_read', { path: '/etc/passwd', offset: 2, limit: 3 })
  if (!/\/etc\/passwd: lines 2-4/.test(window)) throw new Error(window)
  if (!/offset=5/.test(window)) throw new Error(`the next offset is not offered:\n${window}`)
  const missing = await call('ssh_read', { path: '/etc/definitely-not-here-live' }).catch((error) => error)
  if (!/No such file/.test(String(missing.message ?? missing))) {
    throw new Error(`a missing file must be reported:\n${String(missing.message ?? missing)}`)
  }
})

await check('ssh_ls lists a directory', async () => {
  const listing = await call('ssh_ls', { path: '/etc/ssh', long: false })
  if (!/sshd_config/.test(listing)) throw new Error(listing)
})

await check('ssh_grep keeps the path:line:text shape', async () => {
  const found = await call('ssh_grep', { pattern: '^root:', path: '/etc/passwd' })
  if (!/\/etc\/passwd:1:root:/.test(found)) throw new Error(found)
})

await check('ssh_grep reports "no matches" as a normal answer', async () => {
  const none = await call('ssh_grep', { pattern: 'dsh-live-no-such-string-anywhere', path: '/etc/passwd' })
  if (!/no matches/.test(none)) throw new Error(none)
})

await check('ssh_glob finds files by name', async () => {
  const found = await call('ssh_glob', { pattern: 'sshd_config', path: '/etc/ssh' })
  if (!/\/etc\/ssh\/sshd_config/.test(found)) throw new Error(found)
})

// ---------- tty and detached ----------

await check('tty: true allocates a terminal on the server', async () => {
  const report = await call('ssh_run', { command: 'test -t 1 && echo tty-ok', tty: true })
  if (!/tty-ok/.test(report)) throw new Error(report)
})

await check('detached: true returns a pid and a growing log', async () => {
  const logPath = `/tmp/${marker}-detached.log`
  const report = await call('ssh_run', {
    command: `sleep 2; echo detached-done-${marker}`,
    detached: true,
    logPath,
  })
  const pid = /\bpid (\d+)/.exec(report)?.[1]
  if (pid === undefined) throw new Error(`no pid in the report:\n${report}`)
  if (!report.includes(logPath)) throw new Error('no log path in the report')
  await new Promise((resolve) => setTimeout(resolve, 3_000))
  const log = await call('ssh_read', { path: logPath })
  if (!log.includes(`detached-done-${marker}`)) throw new Error(`the log did not fill:\n${log}`)
  await call('ssh_run', { command: `rm -f ${logPath}` }).catch(() => {})
})

// ---------- action log ----------

await check('every live call left a redacted action-log line', async () => {
  const raw = await readFile(join(home, 'audit.jsonl'), 'utf-8')
  const records = raw.trim().split('\n').map((line) => JSON.parse(line))
  const tools = new Set(records.map((record) => record.tool))
  for (const name of ['ssh_run', 'ssh_read', 'ssh_ls', 'ssh_grep', 'ssh_glob']) {
    if (!tools.has(name)) throw new Error(`no audit record for ${name}`)
  }
  if (raw.includes('live-secret-1234')) throw new Error('the password reached the log')
  if (!records.every((record) => typeof record.ts === 'string')) throw new Error('a record has no timestamp')
})

// ---------- cleanup ----------

await call('ssh_run', { command: `rm -f ${remotePath}` }).catch(() => {})
await rm(home, { recursive: true, force: true })

console.log(`\n${checks - failed}/${checks} live checks passed.`)
if (failed > 0) process.exitCode = 1
