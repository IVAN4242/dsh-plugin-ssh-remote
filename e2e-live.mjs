/**
 * End-to-end check of the real plugin code against a real SSH server.
 *
 * This is not part of the normal suite: it needs a reachable server and it
 * spawns the real `ssh.exe`. It exists because the unit tests use a fake
 * subprocess, and the one thing a fake cannot prove is that OpenSSH actually
 * consumes the generated SSH_ASKPASS helper.
 *
 * The child's output goes to files rather than pipes, because the DSH sandbox
 * denies piped stdio for spawned processes.
 *
 * Usage: node e2e-live.mjs <host> [user] [password]
 * With no password it checks the key path; with one it checks the password path.
 */
import { spawn } from 'node:child_process'
import { createRequire } from 'node:module'
import { openSync, closeSync, readFileSync } from 'node:fs'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const require = createRequire(import.meta.url)

const host = process.argv[2]
const user = process.argv[3] ?? 'root'
const password = process.argv[4]
if (host === undefined) {
  console.error('usage: node e2e-live.mjs <host> [user] [password]')
  process.exit(2)
}

const home = await mkdtemp(join(tmpdir(), 'ssh-e2e-'))
const registryPath = join(home, 'hosts.json')
const secretsPath = join(home, 'secrets.json')
const askpassDir = join(home, 'askpass')

await writeFile(registryPath, JSON.stringify({ version: 1, hosts: [{ name: 'live', host, user }] }), 'utf-8')
await writeFile(
  secretsPath,
  JSON.stringify({ version: 1, passwords: password === undefined ? {} : { live: password } }),
  'utf-8',
)

const tools = new Map()

/**
 * A subprocess provider that matches the documented contract but writes the
 * child's streams to files. Pipes are denied by the sandbox; files are not.
 */
const subprocess = {
  spawn(spec) {
    const [program, ...rest] = spec.argv
    const outPath = join(home, `out-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.txt`)
    const errPath = join(home, `err-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.txt`)
    // Pipes are denied by the sandbox, so the child writes straight to files.
    const outFd = openSync(outPath, 'w')
    const errFd = openSync(errPath, 'w')
    const child = spawn(program, rest, {
      cwd: spec.cwd,
      env: spec.env ?? process.env,
      stdio: ['ignore', outFd, errFd],
    })
    closeSync(outFd)
    closeSync(errFd)
    const done = new Promise((resolve) => {
      child.on('error', (error) => resolve({ exitCode: null, signal: null, error }))
      child.on('close', (code, signal) => resolve({ exitCode: code, signal: signal ?? null }))
    })
    return {
      collected: {
        // The plugin reads collected output after `done` resolves, by which time
        // the child's files are complete, so a synchronous read is correct here.
        stdout: { readFrom: () => ({ text: readFileSync(outPath, 'utf-8') }) },
        stderr: { readFrom: () => ({ text: readFileSync(errPath, 'utf-8') }) },
      },
      done,
      terminate: () => child.kill(),
      waitForExit: () => done.then(() => true),
    }
  },
}

const ctx = {
  logger: { info: () => {}, warn: (m, ...r) => console.error('[warn]', m, ...r), error: () => {}, debug: () => {} },
  get: (name) => (name === 'subprocess' ? subprocess : undefined),
  tools: { register: (d) => { tools.set(d.name, d) }, guard: () => {} },
  inject: () => {},
  effect: () => () => {},
}

const { apply } = await import('./index.js')
apply(ctx, {
  registryPath,
  secretsPath,
  askpassDir,
  // A throwaway registry must not append to the real action log.
  auditLogPath: join(home, 'audit.jsonl'),
  sshPath: 'C:/Windows/System32/OpenSSH/ssh.exe',
  scpPath: 'C:/Windows/System32/OpenSSH/scp.exe',
  connectTimeoutMs: 15_000,
  defaultTimeoutMs: 30_000,
  maxOutputChars: 4_000,
})

const tool = tools.get('ssh_run')
try {
  const report = await tool.execute(
    { host: 'live', command: 'id; uname -s' },
    { agent: { id: 's', session: { header: { cwd: process.cwd() } } }, signal: new AbortController().signal },
  )
  console.log('RESULT: SUCCESS')
  console.log(report.slice(0, 500))
} catch (error) {
  console.log('RESULT: FAILED')
  console.log('CODE:', error.code)
  // Only the first lines matter; the rest is the raw ssh stderr.
  console.log('MESSAGE:', error.message.split('\n').slice(0, 3).join(' | '))
}
