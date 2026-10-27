/**
 * Unit tests for the pure layers: SSH argv construction, failure
 * classification, output truncation, and the server registry.
 *
 * Nothing here touches the network or a real server. The argv assertions are the
 * important ones: the exact command line is the plugin's whole contract with
 * OpenSSH, and a mistake there (a flag scp rejects, a port on the wrong flag)
 * only shows up as a confusing runtime failure.
 */
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { closeSync, mkdtempSync, openSync, readFileSync, rmSync } from 'node:fs'
import { mkdtemp, readFile, readdir, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  BATCH_MODE,
  DETACHED_PID,
  STRICT_HOST_KEY,
  classifyCommand,
  classifyFailure,
  connectionOptions,
  copyArgv,
  destination,
  formatArgv,
  formatRunResult,
  redact,
  runArgv,
  shellQuote,
  truncate,
} from './args.js'
import { appendAudit, buildAuditRecord } from './audit.js'
import { hardenPathAcl, icaclsArgv, windowsIdentity } from './acl.js'
import { replaceFile } from './atomic.js'
import {
  RegistryError,
  defaultRegistryPath,
  findEntry,
  mergeDiscovered,
  normalizeEntry,
  parseSshConfig,
  readRegistry,
  removeEntry,
  resolveHome,
  upsertEntry,
  writeRegistry,
} from './registry.js'
import {
  createAskpass,
  defaultSecretsPath,
  queueAskpassCleanup,
  readSecrets,
  removePassword,
  setPassword,
  writeSecrets,
} from './secrets.js'

const config = {
  sshPath: 'ssh',
  scpPath: 'scp',
  connectTimeoutMs: 10_000,
  serverAliveIntervalSec: 15,
  serverAliveCountMax: 3,
  multiplex: false,
}

let checks = 0
/** Run one assertion group with a readable label. */
const ok = (label, fn) => {
  fn()
  checks += 1
  console.log(`  ok  ${label}`)
}

// ---------- argv ----------

ok('command travels as one argv element AND is quoted for the remote shell', () => {
  const argv = runArgv(config, { name: 'web', host: 'example.com' }, 'echo "a b" && ls', undefined)
  // The remote shell is identified by its last two elements. The command is one
  // argument, so no LOCAL shell ever re-parses it...
  assert.deepEqual(argv.slice(-3), ['bash', '-lc', `'echo "a b" && ls'`])
  // ...and it is shell-quoted because `ssh` joins the arguments after the
  // destination with spaces and lets the REMOTE shell parse the result again.
  // Unquoted, `echo AAA` ran a bare `echo` with $0=AAA and printed nothing.
  assert.equal(argv.at(-1), `'echo "a b" && ls'`)
  assert.equal(shellQuote('echo AAA'), "'echo AAA'")
})

ok('connection options are strict and non-interactive', () => {
  const options = connectionOptions(config)
  assert.ok(options.includes(BATCH_MODE), 'BatchMode must be present')
  assert.ok(options.includes(STRICT_HOST_KEY), 'strict host-key checking must be present')
  assert.ok(!options.includes('StrictHostKeyChecking=no'))
  assert.ok(!options.includes('StrictHostKeyChecking=accept-new'))
})

ok('password mode relaxes only BatchMode, never host-key checking', () => {
  const options = connectionOptions(config, true)
  // BatchMode must go, or SSH_ASKPASS is unreachable and no password can work.
  assert.ok(!options.includes(BATCH_MODE), 'BatchMode must be dropped for password auth')
  assert.ok(options.includes('BatchMode=no'))
  // The safety half is kept: exactly one attempt, never an open-ended prompt.
  assert.ok(options.includes('NumberOfPasswordPrompts=1'), 'one attempt only')
  // The key is still tried first, so a keyed server never sees a password.
  assert.ok(options.includes('PreferredAuthentications=publickey,password'))
  // A password changes authentication, not server identity verification.
  assert.ok(options.includes(STRICT_HOST_KEY), 'host-key checking must stay strict')
  assert.ok(!options.some((part) => part.includes('StrictHostKeyChecking=no')))
})

ok('the password value never appears in argv', () => {
  const secret = 's3cret-pw'
  const argv = runArgv(config, { name: 'w', host: 'h', user: 'root' }, 'true', undefined, true)
  // Options legitimately mention password auth (`NumberOfPasswordPrompts`,
  // `PreferredAuthentications`); what must never appear is the secret VALUE, or
  // a flag that would carry it onto the command line where the process list
  // exposes it to every local user.
  assert.ok(!argv.some((part) => part.includes(secret)), 'the secret value must not be an argument')
  assert.ok(!argv.some((part) => /^(-o\s*)?PasswordAuthentication=/i.test(part)), 'no value-carrying password option')
  // The only password-bearing options are the safe, valueless ones.
  for (const part of argv.filter((value) => /password/i.test(value))) {
    assert.ok(
      part === 'NumberOfPasswordPrompts=1' || part === 'PreferredAuthentications=publickey,password',
      `unexpected password-related argument: ${part}`,
    )
  }
})

ok('-T is added for ssh but absent from the shared options', () => {
  const argv = runArgv(config, { name: 'web', host: 'example.com' }, 'true', undefined)
  assert.equal(argv[1], '-T')
  // scp rejects -T outright, so it must not leak into the shared option list.
  assert.ok(!connectionOptions(config).includes('-T'))
})

ok('multiplex flags appear only when enabled', () => {
  assert.ok(!connectionOptions(config).some((part) => part.startsWith('ControlMaster')))
  const shared = connectionOptions({ ...config, multiplex: true, controlPath: '/tmp/c.sock' })
  assert.ok(shared.includes('ControlMaster=auto'))
})

ok('user and non-default port are rendered explicitly', () => {
  assert.equal(destination({ name: 'w', host: 'h', user: 'root' }), 'root@h')
  const argv = runArgv(config, { name: 'w', host: 'h', user: 'root', port: 2222 }, 'true', undefined)
  assert.ok(argv.includes('root@h'))
  const portIndex = argv.indexOf('-p')
  assert.ok(portIndex >= 0, 'a non-default port must be passed')
  assert.equal(argv[portIndex + 1], '2222')
  // The literal host must be an argv element on its own, not glued to a flag.
  assert.ok(!argv.some((part) => part.includes('ssh://')))
})

ok('port 22 is left implicit', () => {
  const argv = runArgv(config, { name: 'w', host: 'h', port: 22 }, 'true', undefined)
  assert.ok(!argv.includes('-p'))
})

ok('identity file is passed when configured', () => {
  const argv = runArgv(config, { name: 'w', host: 'h', identityFile: '/home/u/.ssh/id_ed25519' }, 'true', undefined)
  const index = argv.indexOf('-i')
  assert.ok(index >= 0)
  assert.equal(argv[index + 1], '/home/u/.ssh/id_ed25519')
})

ok('cwd is applied as a quoted cd prefix inside the quoted body', () => {
  const argv = runArgv(config, { name: 'w', host: 'h' }, 'ls', '/srv/app')
  // The whole body is one quoted word, so the `cd` and the command reach
  // `bash -lc` together and `&&` still means "and then" on the server.
  assert.equal(argv.at(-1), shellQuote(`cd ${shellQuote('/srv/app')} && ls`))
  // A quote inside the path must not be able to escape the quoting.
  const tricky = runArgv(config, { name: 'w', host: 'h' }, 'ls', "/srv/it's")
  assert.equal(tricky.at(-1), shellQuote(`cd ${shellQuote("/srv/it's")} && ls`))
  // The rendered argument must be a single POSIX shell word that decodes back
  // to the original body, quotes and all.
  assert.deepEqual(shellWords(tricky.at(-1)), [`cd '/srv/it'\\''s' && ls`])
})

/**
 * Split a string into shell words, modelling POSIX single-quote rules.
 *
 * This is what the remote login shell does to the single string `ssh` sends. It
 * handles exactly the constructs `shellQuote` can emit and nothing more, which
 * keeps it a fair oracle rather than a shell re-implementation:
 *
 *   - unquoted whitespace separates words;
 *   - `'…'` is literal, with no escape sequences of any kind inside;
 *   - `\x` outside quotes yields the literal `x`.
 *
 * A real shell is used instead where one exists (see the agreement check below);
 * this exists because the sandbox denies WSL `bash.exe`.
 *
 * @param text - the command line as the remote shell receives it.
 * @returns the words the remote shell would see.
 */
function shellWords(text) {
  const words = []
  let word = ''
  let started = false
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index]
    if (char === "'") {
      const close = text.indexOf("'", index + 1)
      if (close < 0) throw new Error(`unterminated single quote in: ${text}`)
      word += text.slice(index + 1, close)
      started = true
      index = close
      continue
    }
    if (char === '\\') {
      word += text[index + 1] ?? ''
      started = true
      index += 1
      continue
    }
    if (char === ' ' || char === '\t' || char === '\n') {
      if (started) words.push(word)
      word = ''
      started = false
      continue
    }
    word += char
    started = true
  }
  if (started) words.push(word)
  return words
}

/**
 * Reproduce what `ssh` does to argv after the destination: join the arguments
 * with single spaces into one string, then let the remote shell parse it.
 *
 * This is the exact mechanism behind every symptom in the SSH plugin report, so
 * the round trip is asserted here rather than only in a comment.
 *
 * @param argv - the argv the plugin would spawn.
 * @returns the one command line the server receives.
 */
function whatTheServerSends(argv) {
  return argv.slice(argv.indexOf('bash')).join(' ')
}

ok('the quoted body survives the SSH join and a second shell parse', () => {
  // Every case that used to be mangled by the missing quotes.
  const cases = [
    'echo AAA',
    'uname -m',
    'echo FIRST; echo SECOND',
    'for i in 1 2 3; do echo "iter$i"; done',
    'if [ -d /var/www ]; then echo httpd-ok; fi',
    "sh -c 'echo quoted-ok'",
    'printf "b\\na\\n" | sort',
    'echo "кавычки \'внутри\'"',
  ]
  for (const command of cases) {
    const argv = runArgv(config, { name: 'w', host: 'h' }, command, undefined)
    // `ssh` joins argv with spaces; the remote shell must still recover exactly
    // three words — the interpreter, its flag, and the untouched command. Before
    // the fix `echo AAA` arrived as `bash -lc echo AAA` and ran a bare `echo`.
    assert.deepEqual(
      shellWords(whatTheServerSends(argv)),
      ['bash', '-lc', command],
      `the body was re-split on the server: ${command}`,
    )
  }
})

ok('the quoted body also survives a cwd prefix', () => {
  const argv = runArgv(config, { name: 'w', host: 'h' }, "echo 'a b'", "/srv/it's")
  assert.deepEqual(shellWords(whatTheServerSends(argv)), ['bash', '-lc', `cd '/srv/it'\\''s' && echo 'a b'`])
})

ok('a real shell agrees with the splitter, where one is available', () => {
  // On Linux CI this is the stronger oracle. On Windows `bash.exe` is WSL, which
  // this sandbox denies, so the splitter check above is what runs.
  const command = "for i in 1 2; do echo \"$i\"; done"
  const sent = whatTheServerSends(runArgv(config, { name: 'w', host: 'h' }, command, undefined))
  const dir = mkdtempSync(join(tmpdir(), 'ssh-quote-'))
  const outPath = join(dir, 'probe.txt')
  const outFd = openSync(outPath, 'w')
  const probe = spawnSync('bash', ['-c', `printf '%s\\n' ${sent}`], { stdio: ['ignore', outFd, 'ignore'] })
  closeSync(outFd)
  // `bash` is only useful if it actually parsed the line; a denied or broken
  // interpreter writes nothing and must not be mistaken for a pass.
  const parsed = probe.error === undefined && probe.status === 0 ? readFileSync(outPath, 'utf-8') : ''
  rmSync(dir, { recursive: true, force: true })
  if (parsed.length === 0) {
    console.log('       (no usable POSIX shell here; the splitter check above stands)')
    return
  }
  assert.deepEqual(parsed.split('\n').slice(0, 3), ['bash', '-lc', command])
})

ok('shellQuote neutralizes embedded single quotes', () => {
  assert.equal(shellQuote('plain'), "'plain'")
  assert.equal(shellQuote("a'b"), "'a'\\''b'")
})

ok('scp puts the remote on the correct side and uses -P', () => {
  const put = copyArgv(config, { name: 'w', host: 'h', user: 'root', port: 2222 }, '/local/f', '/remote/f', 'put')
  assert.deepEqual(put.slice(-2), ['/local/f', 'root@h:/remote/f'])
  const get = copyArgv(config, { name: 'w', host: 'h', user: 'root', port: 2222 }, '/local/f', '/remote/f', 'get')
  assert.deepEqual(get.slice(-2), ['root@h:/remote/f', '/local/f'])
  // scp spells the port -P; using ssh's -p here would be silently wrong.
  const portIndex = put.indexOf('-P')
  assert.ok(portIndex >= 0)
  assert.equal(put[portIndex + 1], '2222')
  assert.ok(!put.includes('-p'))
  assert.ok(!put.includes('-T'), 'scp must not receive the ssh-only -T flag')
  assert.ok(put.includes('-O'), 'the legacy scp protocol keeps copies predictable')
})

// ---------- destructive command classification ----------

ok('the catastrophic tier is always blocked, wrappers included', () => {
  for (const command of [
    'rm -rf /',
    'rm -rf /*',
    'rm -rf ~',
    'rm -rf $HOME',
    'rm -rf "/"',
    'rm -r -f /',
    'sudo rm -rf /',
    'sudo -u root rm -rf /',
    'nohup rm -rf / &',
    'mkfs.ext4 /dev/sda1',
    'mkfs /dev/sda',
    'dd if=/dev/zero of=/dev/sda',
    ':(){ :|:& };:',
    'shutdown -h now',
    'reboot',
    'halt',
    'poweroff',
    'chmod -R 777 /',
    'echo x > /dev/sda',
    "sudo bash -c 'rm -rf /'",
  ]) {
    assert.equal(classifyCommand(command).tier, 'block', command)
  }
})

ok('an irreversible but legitimate command asks first', () => {
  for (const command of [
    'rm -rf /var/www/app',
    'rm -rf .',
    'rm -rf ..',
    'rm -rf *',
    'rm --recursive /tmp/x',
    'docker system prune -af',
    'docker volume rm data',
    'apt purge nginx',
    'apt-get purge -y foo',
    'kill -9 1',
    "mysql -e 'DROP DATABASE prod'",
    'psql -c "TRUNCATE TABLE users"',
  ]) {
    assert.equal(classifyCommand(command).tier, 'ask', command)
  }
})

ok('routine work stays silent, including near-miss text', () => {
  for (const command of [
    'rm -rf ./build',
    'rm -rf node_modules',
    'rm -f /tmp/x',
    'echo "rm -rf /"',
    'echo hi # rm -rf /',
    'echo docker system prune',
    'echo "DROP DATABASE x"',
    'ls -la /',
    'grep -rn "shutdown" /etc',
    'cat /etc/passwd',
    'apt update',
    'df -h',
    'systemctl restart nginx',
    "find . -name '*.log'",
    '',
  ]) {
    assert.equal(classifyCommand(command).tier, 'allow', command)
  }
})

ok('a refusal carries the reason and the accepted limitation is explicit', () => {
  const verdict = classifyCommand('rm -rf /')
  assert.equal(verdict.tier, 'block')
  assert.match(verdict.reason, /recursive delete of \//)
  // Pattern matching, not evaluation: substitution is invisible to the
  // classifier. This is documented in the README as a speed bump, not a boundary.
  assert.doesNotThrow(() => classifyCommand('rm -rf $(echo /)'))
})

ok('tty swaps -T for -tt without ever duplicating the flag', () => {
  const plain = runArgv(config, { name: 'w', host: 'h' }, 'top', undefined)
  assert.equal(plain[1], '-T')
  assert.equal(plain.filter((arg) => arg === '-T' || arg === '-tt').length, 1)
  const tty = runArgv(config, { name: 'w', host: 'h' }, 'top', undefined, undefined, { tty: true })
  assert.equal(tty[1], '-tt')
  assert.ok(!tty.includes('-T'), 'a duplicate -T would cancel the request')
})

ok('detached wraps the command in nohup and prints the pid', () => {
  const command = 'apt upgrade -y'
  const logPath = "/tmp/it's log.txt"
  const body = runArgv(config, { name: 'w', host: 'h' }, command, '/srv/app', undefined, {
    detached: true,
    logPath,
  }).at(-1)
  // The body is one quoted argv element whose content is exactly the documented
  // wrapper: a cd, a group, nohup around an inner login shell, and `echo $!`.
  assert.equal(
    body,
    shellQuote(`cd ${shellQuote('/srv/app')} && { nohup bash -lc ${shellQuote(command)} > ${shellQuote(logPath)} 2>&1 </dev/null & echo $!; }`),
  )
  // Standard input is closed: a background process reading the closed channel
  // would die at its first read.
  assert.match(body, /<\/dev\/null/)
  const noCwd = runArgv(config, { name: 'w', host: 'h' }, 'sleep 1', undefined, undefined, {
    detached: true,
    logPath: '/tmp/x.log',
  }).at(-1)
  assert.equal(noCwd, shellQuote(`{ nohup bash -lc ${shellQuote('sleep 1')} > '/tmp/x.log' 2>&1 </dev/null & echo $!; }`))
  // The pid pattern decides what the tool reports, so it must not match prose.
  assert.equal(DETACHED_PID.exec('4242\n')?.[1], '4242')
  assert.equal(DETACHED_PID.exec('started fine'), null)
})

// ---------- failure classification ----------

ok('a changed host key is reported, never auto-accepted', () => {
  const failure = classifyFailure(255, 'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!')
  assert.equal(failure.code, 'HOST_KEY_CHANGED')
  assert.match(failure.message, /known_hosts/)
  // The message must steer to manual verification, not to a bypass flag.
  assert.doesNotMatch(failure.message, /StrictHostKeyChecking=no/)
})

ok('an offline key is distinguished from a generic failure', () => {
  const failure = classifyFailure(255, 'root@h: Permission denied (publickey,password).')
  assert.equal(failure.code, 'AUTH_FAILED')
  // Without a password the advice points at keys and at the password command.
  assert.match(failure.message, /public key/)
  assert.match(failure.message, /\/ssh pass/)
})

ok('a rejected password is explained as a password problem', () => {
  const failure = classifyFailure(255, 'root@h: Permission denied (publickey,password).', true)
  assert.equal(failure.code, 'AUTH_FAILED')
  // Telling a password user to install a key would hide the real cause.
  assert.match(failure.message, /rejected the password/)
  assert.doesNotMatch(failure.message, /Install your public key/)
})

ok('host-key order wins over the generic 255 branch', () => {
  // Both conditions exit 255; the more important one must be chosen.
  const failure = classifyFailure(255, 'Host key verification failed.')
  assert.equal(failure.code, 'HOST_KEY_CHANGED')
})

ok('network failures are named distinctly', () => {
  assert.equal(classifyFailure(255, 'ssh: Could not resolve hostname h').code, 'HOST_UNRESOLVED')
  assert.equal(classifyFailure(255, 'ssh: connect to host h port 22: Connection timed out').code, 'UNREACHABLE')
})

ok('a remote non-zero exit is not a connection failure', () => {
  const failure = classifyFailure(1, 'apt: command not found')
  assert.equal(failure.code, 'REMOTE_EXIT')
  // The remote's own stderr must travel with the message. It is the only thing
  // that says WHICH command failed and why; without it a failed scp was a bare
  // "exited with code 1" with no path, command or cause.
  assert.match(failure.message, /command not found/)
  // With no stderr there is nothing to append, and no stray blank section.
  const silent = classifyFailure(1, '')
  assert.equal(silent.code, 'REMOTE_EXIT')
  assert.doesNotMatch(silent.message, /\n\n/)
  assert.equal(classifyFailure(0, ''), undefined)
  assert.equal(classifyFailure(0, 'warning on stderr'), undefined)
})

ok('argv is rendered as one readable line for diagnostics', () => {
  const line = formatArgv(['ssh', '-T', 'root@h', 'bash', '-lc', `'echo "a b"'`])
  assert.match(line, /^ssh -T root@h bash -lc /)
  // Elements with spaces or quotes keep visible boundaries so the line can be
  // re-read. The body is JSON-quoted, so its own quotes appear escaped.
  assert.match(line, /"'echo \\"a b\\"'"$/)
  assert.equal(formatArgv([]), '')
  // A pathologically long body is clipped rather than flooding the transcript.
  assert.ok(formatArgv(['ssh', 'x'.repeat(5_000)]).length <= 2_001)
})

// ---------- output ----------

ok('truncation keeps both ends and reports exactly what was dropped', () => {
  assert.deepEqual(truncate('short', 100), { text: 'short', truncated: false })
  const cut = truncate('x'.repeat(50), 10)
  assert.equal(cut.truncated, true)
  assert.match(cut.note, /40 of 50 characters omitted/)
  assert.match(cut.text, /… пропущено 40 символов \(из 50\) …/)
  // The tail is the whole point: the failing step of a long build and an apt
  // error are at the END, and a head-only cut hid them.
  const long = `${'H'.repeat(600)}${'T'.repeat(400)}`
  const clipped = truncate(long, 100)
  assert.ok(clipped.text.startsWith('H'))
  assert.ok(clipped.text.endsWith('T'))
  assert.ok(clipped.text.includes('… пропущено 900 символов (из 1000) …'))
  // The marker may overshoot the budget; the captured text itself may not.
  assert.ok(clipped.text.length <= 100 + 100, 'the marker is the only allowed overshoot')
})

ok('high-confidence secrets are removed from captured output', () => {
  const key = '-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3NzaC1yc2E\n-----END OPENSSH PRIVATE KEY-----'
  const redacted = redact(`before\n${key}\nafter`)
  assert.equal(redacted.count, 1)
  assert.equal(redacted.text, 'before\n«redacted:private-key»\nafter')
  assert.equal(redact('AKIAABCDEFGHIJKLMNOP').count, 1)
  assert.equal(redact('sk-abcdefghijklmnopqrstuvwx').count, 1)
  // A labeled secret is ONE removal, even when its value also matches a value
  // rule: counting it twice reported a wrong number and kept the value marker.
  assert.equal(redact('token: sk-abcdefghijklmnopqrstuvwx').count, 1)
  assert.equal(redact('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U').count, 1)
  assert.equal(redact('Authorization: Bearer abc.def.ghi').count, 1)
  assert.equal(redact('postgres://user:pass@db.example.com:5432/app').count, 1)
  assert.equal(redact('DB_PASSWORD="two words"').count, 1)
  // The report says a value was removed, so the model does not read the command
  // as broken output.
  const report = formatRunResult({ exitCode: 0, stdout: 'password=hunter2', stderr: '' }, 1_000)
  assert.match(report, /вырезано 1 секрет/)
  assert.doesNotMatch(report, /hunter2/)
})

ok('redaction leaves ordinary output alone', () => {
  for (const text of [
    'password=',
    'https://example.com/path',
    'a normal log line',
    'token',
    'mypassword=s3cr3t',
    'the token field is empty',
  ]) {
    const result = redact(text)
    assert.equal(result.count, 0, text)
    assert.equal(result.text, text)
  }
})

ok('the run report always carries stdout, stderr and the exit code', () => {
  const report = formatRunResult({ exitCode: 0, stdout: 'hello', stderr: '' }, 1000)
  assert.match(report, /exit=0/)
  assert.match(report, /--- stdout ---/)
  assert.match(report, /hello/)
  assert.match(report, /\(empty\)/)
  const signalled = formatRunResult({ exitCode: null, signal: 'SIGTERM', stdout: '', stderr: '' }, 1000)
  assert.match(signalled, /signal/)
})

// ---------- registry ----------

ok('entry normalization rejects unusable names and hosts', () => {
  assert.throws(() => normalizeEntry({ name: '', host: 'h' }), RegistryError)
  assert.throws(() => normalizeEntry({ name: 'has space', host: 'h' }), RegistryError)
  assert.throws(() => normalizeEntry({ name: 'ok', host: '' }), RegistryError)
  assert.throws(() => normalizeEntry({ name: 'ok', host: 'h', port: 0 }), RegistryError)
  assert.throws(() => normalizeEntry({ name: 'ok', host: 'h', port: 70000 }), RegistryError)
  const entry = normalizeEntry({ name: 'web-1', host: 'h', user: 'root', port: 2222 })
  assert.deepEqual({ name: entry.name, host: entry.host, user: entry.user, port: entry.port }, { name: 'web-1', host: 'h', user: 'root', port: 2222 })
})

ok('duplicate names are refused unless replacement is explicit', () => {
  const list = [normalizeEntry({ name: 'web', host: 'a' })]
  assert.throws(() => upsertEntry(list, normalizeEntry({ name: 'web', host: 'b' }), false), RegistryError)
  const replaced = upsertEntry(list, normalizeEntry({ name: 'web', host: 'b' }), true)
  assert.equal(replaced.length, 1)
  assert.equal(replaced[0].host, 'b')
})

ok('removal reports an unknown name instead of silently succeeding', () => {
  const list = [normalizeEntry({ name: 'web', host: 'a' })]
  assert.throws(() => removeEntry(list, 'nope'), RegistryError)
  assert.deepEqual(removeEntry(list, 'web'), [])
})

ok('lookup is case-insensitive but never invents an entry', () => {
  const list = [normalizeEntry({ name: 'Web', host: 'a' })]
  assert.equal(findEntry(list, 'web')?.name, 'Web')
  assert.equal(findEntry(list, 'other'), undefined)
})

ok('only a broken FILE is fatal; a repairable row is a warning', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-remote-reg-'))
  const path = join(dir, 'hosts.json')
  await writeFile(path, '{ not json', 'utf-8')
  const broken = readRegistry(path)
  assert.equal(broken.hosts.length, 0)
  // A file that cannot be parsed at all is fatal: nothing in it is trustworthy.
  assert.match(broken.problem, /not valid JSON/)

  // One unusable row must NOT be fatal, or a single bad entry would take the
  // whole command down. This distinction is a fixed bug: conflating the two made
  // /ssh refuse to list a registry that was otherwise perfectly usable.
  await writeFile(path, JSON.stringify({ version: 1, hosts: [{ name: 'ok', host: 'h' }, { name: 'bad name', host: 'h' }] }), 'utf-8')
  const partial = readRegistry(path)
  assert.equal(partial.hosts.length, 1, 'the valid row survives')
  assert.equal(partial.problem, undefined, 'a skipped row must not be fatal')
  assert.match(partial.warnings.join(' '), /skipped/)
})

ok('a missing registry is a normal first run, not a problem', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-remote-missing-'))
  const document = readRegistry(join(dir, 'absent.json'))
  assert.deepEqual(document.hosts, [])
  assert.equal(document.problem, undefined)
  assert.deepEqual(document.warnings, [])
})

ok('the registry round-trips through an atomic write', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-remote-rw-'))
  const path = join(dir, 'nested', 'hosts.json')
  const hosts = [normalizeEntry({ name: 'web', host: 'h', user: 'root', port: 2222 })]
  await writeRegistry(path, hosts, 'web')
  const document = readRegistry(path)
  assert.equal(document.hosts.length, 1)
  assert.equal(document.hosts[0].port, 2222)
  assert.equal(document.default, 'web')
  const raw = JSON.parse(await readFile(path, 'utf-8'))
  assert.equal(raw.version, 1)
})

ok('registry location follows DSH_HOME', () => {
  const previous = process.env.DSH_HOME
  process.env.DSH_HOME = 'C:\\temp\\dsh-home'
  try {
    assert.equal(resolveHome(undefined), 'C:\\temp\\dsh-home')
    assert.ok(defaultRegistryPath(resolveHome(undefined)).endsWith('ssh-remote-hosts.json'))
  } finally {
    if (previous === undefined) delete process.env.DSH_HOME
    else process.env.DSH_HOME = previous
  }
})

// ---------- ssh config parsing ----------

const sampleConfig = `
# a comment
Host simple
  HostName 203.0.113.10
  User root
  Port 2222
  IdentityFile ~/.ssh/id_ed25519

Host alias-only

Host multi one
  HostName 203.0.113.11

Host *
  ServerAliveInterval 30

Include conf.d/*.conf

Host withEquals
  HostName=203.0.113.12
  User=admin
`

ok('the parser reads the common Host form', () => {
  const { found } = parseSshConfig(sampleConfig)
  const simple = found.find((entry) => entry.name === 'simple')
  assert.deepEqual(simple, { name: 'simple', host: '203.0.113.10', user: 'root', port: 2222, identityFile: '~/.ssh/id_ed25519' })
  // A block with no HostName falls back to its own pattern.
  assert.deepEqual(found.find((entry) => entry.name === 'alias-only'), { name: 'alias-only', host: 'alias-only' })
})

ok('Host and value separated by = is accepted too', () => {
  const { found } = parseSshConfig(sampleConfig)
  assert.deepEqual(found.find((entry) => entry.name === 'withEquals'), { name: 'withEquals', host: '203.0.113.12', user: 'admin' })
})

ok('wildcards and multi-pattern blocks are skipped, not guessed', () => {
  const { found, skipped } = parseSshConfig(sampleConfig)
  assert.equal(found.find((entry) => entry.name === '*'), undefined)
  assert.equal(found.find((entry) => entry.name === 'multi'), undefined)
  assert.ok(skipped.includes('*'))
  assert.ok(skipped.includes('multi one'), 'a multi-pattern block cannot be reduced to one server')
  assert.ok(skipped.some((item) => item.startsWith('include')), 'Include is reported rather than half-applied')
})

ok('comments and blank lines are ignored', () => {
  const { found } = parseSshConfig('# only a comment\n\n')
  assert.deepEqual(found, [])
})

ok('sync adds new servers but never overwrites an existing one', () => {
  const existing = [normalizeEntry({ name: 'simple', host: 'kept.example' })]
  const { hosts, added } = mergeDiscovered(existing, [
    { name: 'simple', host: '203.0.113.10' },
    { name: 'fresh', host: '203.0.113.99' },
  ])
  assert.deepEqual(added, ['fresh'])
  assert.equal(hosts.find((entry) => entry.name === 'simple').host, 'kept.example', 'a working entry must not be silently rewritten')
  assert.equal(hosts.length, 2)
})

// ---------- password store ----------

await ok('a missing password store is a normal first run', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-remote-sec-'))
  const document = readSecrets(join(dir, 'absent.json'))
  assert.deepEqual(document.passwords, {})
  assert.equal(document.problem, undefined)
  assert.ok(defaultSecretsPath(dir).endsWith('ssh-remote-secrets.json'))
})

await ok('passwords round-trip and never lose an unrelated entry', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-remote-sec-rw-'))
  const path = join(dir, 'secrets.json')
  let passwords = {}
  passwords = setPassword(passwords, 'web1', 'first')
  passwords = setPassword(passwords, 'web2', 'second')
  await writeSecrets(path, passwords)
  let document = readSecrets(path)
  assert.equal(document.passwords.web1, 'first')
  assert.equal(document.passwords.web2, 'second')

  // Replacing one entry must not disturb the others.
  await writeSecrets(path, setPassword(document.passwords, 'web1', 'changed'))
  document = readSecrets(path)
  assert.equal(document.passwords.web1, 'changed')
  assert.equal(document.passwords.web2, 'second')

  await writeSecrets(path, removePassword(document.passwords, 'web1'))
  document = readSecrets(path)
  assert.equal(document.passwords.web1, undefined)
  assert.equal(document.passwords.web2, 'second')
})

await ok('an empty stored password counts as absent', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-remote-sec-empty-'))
  const path = join(dir, 'secrets.json')
  await writeFile(path, JSON.stringify({ version: 1, passwords: { web: '', other: 'x' } }), 'utf-8')
  const document = readSecrets(path)
  // A blank must never masquerade as a configured password.
  assert.equal(document.passwords.web, undefined)
  assert.equal(document.passwords.other, 'x')
})

await ok('a corrupt password store reports rather than guessing', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-remote-sec-bad-'))
  const path = join(dir, 'secrets.json')
  await writeFile(path, '{ not json', 'utf-8')
  const document = readSecrets(path)
  assert.deepEqual(document.passwords, {})
  assert.match(document.problem, /not valid JSON/)
})

await ok('the askpass helper carries the password without shell interpretation', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-remote-ask-'))
  // Characters that would break a batch file if interpolated into it.
  const password = 'p%a&s"s^w<o>r|d'
  const askpass = await createAskpass(dir, password)
  assert.ok(askpass.env.SSH_ASKPASS, 'the helper path must be exported')
  // Without `force`, the helper is ignored on a machine with no terminal.
  assert.equal(askpass.env.SSH_ASKPASS_REQUIRE, 'force')
  assert.ok(askpass.env.DSH_SSH_ASKPASS_FILE, 'the secret file must be exported')

  const shim = await readFile(askpass.env.SSH_ASKPASS, 'utf-8')
  // The shim must read the file, never embed the value: embedding would let a
  // `%`, `&` or quote in the password execute as batch syntax.
  assert.ok(!shim.includes(password), 'the shim must not embed the password')
  assert.match(shim, /DSH_SSH_ASKPASS_FILE/)

  const secret = await readFile(askpass.env.DSH_SSH_ASKPASS_FILE, 'utf-8')
  // Exactly one trailing newline is what ssh expects to read as the password.
  assert.equal(secret, `${password}\n`)

  await askpass.cleanup()
  await assert.rejects(() => readFile(askpass.env.SSH_ASKPASS, 'utf-8'), 'the helper must be removed')
  await assert.rejects(() => readFile(askpass.env.DSH_SSH_ASKPASS_FILE, 'utf-8'), 'the secret must be removed')
})

await ok('a note typed into the key field is refused', () => {
  // This is a real observed mistake: "no key, there is a password" went into the
  // key path, then reached `ssh -i` and produced a confusing auth failure.
  assert.throws(
    () => normalizeEntry({ name: 'web', host: 'h', identityFile: 'Нет ключа, есть пароль' }),
    /does not look like a path/,
  )
  assert.throws(() => normalizeEntry({ name: 'web', host: 'h', identityFile: 'no key yet' }), RegistryError)
})

await ok('legitimate key paths are accepted', () => {
  // A path with separators is accepted even with spaces, as a Windows profile may.
  assert.equal(normalizeEntry({ name: 'w', host: 'h', identityFile: 'C:\\Users\\user name\\.ssh\\id_ed25519' }).identityFile, 'C:\\Users\\user name\\.ssh\\id_ed25519')
  assert.equal(normalizeEntry({ name: 'w', host: 'h', identityFile: '~/.ssh/id_ed25519' }).identityFile, '~/.ssh/id_ed25519')
  // A bare filename is accepted by extension or by the conventional prefix.
  assert.equal(normalizeEntry({ name: 'w', host: 'h', identityFile: 'id_ed25519' }).identityFile, 'id_ed25519')
  assert.equal(normalizeEntry({ name: 'w', host: 'h', identityFile: 'mykey.pem' }).identityFile, 'mykey.pem')
})

await ok('a description is stored separately from the key', () => {
  const entry = normalizeEntry({ name: 'w', host: 'h', description: 'no key, use a password' })
  assert.equal(entry.description, 'no key, use a password')
  assert.equal(entry.identityFile, undefined, 'a note must never become the key path')
})

await ok('a bad key path keeps the server instead of dropping it', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-remote-salvage-'))
  const path = join(dir, 'hosts.json')
  // The exact shape a real registry ended up in: a note in the key field.
  await writeFile(
    path,
    JSON.stringify({
      version: 1,
      hosts: [{ name: 'ND', host: '203.0.113.9', user: 'root', identityFile: 'Нет ключа, есть пароль' }],
    }),
    'utf-8',
  )
  const document = readRegistry(path)
  // The address and user are still usable, so the entry must survive without
  // its bogus key rather than disappearing entirely.
  assert.equal(document.hosts.length, 1, 'the server must be salvaged')
  assert.equal(document.hosts[0].name, 'ND')
  assert.equal(document.hosts[0].host, '203.0.113.9')
  assert.equal(document.hosts[0].identityFile, undefined, 'the bad key must be dropped')
  // Crucially this is a WARNING: the registry still works, and /ssh must list it.
  assert.equal(document.problem, undefined, 'a salvaged entry must not be fatal')
  assert.match(document.warnings.join(' '), /not a key path/)
})

await ok('askpass survives a concurrent cleanup of the scratch root', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-remote-race-'))
  // Regression: activation queues an rm -rf of the scratch root, and an
  // unsequenced version of it deleted the secret mid-connection, which surfaced
  // as "The system cannot find the file specified" from Windows and a failed
  // login even with a correct password.
  void queueAskpassCleanup(dir)
  const askpass = await createAskpass(dir, 'race-secret')
  const secret = await readFile(askpass.env.DSH_SSH_ASKPASS_FILE, 'utf-8')
  assert.equal(secret, 'race-secret\n', 'the secret must survive the queued cleanup')
  // It must also still be there a moment later, once the cleanup has settled.
  await new Promise((resolve) => setTimeout(resolve, 50))
  assert.equal(await readFile(askpass.env.DSH_SSH_ASKPASS_FILE, 'utf-8'), 'race-secret\n')
  await askpass.cleanup()
  await assert.rejects(() => readFile(askpass.env.DSH_SSH_ASKPASS_FILE, 'utf-8'))
})

await ok('two concurrent password calls use independent directories', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-remote-parallel-'))
  const [first, second] = await Promise.all([createAskpass(dir, 'first-pw'), createAskpass(dir, 'second-pw')])
  // One call's cleanup must never be able to remove the other's files.
  assert.notEqual(first.env.DSH_SSH_ASKPASS_FILE, second.env.DSH_SSH_ASKPASS_FILE)
  await first.cleanup()
  assert.equal(await readFile(second.env.DSH_SSH_ASKPASS_FILE, 'utf-8'), 'second-pw\n', 'the other call must survive')
  await second.cleanup()
})

await ok('concurrent registry writes use their own temporary file', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-remote-registry-'))
  const path = join(dir, 'hosts.json')
  const left = [{ name: 'left', host: '10.0.0.1' }]
  const right = [{ name: 'right', host: '10.0.0.2' }]
  await Promise.all([writeRegistry(path, left, 'left'), writeRegistry(path, right, 'right')])
  const parsed = JSON.parse(await readFile(path, 'utf-8'))
  // Either writer may win the last rename, but the file must be one complete
  // document — never a mixture of both and never a truncated file.
  const stored = JSON.stringify(parsed.hosts)
  assert.ok(stored === JSON.stringify(left) || stored === JSON.stringify(right), `unmerged result: ${stored}`)
  // A shared `${path}.tmp` would also leave a file behind after a crash.
  assert.deepEqual((await readdir(dir)).filter((name) => name.endsWith('.tmp')), [])
})

await ok('replaceFile swaps the document and keeps no temporary', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-remote-atomic-'))
  const target = join(dir, 'doc.json')
  await writeFile(target, '{"v":1}\n', 'utf-8')
  const temporary = join(dir, 'doc.json.tmp')
  await writeFile(temporary, '{"v":2}\n', 'utf-8')
  await replaceFile(temporary, target)
  assert.equal(await readFile(target, 'utf-8'), '{"v":2}\n')
  assert.deepEqual(await readdir(dir), ['doc.json'])
})

await ok('replaceFile rethrows a failure that retrying cannot fix', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-remote-atomic-'))
  const temporary = join(dir, 'doc.json.tmp')
  await writeFile(temporary, '{"v":2}\n', 'utf-8')
  // A missing parent is a permanent error, not a held file: it must surface at
  // once rather than being retried into a generic timeout.
  await assert.rejects(
    () => replaceFile(temporary, join(dir, 'missing', 'doc.json')),
    (error) => error.code === 'ENOENT',
  )
})

// ---------- Windows ACL ----------------------------------------------------

ok('icacls argv is built without a shell', () => {
  assert.deepEqual(icaclsArgv('C:\\Users\\user\\.dsh\\ssh-remote-secrets.json', 'PC\\user'), [
    'icacls',
    'C:\\Users\\user\\.dsh\\ssh-remote-secrets.json',
    '/inheritance:r',
    '/grant:r',
    'PC\\user:F',
  ])
  // A directory needs an inheritable grant, or files created inside it keep
  // whatever the parent directory granted them — which is the leak this closes.
  assert.equal(icaclsArgv('C:\\dir', 'PC\\user', { inheritable: true }).at(-1), 'PC\\user:(OI)(CI)F')
  assert.equal(windowsIdentity({ USERDOMAIN: 'PC' }, 'user'), 'PC\\user')
  assert.equal(windowsIdentity({}, 'user'), 'user')
})

await ok('a POSIX host never runs icacls at all', async () => {
  let called = 0
  const outcome = await hardenPathAcl('/home/u/.dsh/ssh-remote-secrets.json', {
    platform: 'linux',
    run: async () => {
      called += 1
      return 0
    },
  })
  assert.equal(called, 0, 'chmod is the POSIX mechanism; icacls must not run')
  assert.equal(outcome.applied, false)
  assert.match(outcome.reason, /not windows/)
})

await ok('a Windows ACL failure is logged, never raised', async () => {
  const warnings = []
  const failed = await hardenPathAcl('C:\\file', {
    platform: 'win32',
    identity: 'PC\\user',
    logger: { warn: (...args) => warnings.push(args) },
    run: async () => 5,
  })
  // Tightening an ACL must never fail the password write it accompanies.
  assert.equal(failed.applied, false)
  assert.equal(warnings.length, 1)
  const threw = await hardenPathAcl('C:\\file', {
    platform: 'win32',
    identity: 'PC\\user',
    run: async () => {
      throw new Error('icacls is missing')
    },
  })
  assert.equal(threw.applied, false)
  assert.match(String(threw.error?.message), /icacls is missing/)
})

// ---------- audit log -------------------------------------------------------

await ok('an audit record redacts secrets and clips the command', async () => {
  const record = buildAuditRecord({
    server: 'web1',
    host: '10.0.0.1',
    tool: 'ssh_run',
    command: 'curl -H "Authorization: Bearer abc.def" https://x && echo password=hunter2',
    exitCode: 0,
    durationMs: 12.6,
    timedOut: false,
    passwordAuth: true,
  })
  assert.equal(record.server, 'web1')
  assert.equal(record.host, '10.0.0.1')
  assert.equal(record.exitCode, 0)
  assert.equal(record.durationMs, 13)
  assert.equal(record.passwordAuth, true)
  assert.equal(record.timedOut, false)
  assert.match(record.command, /«redacted:bearer»/)
  assert.match(record.command, /«redacted:credential»/)
  assert.ok(!record.command.includes('hunter2'), 'a log that leaks the secret is a leak')
  // One record is one line, so `jq`/`grep` can read it and a newline in the
  // command cannot forge a second entry.
  assert.equal(buildAuditRecord({ command: 'line one\nline two' }).command, 'line one line two')
  assert.ok(buildAuditRecord({ command: 'x'.repeat(500) }).command.length <= 200)
})

await ok('every call appends one JSON line, and the file rotates', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-remote-audit-'))
  const path = join(dir, 'audit.jsonl')
  await appendAudit(path, buildAuditRecord({ tool: 'ssh_run', command: 'id' }))
  await appendAudit(path, buildAuditRecord({ tool: 'ssh_put', exitCode: 1 }))
  const lines = (await readFile(path, 'utf-8')).trim().split('\n')
  assert.equal(lines.length, 2)
  assert.equal(JSON.parse(lines[0]).tool, 'ssh_run')
  assert.equal(JSON.parse(lines[1]).exitCode, 1)
  // The previous contents are kept as one archive, so the log stays bounded.
  const rotated = join(dir, 'rotated.jsonl')
  await appendAudit(rotated, buildAuditRecord({ command: 'first-entry' }), { maxBytes: 50 })
  await appendAudit(rotated, buildAuditRecord({ command: 'second-entry' }), { maxBytes: 50 })
  assert.match(await readFile(`${rotated}.1`, 'utf-8'), /first-entry/)
  assert.equal((await readFile(rotated, 'utf-8')).trim().split('\n').length, 1)
})

await ok('concurrent audit appends stay whole lines', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ssh-remote-audit-race-'))
  const path = join(dir, 'audit.jsonl')
  await Promise.all(
    Array.from({ length: 20 }, (_, index) => appendAudit(path, buildAuditRecord({ command: `cmd-${index}`, server: 's' }))),
  )
  const lines = (await readFile(path, 'utf-8')).trim().split('\n')
  assert.equal(lines.length, 20)
  for (const line of lines) assert.doesNotThrow(() => JSON.parse(line), 'no interleaved record')
})

console.log(`\n${checks} checks passed.`)
