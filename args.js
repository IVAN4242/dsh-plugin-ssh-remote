/**
 * Pure helpers for building OpenSSH argv and classifying its failures.
 *
 * Every function here is side-effect free and network free, so the whole
 * contract of "what exactly do we execute, and how do we read the result" is
 * testable without touching a server.
 *
 * Design notes:
 *  - Commands travel as ONE argv element. No local shell is involved, so there
 *    is no Windows/POSIX quoting gap and no shell injection surface.
 *  - The command body is nevertheless shell-quoted for the REMOTE side: `ssh`
 *    does not hand argv through to the server, it joins every argument after the
 *    destination with single spaces and gives the result to the remote login
 *    shell as one string, which parses it again. See {@link runArgv}.
 *  - Host-key checking is always strict. This module never generates a flag that
 *    could accept a changed host key; that decision belongs to the human.
 *  - `BatchMode=yes` guarantees a missing or unusable key fails fast instead of
 *    blocking on a password prompt that no one can answer.
 *  - Output is redacted before it is formatted for the model: a captured secret
 *    must not travel to a model provider just because a command happened to print
 *    it. See {@link redact}.
 *  - Destructive commands are classified, never silently allowed through. The
 *    matching is a speed bump, not a sandbox — see {@link classifyCommand}.
 *
 * @module dsh-plugin-ssh-remote/args
 */

/** Host-key checking policy is deliberately not configurable. */
export const STRICT_HOST_KEY = 'StrictHostKeyChecking=yes'

/** Refuse interactive authentication; fail fast instead of hanging on a prompt. */
export const BATCH_MODE = 'BatchMode=yes'

/**
 * The remote shell used to interpret a command string.
 *
 * `bash -lc` gives a login shell so `/etc/profile` PATH entries (where
 * distro-supplied tools often live) are present, while still taking the command
 * as a single argument.
 */
const REMOTE_SHELL = Object.freeze(['bash', '-lc'])

/**
 * Build the connection options both clients accept.
 *
 * `-T` is deliberately absent: it disables pseudo-terminal allocation and is an
 * ssh-only flag that scp rejects outright. `runArgv` adds it, because a
 * non-interactive command must never wait on a TTY.
 *
 * When `passwordAuth` is true, `BatchMode=yes` is swapped for an explicit
 * `NumberOfPasswordPrompts=1`:
 *
 *  - `BatchMode=yes` forbids ALL interactive authentication, which includes the
 *    `SSH_ASKPASS` helper. It must be relaxed for a password to be usable at all.
 *  - `NumberOfPasswordPrompts=1` keeps the important half of that guarantee: one
 *    attempt, then failure. A wrong password can never become a prompt that hangs
 *    waiting for input nobody will type.
 *  - `PreferredAuthentications=publickey,password` still tries the key first, so
 *    a server that has a working key is never asked for a password.
 *
 * Host-key checking is NOT weakened in this mode: a password changes how the
 * client authenticates to the server, not how it verifies the server's identity.
 *
 * @param config - resolved plugin configuration.
 * @param passwordAuth - whether this invocation supplies a password.
 * @returns the shared SSH option flags, in a stable order.
 */
export function connectionOptions(config, passwordAuth) {
  const shared = [
    '-o', STRICT_HOST_KEY,
    '-o', `ConnectTimeout=${config.connectTimeoutMs}`,
    '-o', `ServerAliveInterval=${config.serverAliveIntervalSec}`,
    '-o', `ServerAliveCountMax=${config.serverAliveCountMax}`,
  ]
  const auth =
    passwordAuth === true
      ? ['-o', 'BatchMode=no', '-o', 'NumberOfPasswordPrompts=1', '-o', 'PreferredAuthentications=publickey,password']
      : ['-o', BATCH_MODE]
  return [...auth, ...shared, ...multiplexOptions(config)]
}

/**
 * Connection-sharing flags, when explicitly enabled.
 *
 * Multiplexing needs OpenSSH connection sharing over a Unix socket, which the
 * Windows build does not provide. It stays opt-in so a POSIX deployment can turn
 * it on, and the flags are omitted entirely rather than emitted broken.
 *
 * @param config - resolved plugin configuration.
 * @returns the multiplex flags, or an empty list.
 */
function multiplexOptions(config) {
  if (config.multiplex !== true) return []
  return ['-o', 'ControlMaster=auto', '-o', `ControlPath=${config.controlPath}`, '-o', 'ControlPersist=60']
}

/**
 * Render a registry entry as an OpenSSH destination.
 *
 * The plain `user@host` form is used, with the port carried by a flag instead of
 * a `ssh://…:port` URI. Both clients accept the URI form, but they disagree on
 * how it combines with `-p`, and the flag form is what every OpenSSH release
 * treats identically. Building the destination explicitly also means a server
 * works even with no alias defined for it.
 *
 * @param entry - a validated registry entry.
 * @returns the destination argument for `ssh`.
 */
export function destination(entry) {
  return entry.user === undefined ? entry.host : `${entry.user}@${entry.host}`
}

/**
 * SSH port and identity flags for one entry.
 *
 * Kept separate from {@link copyArgv} because `ssh` spells the port `-p` while
 * `scp` spells it `-P`; sharing one helper silently broke one of them.
 *
 * @param entry - a validated registry entry.
 * @returns extra SSH flags for this server.
 */
export function entryOptions(entry) {
  const options = []
  if (entry.port !== undefined && entry.port !== 22) options.push('-p', String(entry.port))
  if (entry.identityFile !== undefined) options.push('-i', entry.identityFile)
  return options
}

/**
 * Build the argv for a remote command.
 *
 * The body MUST be shell-quoted even though it is already one argv element. The
 * local process boundary is not the problem: `ssh` itself does not forward argv.
 * It concatenates every argument after the destination with single spaces and
 * hands that single string to the remote login shell, which parses it again. An
 * unquoted body is therefore re-split on the server, and
 *
 *   argv:  ssh … host bash -lc echo AAA
 *   string ssh sends:  bash -lc echo AAA
 *   remote shell sees: bash -lc | echo | AAA   →  run `echo`, with $0=AAA
 *
 * which produced empty output for `echo AAA`, dropped every flag (`uname -m` ran
 * a bare `uname`), swallowed the first line of `echo A; echo B`, made `cwd`
 * ineffective (`bash -lc cd '/etc'` left `&& pwd` in the original directory),
 * turned `for`/`if` into syntax errors, and — worst — started an interactive
 * shell or REPL whenever the first word was `sh`, `bash` or `node`, which then
 * waited on stdin until the deadline. Quoting makes the remote shell hand the
 * whole body to `bash -lc` as one argument.
 *
 * `tty: true` swaps `-T` for `-tt`. `-tt` forces allocation even when the local
 * side has no terminal, which is the only form that lets an interactive tool such
 * as `top` or a password-prompting `sudo` run. It also means the captured output
 * contains the terminal's control sequences, so it stays opt-in.
 *
 * `detached: true` starts the work under `nohup` and returns immediately with the
 * pid, so a long `apt` upgrade cannot be killed by the local deadline. The inner
 * `bash -lc` is deliberate: wrapping an arbitrary command in `nohup <command>`
 * breaks on `;`, `&&` and pipes, which the extra shell level preserves.
 *
 * @param config - resolved plugin configuration.
 * @param entry - the server to run on.
 * @param command - the shell command to interpret remotely.
 * @param cwd - optional remote working directory.
 * @param passwordAuth - whether this invocation supplies a password.
 * @param options - `tty`, `detached` and the detached `logPath`.
 * @returns a complete argv, ready to spawn without a local shell.
 */
export function runArgv(config, entry, command, cwd, passwordAuth, options = {}) {
  // `-T` by default: no pseudo-terminal, so a command that would prompt fails
  // instead of waiting forever on a TTY nobody is reading.
  const argv = [
    config.sshPath,
    options.tty === true ? '-tt' : '-T',
    ...connectionOptions(config, passwordAuth),
    ...entryOptions(entry),
    destination(entry),
  ]
  // A `cd` prefix keeps the working-directory feature out of the SSH protocol,
  // so it behaves identically whether or not the server has an sftp subsystem.
  const hasCwd = cwd !== undefined && cwd.length > 0
  let body
  if (options.detached === true) {
    body = detachedBody(command, options.logPath, hasCwd ? cwd : undefined)
  } else {
    body = hasCwd ? `cd ${shellQuote(cwd)} && ${command}` : command
  }
  argv.push(...REMOTE_SHELL, shellQuote(body))
  return argv
}

/**
 * The remote body that starts a command detached and prints its pid.
 *
 * `{ …; }` keeps the background job and the `echo` in one group. `$!` is the
 * `nohup` process, which `exec`s the inner shell, so the pid stays valid after
 * the ssh session closes. stdin is redirected from `/dev/null` because a
 * background process that reads the closed ssh channel would die on its first
 * read.
 *
 * @param command - the command to run in the background.
 * @param logPath - remote file that receives stdout and stderr.
 * @param cwd - optional remote working directory, applied to the whole group.
 * @returns the remote shell body.
 */
export function detachedBody(command, logPath, cwd) {
  const inner = `nohup bash -lc ${shellQuote(command)} > ${shellQuote(logPath)} 2>&1 </dev/null & echo $!`
  const group = `{ ${inner}; }`
  return cwd === undefined ? group : `cd ${shellQuote(cwd)} && ${group}`
}

/** The regular expression that recognises a pid printed by a detached start. */
export const DETACHED_PID = /^\s*(\d+)\s*$/m

/**
 * Build the argv for `scp`, in either direction.
 *
 * `-O` selects the legacy SCP protocol. The SFTP protocol's Windows support has
 * been uneven, and `-O` is what the Windows client documents as the compatible
 * path; it also keeps a plain file copy free of subsystem negotiation.
 *
 * @param config - resolved plugin configuration.
 * @param entry - the server to copy to or from.
 * @param localPath - the local path.
 * @param remotePath - the remote path.
 * @param direction - `'put'` uploads, `'get'` downloads.
 * @param passwordAuth - whether this invocation supplies a password.
 * @returns a complete argv.
 */
export function copyArgv(config, entry, localPath, remotePath, direction, passwordAuth) {
  const argv = [config.scpPath, ...connectionOptions(config, passwordAuth), '-O']
  // scp uses `-P` for the port (ssh uses `-p`), so it cannot reuse entryOptions.
  if (entry.port !== undefined && entry.port !== 22) argv.push('-P', String(entry.port))
  if (entry.identityFile !== undefined) argv.push('-i', entry.identityFile)
  // A remote path goes to the left of the colon, and `-T` is an ssh-only option
  // that scp rejects, so it is never part of the shared option list.
  const remote = `${destination(entry)}:${remotePath}`
  if (direction === 'put') argv.push(localPath, remote)
  else argv.push(remote, localPath)
  return argv
}

/**
 * Quote one path for a POSIX shell.
 *
 * Only single quotes are special inside single quotes, so wrapping in single
 * quotes and escaping embedded ones is sufficient and cannot be broken out of.
 *
 * @param value - the raw path.
 * @returns a safely quoted shell word.
 */
export function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`
}

// --- destructive command classification ------------------------------------

/** Severity order used to combine verdicts from several commands in one line. */
const TIER_RANK = Object.freeze({ allow: 0, ask: 1, block: 2 })

/**
 * Words that merely wrap another command, so the real program is further right.
 *
 * Without this, `sudo rm -rf /` looked like an unknown program called `sudo` and
 * passed the classifier untouched.
 */
const WRAPPERS = new Set([
  'sudo', 'doas', 'env', 'nohup', 'nice', 'time', 'command', 'exec', 'setsid', 'stdbuf', 'xargs', 'chroot',
])

/** Wrapper options that consume the following word as their value. */
const WRAPPER_VALUE_OPTIONS = Object.freeze({
  sudo: new Set(['-u', '-g', '-U', '-p', '-C', '-h', '-r', '-t', '--user', '--group', '--prompt', '--chdir', '--role', '--type', '--host']),
  doas: new Set(['-u', '-C']),
  env: new Set(['-u', '--unset', '-C', '--chdir', '-S', '--split-string']),
  nice: new Set(['-n', '--adjustment']),
  xargs: new Set(['-I', '-n', '-P', '-L', '-s', '-d', '-E', '-a', '--delimiter', '--max-args', '--max-procs', '--max-lines', '--max-chars', '--arg-file', '--eof']),
  stdbuf: new Set(['-i', '-o', '-e']),
  chroot: new Set(['--userspec', '--groups']),
})

/** Wrappers whose first positional argument is not the command. */
const WRAPPER_POSITIONAL = Object.freeze({ chroot: 1 })

/** Shells that can execute a command given as an argument to `-c`. */
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'fish'])

/** Clients whose argument can contain an irreversible SQL statement. */
const DB_CLIENTS = new Set(['mysql', 'mariadb', 'psql', 'sqlite3', 'clickhouse-client', 'mongosh', 'mongo', 'redis-cli'])

/** Paths whose recursive deletion removes a whole filesystem tree. */
const ROOT_DELETE_TARGETS = new Set([
  '/', '/*', '//', '~', '~/', '~/*', '$HOME', '${HOME}', '$HOME/', '${HOME}/', '$HOME/*', '${HOME}/*',
])

/** A device that writing to destroys the disk. */
const BLOCK_DEVICE = /^\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk)/

/** Command words that are syntax, not programs, and must be stepped over. */
const SKIP_WORDS = new Set(['!', '(', '{', 'if', 'then', 'else', 'elif', 'fi', 'while', 'until', 'do', 'done'])

/**
 * Strip shell noise from one word and return the program name it invokes.
 *
 * @param word - one token of a command line.
 * @returns the lower-case program name without a directory or grouping syntax.
 */
function baseName(word) {
  const stripped = String(word)
    .replace(/^[({!\[]+/, '')
    .replace(/[)}\]]+$/, '')
  return (stripped.split('/').pop() ?? stripped).toLowerCase()
}

/** Whether a word is an environment assignment rather than a program. */
function isAssignment(word) {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(word)
}

/**
 * Split a command line into simple commands, honouring quotes and comments.
 *
 * Quoting is what makes the difference between a dangerous command and a
 * harmless string: `echo "rm -rf /"` prints text, while `sh -c "rm -rf /"` runs
 * it. Both are handled correctly only because the tokenizer knows where a quoted
 * word starts and ends, and because the interpreter body is classified again.
 *
 * @param text - the command line.
 * @returns one token list per simple command, tokens carrying their raw value.
 */
function tokenizeShell(text) {
  const segments = []
  let tokens = []
  let word = ''
  let started = false
  let inSingle = false
  let inDouble = false

  const pushWord = () => {
    if (!started) return
    tokens.push({ value: word })
    word = ''
    started = false
  }
  const pushSegment = () => {
    pushWord()
    if (tokens.length > 0) segments.push(tokens)
    tokens = []
  }

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index]
    if (inSingle) {
      if (char === "'") inSingle = false
      else word += char
      continue
    }
    if (inDouble) {
      if (char === '"') inDouble = false
      else if (char === '\\' && index + 1 < text.length) word += text[(index += 1)]
      else word += char
      continue
    }
    if (char === "'") {
      inSingle = true
      started = true
      continue
    }
    if (char === '"') {
      inDouble = true
      started = true
      continue
    }
    if (char === '\\' && index + 1 < text.length) {
      word += text[(index += 1)]
      started = true
      continue
    }
    // A `#` only starts a comment at the beginning of a word; inside a URL or a
    // word it is an ordinary character.
    if (char === '#' && !started) {
      const newline = text.indexOf('\n', index)
      if (newline < 0) break
      index = newline - 1
      continue
    }
    if (/\s/.test(char)) {
      pushWord()
      continue
    }
    if (char === ';' || char === '\n' || char === '\r') {
      pushSegment()
      continue
    }
    if (char === '&' || char === '|') {
      pushSegment()
      if (text[index + 1] === char) index += 1
      continue
    }
    word += char
    started = true
  }
  pushSegment()
  return segments
}

/**
 * Find the index of the token that names the program.
 *
 * Steps over assignments, grouping syntax and wrappers such as `sudo` or `nohup`,
 * including the options that take a value.
 *
 * @param tokens - one simple command.
 * @returns the index of the program token, or -1 when there is none.
 */
function programIndex(tokens) {
  let index = 0
  while (index < tokens.length) {
    // Assignments and pure syntax can precede the real program.
    while (index < tokens.length && (isAssignment(tokens[index].value) || SKIP_WORDS.has(tokens[index].value))) {
      index += 1
    }
    if (index >= tokens.length) return -1
    const wrapper = baseName(tokens[index].value)
    if (!WRAPPERS.has(wrapper)) return index
    index += 1
    const valueOptions = WRAPPER_VALUE_OPTIONS[wrapper]
    while (index < tokens.length && tokens[index].value.startsWith('-')) {
      index += valueOptions !== undefined && valueOptions.has(tokens[index].value) ? 2 : 1
    }
    const positional = WRAPPER_POSITIONAL[wrapper]
    if (positional !== undefined && index < tokens.length && !tokens[index].value.startsWith('-')) {
      index += positional
    }
  }
  return -1
}

/**
 * Detect an unterminated write straight to a block device, such as `> /dev/sda`.
 *
 * @param tokens - one simple command.
 * @returns the device path, or undefined.
 */
function blockDeviceWrite(tokens) {
  const values = tokens.map((token) => token.value)
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index]
    let target
    if (/^[0-9]?&?>>?$/.test(value)) target = values[index + 1]
    else if (/^[0-9]?&?>>?\/.+/.test(value)) target = value.replace(/^[0-9]?&?>>?/, '')
    if (target !== undefined && BLOCK_DEVICE.test(target)) return target
  }
  return undefined
}

/**
 * Extract the command a shell or `eval` would run from its arguments.
 *
 * @param program - the program name.
 * @param args - its arguments.
 * @returns the nested command, or undefined.
 */
function interpreterBody(program, args) {
  if (SHELLS.has(program)) {
    const index = args.findIndex((arg) => /^-[a-zA-Z]*c$/.test(arg))
    return index < 0 ? undefined : args.slice(index + 1).join(' ')
  }
  if (program === 'eval') return args.join(' ')
  return undefined
}

/**
 * Classify a recursive `rm`.
 *
 * A relative target such as `./build` is routine build cleanup and stays silent;
 * an absolute path, a parent directory or a wildcard is irreversible enough to
 * ask; the filesystem root and the whole home directory are refused.
 *
 * @param args - the arguments after `rm`.
 * @returns a verdict.
 */
function classifyRm(args) {
  const recursive = args.some((arg) => arg === '--recursive' || /^-[a-zA-Z]*[rR][a-zA-Z]*$/.test(arg))
  if (!recursive) return { tier: 'allow', reason: 'delete without recursion' }
  const targets = args.filter((arg) => !arg.startsWith('-'))
  if (targets.length === 0) return { tier: 'allow', reason: 'recursive delete without a target' }
  for (const target of targets) {
    if (ROOT_DELETE_TARGETS.has(target)) {
      return { tier: 'block', reason: `recursive delete of ${target} removes a whole filesystem tree` }
    }
  }
  const risky = targets.find(
    (target) => target.startsWith('/') || target === '.' || target === '..' || target.startsWith('../') || /[*?]/.test(target),
  )
  if (risky !== undefined) return { tier: 'ask', reason: `recursive delete of ${risky} cannot be undone` }
  return { tier: 'allow', reason: 'recursive delete of a project-relative path' }
}

/**
 * Classify the arguments of one simple command.
 *
 * @param tokens - one simple command.
 * @param depth - nesting depth, so an interpreter chain cannot recurse forever.
 * @returns a verdict.
 */
function classifySegment(tokens, depth) {
  const index = programIndex(tokens)
  if (index < 0) return { tier: 'allow', reason: 'no program' }
  const program = baseName(tokens[index].value)
  const args = tokens.slice(index + 1).map((token) => token.value)

  // A quoted body is executed by these, so it is classified as a command rather
  // than as text. `sh -c "rm -rf /"` must not pass because the payload is quoted.
  const nested = interpreterBody(program, args)
  if (nested !== undefined) {
    if (depth >= 3) return { tier: 'ask', reason: 'deeply nested shell command' }
    const verdict = classify(nested, depth + 1)
    return verdict.tier === 'allow' ? { tier: 'allow', reason: 'nested command is safe' } : verdict
  }

  const device = blockDeviceWrite(tokens)
  if (device !== undefined) return { tier: 'block', reason: `raw write to block device ${device} destroys the disk` }

  if (program === 'rm') return classifyRm(args)
  if (/^mkfs(\..+)?$/.test(program) || program === 'mke2fs') {
    return { tier: 'block', reason: `${program} formats a device and destroys everything on it` }
  }
  if (program === 'dd') {
    const target = args.find((arg) => /^of=\/dev\//.test(arg))
    if (target !== undefined) return { tier: 'block', reason: `dd writes directly to ${target.slice(3)}` }
  }
  if (program === 'shutdown' || program === 'reboot' || program === 'halt' || program === 'poweroff') {
    return { tier: 'block', reason: `${program} takes the server down` }
  }
  if (program === 'chmod') {
    const recursive = args.some((arg) => arg === '--recursive' || /^-[a-zA-Z]*[rR]/.test(arg))
    const open = args.some((arg) => arg === '777' || arg === '7777' || arg === '0777' || arg === '666' || arg === '0666')
    const root = args.some((arg) => arg === '/' || arg === '/*')
    if (recursive && open && root) {
      return { tier: 'block', reason: 'chmod -R 777 / makes every file on the server writable by anyone' }
    }
  }
  if (program === 'docker') {
    const positionals = args.filter((arg) => !arg.startsWith('-')).join(' ')
    if (/^system\s+prune\b/.test(positionals)) {
      return { tier: 'ask', reason: 'docker system prune deletes stopped containers, unused images and networks' }
    }
    if (/^volume\s+(rm|prune)\b/.test(positionals)) {
      return { tier: 'ask', reason: 'removing a docker volume destroys the data it holds' }
    }
  }
  if (program === 'apt' || program === 'apt-get' || program === 'aptitude') {
    if (args.includes('purge')) return { tier: 'ask', reason: 'apt purge deletes packages together with their configuration' }
  }
  if (program === 'kill' || program === 'killall' || program === 'pkill') {
    const signal9 =
      args.some((arg) => arg === '-9' || arg === '-KILL' || arg === '--signal=KILL' || arg === '-s9') ||
      args.some((arg, position) => arg === '-s' && (args[position + 1] === '9' || args[position + 1] === 'KILL'))
    if (signal9 && args.includes('1')) return { tier: 'ask', reason: 'kill -9 1 kills init and stops the server' }
  }
  if (DB_CLIENTS.has(program)) {
    const sql = args.join(' ')
    if (/\bDROP\s+DATABASE\b/i.test(sql) || /\bTRUNCATE\s+(?:TABLE\s+)?\w/i.test(sql)) {
      return { tier: 'ask', reason: 'irreversible SQL (DROP DATABASE / TRUNCATE)' }
    }
  }
  return { tier: 'allow', reason: 'no destructive pattern matched' }
}

/**
 * Classify a whole command line without evaluating it.
 *
 * @param command - the command as the model wrote it.
 * @param depth - internal nesting depth.
 * @returns the most severe verdict: `block`, `ask` or `allow`, with a reason.
 */
function classify(command, depth) {
  const text = String(command ?? '')
  if (text.trim().length === 0) return { tier: 'allow', reason: 'empty command' }
  const verdicts = []
  // A fork bomb is a syntax rather than a program, so it is seen in the raw text.
  if (/:\s*\(\s*\)\s*\{/.test(text)) verdicts.push({ tier: 'block', reason: 'fork bomb exhausts the server' })
  for (const tokens of tokenizeShell(text)) verdicts.push(classifySegment(tokens, depth))
  const dangerous = verdicts.filter((verdict) => verdict.tier !== 'allow')
  if (dangerous.length === 0) return { tier: 'allow', reason: 'no destructive pattern matched' }
  dangerous.sort((left, right) => TIER_RANK[right.tier] - TIER_RANK[left.tier])
  return dangerous[0]
}

/**
 * Decide how dangerous a remote command is.
 *
 * This is a speed bump, not a boundary. It reads the command text without
 * running a shell, so anything a shell would compute — command substitution,
 * variable expansion, a script file that is uploaded and then executed — is
 * invisible to it. The real boundary is a separate unprivileged user on the
 * server, which is an operations decision rather than code.
 *
 * @param command - the command the model wants to run.
 * @returns `{ tier, reason }`, where tier is `'block' | 'ask' | 'allow'`.
 */
export function classifyCommand(command) {
  return classify(command, 0)
}

// --- secret redaction ------------------------------------------------------

/**
 * Patterns whose match is certainly a secret.
 *
 * Deliberately narrow: a broad rule such as "anything after `token`" would cut
 * ordinary output. Each replacement keeps enough context (the label, the header)
 * that the report still makes sense to the model.
 */
const REDACTIONS = Object.freeze([
  {
    pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
    replace: () => '«redacted:private-key»',
  },
  {
    // The label rule runs before the value rules: `token: sk-…` is one secret,
    // and letting both patterns match it would report two values removed and
    // leave «redacted:api-key» as the visible value of `token`.
    //
    // The lookbehind is what lets `DB_PASSWORD=…` match while a word that merely
    // ends in "password" (`mypassword`) does not.
    pattern: /(?<![A-Za-z0-9])(password|passwd|pwd|secret|token|api[_-]?key)(\s*[=:]\s*)(?:"[^"\n]*"|'[^'\n]*'|\S+)/gi,
    replace: (_match, label, separator) => `${label}${separator}«redacted:credential»`,
  },
  { pattern: /\bAKIA[0-9A-Z]{16}\b/g, replace: () => '«redacted:aws-key»' },
  { pattern: /\bsk-[A-Za-z0-9]{20,}\b/g, replace: () => '«redacted:api-key»' },
  {
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    replace: () => '«redacted:jwt»',
  },
  {
    pattern: /\bAuthorization:\s*Bearer\s+[^\s"',;]+/gi,
    replace: () => 'Authorization: Bearer «redacted:bearer»',
  },
  {
    pattern: /\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s@]+@/gi,
    replace: (match) => match.replace(/\/\/[^@]*@$/, '//«redacted:url-credentials»@'),
  },
])

/**
 * Remove high-confidence secrets from captured output.
 *
 * The output of `cat ~/.ssh/id_rsa`, `env`, `docker inspect` or `wp-config.php`
 * travels to a model provider as part of the conversation, so a secret printed
 * by a remote command must not be forwarded verbatim.
 *
 * @param text - the captured text.
 * @returns the redacted text and how many values were replaced.
 */
export function redact(text) {
  let value = String(text ?? '')
  let count = 0
  for (const rule of REDACTIONS) {
    value = value.replace(rule.pattern, (match, ...rest) => {
      count += 1
      return rule.replace(match, ...rest)
    })
  }
  return { text: value, count }
}

/**
 * Render an argv as one line a human can read and paste.
 *
 * Used only for diagnostics: a failure that says "exited with code 1" and nothing
 * else cannot be reproduced or explained. Elements containing spaces or quotes
 * are shown JSON-quoted so the boundaries stay visible; no secret ever appears in
 * argv (a password travels through SSH_ASKPASS), so this is safe to surface.
 *
 * @param argv - the spawned argument list.
 * @returns a single-line rendering of the command.
 */
export function formatArgv(argv) {
  const parts = (argv ?? []).map((part) => {
    const value = String(part)
    return /[\s"'\\]/.test(value) ? JSON.stringify(value) : value
  })
  const line = parts.join(' ')
  // A remote body can be long; the point is recognition, not completeness.
  return line.length <= 2_000 ? line : `${line.slice(0, 2_000)}…`
}

/**
 * Validation failures the tools report verbatim. Every message is actionable:
 * it names what was wrong and what to do instead.
 */
export class SshRemoteError extends Error {
  /**
   * @param message - user-facing explanation.
   * @param code - stable machine-readable reason.
   */
  constructor(message, code) {
    super(message)
    this.name = 'SshRemoteError'
    this.code = code
  }
}

/** A snapshot of what one remote invocation produced. */
export const EXIT_PREFIX = 'exit='

/**
 * Classify an SSH failure from its exit code and stderr.
 *
 * The order matters: a changed host key also exits 255, so it must be detected
 * before the generic connection-failure branch, or the most important warning
 * would be reported as a plain network error.
 *
 * @param exitCode - the local ssh/scp exit code.
 * @param stderr - captured stderr text.
 * @param passwordAuth - whether a password was supplied for this invocation.
 * @returns a description of the failure, or undefined when nothing failed.
 */
export function classifyFailure(exitCode, stderr, passwordAuth) {
  if (exitCode === 0) return undefined
  const text = String(stderr ?? '')
  if (/REMOTE HOST IDENTIFICATION HAS CHANGED|Host key verification failed/i.test(text)) {
    return {
      code: 'HOST_KEY_CHANGED',
      message:
        'The server presented a different host key than the one recorded in known_hosts. ' +
        'This is either a reinstall or an interception, so the plugin refuses to continue. ' +
        `Verify the fingerprint out-of-band, then update known_hosts yourself (ssh-keygen -R <address>).\n\n${text}`,
    }
  }
  if (/Permission denied/i.test(text)) {
    // The advice depends on what was attempted: telling a password user to
    // install a key would hide the actual cause (a wrong or changed password).
    const message =
      passwordAuth === true
        ? 'The server rejected the password. Re-run /ssh pass to store the current one. ' +
          'If the password is definitely right, the account may be locked or permit no password login.'
        : 'The server rejected key authentication. Install your public key on the server, ' +
          'or point the entry at the right key with identityFile. If this server has no key yet, ' +
          'store a password with /ssh pass to connect without one.'
    return { code: 'AUTH_FAILED', message: `${message}\n\n${text}` }
  }
  if (/Could not resolve hostname|Name or service not known/i.test(text)) {
    return { code: 'HOST_UNRESOLVED', message: `The server address could not be resolved.\n\n${text}` }
  }
  if (/Connection timed out|Connection refused|No route to host|Operation timed out/i.test(text)) {
    return { code: 'UNREACHABLE', message: `The server could not be reached.\n\n${text}` }
  }
  if (exitCode === 255) {
    return { code: 'CONNECTION_FAILED', message: `The SSH client failed before the command ran.\n\n${text}` }
  }
  // Any other non-zero code came from the remote command itself, which is a
  // normal result rather than a connection problem. The remote's own stderr is
  // the only thing that explains WHICH command failed and why, so it travels
  // with the message: without it a put/get failure was a bare "exited with code
  // 1" with no path, no command and no cause.
  return {
    code: 'REMOTE_EXIT',
    message: `The remote command exited with code ${exitCode}.${text.trim().length === 0 ? '' : `\n\n${text.trimEnd()}`}`,
  }
}

/**
 * Truncate captured output to a budget, keeping both ends.
 *
 * Keeping only the head hid the interesting part of every long log: a build's
 * failing step and an apt error are at the END. Six tenths of the budget stay at
 * the head, four tenths at the tail, and the marker says exactly how much sat
 * between them.
 *
 * The marker is not counted against the budget, so the result can be a few dozen
 * characters longer than `maxChars`; that is deliberate, because a marker that
 * ate into the visible text would be worse than a slight overshoot.
 *
 * @param text - the full captured text.
 * @param maxChars - the configured ceiling.
 * @returns the visible text and an optional truncation note.
 */
export function truncate(text, maxChars) {
  const value = String(text ?? '')
  const budget = Math.max(1, Math.floor(maxChars))
  if (value.length <= budget) return { text: value, truncated: false }
  const headChars = Math.floor(budget * 0.6)
  const tailChars = budget - headChars
  const head = value.slice(0, headChars)
  const tail = value.slice(value.length - tailChars)
  const omitted = value.length - headChars - tailChars
  return {
    text: `${head}\n… пропущено ${omitted} символов (из ${value.length}) …\n${tail}`,
    truncated: true,
    note:
      `… output truncated: ${omitted} of ${value.length} characters omitted; ` +
      `the first ${headChars} and the last ${tailChars} are shown. Re-run with a narrower command to see the rest.`,
  }
}

/**
 * Russian plural for a count of secrets in the report.
 *
 * @param count - how many values were redacted.
 * @returns the phrase that follows "вырезано".
 */
function secretsPhrase(count) {
  const mod10 = count % 10
  const mod100 = count % 100
  if (mod10 === 1 && mod100 !== 11) return `${count} секрет`
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return `${count} секрета`
  return `${count} секретов`
}

/**
 * Render one command result as the text the model receives.
 *
 * Output is redacted BEFORE truncation: cutting first could leave the first lines
 * of a private key visible with only the footer removed.
 *
 * @param result - exit code and captured streams.
 * @param maxChars - the per-stream character ceiling.
 * @returns the formatted report.
 */
export function formatRunResult(result, maxChars) {
  const stdoutSecrets = redact(result.stdout)
  const stderrSecrets = redact(result.stderr)
  const stdout = truncate(stdoutSecrets.text, maxChars)
  const stderr = truncate(stderrSecrets.text, maxChars)
  const lines = [`${EXIT_PREFIX}${result.exitCode ?? 'signal'}${result.signal === undefined ? '' : ` (signal ${result.signal})`}`]
  lines.push('--- stdout ---', stdout.text.length === 0 ? '(empty)' : stdout.text)
  if (stdout.truncated) lines.push(stdout.note.trimStart())
  lines.push('--- stderr ---', stderr.text.length === 0 ? '(empty)' : stderr.text)
  if (stderr.truncated) lines.push(stderr.note.trimStart())
  const secrets = stdoutSecrets.count + stderrSecrets.count
  if (secrets > 0) {
    lines.push(`… вырезано ${secretsPhrase(secrets)}: значения заменены на «redacted:…» и не отправлены модели.`)
  }
  return lines.join('\n')
}
