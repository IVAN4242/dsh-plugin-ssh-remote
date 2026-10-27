/**
 * SSH Remote — Host half.
 *
 * Lets the agent reach any number of VPS servers over SSH: a durable server
 * registry, a `/ssh` selection flow, command and transfer tools, and four
 * read-only navigation tools (`ssh_read`, `ssh_ls`, `ssh_grep`, `ssh_glob`).
 *
 * Three safety layers sit on top of that access:
 *  - a command classifier refuses catastrophic commands and asks about the
 *    irreversible-but-legitimate ones (see `args.js`);
 *  - captured output is redacted before it is formatted for the model;
 *  - every client invocation is written to an action log, with the command
 *    already redacted.
 *
 * Two constraints shape the whole design:
 *
 *  1. DSH ships `@deepseek-ai/dsh-ssh`, but that stack requires a POSIX *local*
 *     endpoint: it drives OpenSSH connection multiplexing and forwards Unix
 *     sockets. The Windows OpenSSH build cannot do either, so this plugin
 *     invokes `ssh.exe` / `scp.exe` directly instead.
 *
 *  2. Because it spawns those binaries itself, the local DSH file sandbox does
 *     not constrain what runs. Remote commands execute with the authority of the
 *     user's SSH key regardless of the local sandbox mode. The registry is
 *     therefore the allowlist: only named servers are reachable, and a new entry
 *     needs human confirmation.
 *
 * Authentication is by key where one is configured, and by a stored password
 * otherwise. A password is never passed on a command line: it is delivered
 * through a generated `SSH_ASKPASS` helper, so it stays out of the process list.
 * Keys are strongly preferred — see README for what the store does and does not
 * protect against.
 *
 * @module dsh-plugin-ssh-remote
 */
import { readFileSync } from 'node:fs'
import { resolve as resolvePath } from 'node:path'
import z from '@deepseek-ai/schemastery'
import {
  BATCH_MODE,
  DETACHED_PID,
  STRICT_HOST_KEY,
  SshRemoteError,
  classifyCommand,
  classifyFailure,
  copyArgv,
  formatArgv,
  formatRunResult,
  runArgv,
  shellQuote,
  truncate,
} from './args.js'
import { appendAudit, buildAuditRecord, defaultAuditPath } from './audit.js'
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

/** Plugin display name; also the row id used by the bundle patch. */
export const name = 'ssh-remote'

/**
 * Declared service dependencies.
 *
 * `subprocess` MUST be listed here and not merely fetched with `ctx.get` inside
 * `apply`. Cordis invokes `apply` once the declared dependencies are ready, but
 * at application start the rows activate in an order where the process provider
 * may not exist yet. Without this declaration `apply` ran early, `ctx.get`
 * returned undefined, and the whole plugin failed activation — which removed
 * `/ssh` too, because the command lives in this same plugin. Toggling the bundle
 * live appeared to work only because every service was already running by then.
 *
 * Declaring the dependency makes Cordis wait instead of failing.
 */
export const inject = ['tools', 'subprocess']

/** Plugin configuration, declared so `cordis.patch.yml` values are validated. */
export const Config = z.object({
  /** Registry location. Defaults to `$DSH_HOME/ssh-remote-hosts.json`. */
  registryPath: z.string(),
  /** Password store location. Defaults to `$DSH_HOME/ssh-remote-secrets.json`. */
  secretsPath: z.string(),
  /** Scratch directory for the transient password helper. Defaults under `$DSH_HOME`. */
  askpassDir: z.string(),
  /** Action log. Defaults to `$DSH_HOME/ssh-remote-audit.jsonl`. */
  auditLogPath: z.string(),
  /** OpenSSH client configuration, used as the source for `/ssh sync`. */
  sshConfigPath: z.string(),
  /** Allow connecting to an address that is not a registered server name. */
  allowRawHosts: z.boolean().default(false),
  /** Explicit client paths; otherwise the platform defaults are used. */
  sshPath: z.string(),
  scpPath: z.string(),
  connectTimeoutMs: z.number().min(1).default(10_000),
  serverAliveIntervalSec: z.number().min(0).default(15),
  serverAliveCountMax: z.number().min(1).default(3),
  defaultTimeoutMs: z.number().min(1).default(120_000),
  maxTimeoutMs: z.number().min(1).default(1_800_000),
  maxOutputChars: z.number().min(1).default(60_000),
  /**
   * How a risky-but-legitimate command is treated.
   *
   * `standard` asks for confirmation; `off` runs it without asking. Neither value
   * allows a catastrophic command: the block tier is unconditional.
   */
  commandPolicy: z.union([z.const('standard'), z.const('off')]).default('standard'),
  /** Enable OpenSSH connection sharing; requires a POSIX local endpoint. */
  multiplex: z.boolean().default(false),
  /** Control socket path; only meaningful when `multiplex` is true. */
  controlPath: z.string(),
})

/**
 * The platform's OpenSSH client.
 *
 * Windows ships `ssh.exe` outside the ordinary PATH in some installations, so
 * the System32 location is used explicitly rather than trusting PATH order.
 *
 * @param program - the executable base name.
 * @returns an absolute path on Windows, or the bare name elsewhere.
 */
function defaultClient(program) {
  if (process.platform !== 'win32') return program
  const root = process.env.SystemRoot ?? process.env.windir ?? 'C:\\Windows'
  return `${root}\\System32\\OpenSSH\\${program}.exe`
}

/** The current user's OpenSSH client configuration. */
function defaultSshConfigPath() {
  const home = process.env.USERPROFILE ?? process.env.HOME ?? '.'
  return resolvePath(home, '.ssh', 'config')
}

/**
 * Bash tail for a `producer | head` pipeline.
 *
 * `head` closes the pipe early, so the producer commonly dies of SIGPIPE (141).
 * Without pipefail the pipeline would report `head`'s success and hide a real
 * failure such as `ls` on a missing directory; with pipefail alone the harmless
 * SIGPIPE would be reported as an error. Both cases are named explicitly.
 */
export const PIPE_STATUS =
  'st=${PIPESTATUS[0]}; if [ "$st" -ne 0 ] && [ "$st" -ne 141 ]; then exit "$st"; fi'

/**
 * The same tail for `grep`, whose exit status 1 means "no matches", not a fault.
 *
 * The "no matches" line goes to stdout so the tool's own report shows it; grep's
 * real errors (a bad pattern exits 2) still surface as a failed command.
 */
export const GREP_STATUS =
  'st=${PIPESTATUS[0]}; if [ "$st" -eq 1 ]; then printf "no matches\\n"; exit 0; fi; ' +
  'if [ "$st" -ne 0 ] && [ "$st" -ne 141 ]; then exit "$st"; fi'

/**
 * The local directory a spawned process should start in.
 *
 * `spawn` requires a real directory, and the session's workspace is the natural
 * choice: it is also what a relative local file path in `ssh_put` resolves
 * against.
 *
 * @param exec - the tool execution.
 * @returns an absolute local directory.
 */
function localCwd(exec) {
  return exec.agent?.session?.header?.cwd ?? process.cwd()
}

/**
 * Turn a classified connection failure into one short, actionable Russian line.
 *
 * The point is to name the state and the cure, not to relay OpenSSH's English
 * diagnostic: a server that simply has no key yet is a normal setup step, and
 * presenting it as a wall of stderr makes a routine action look like a fault.
 *
 * @param entry - the server that refused.
 * @param failure - the classified failure.
 * @param usedPassword - whether a password was already supplied.
 * @returns the message to show.
 */
export function refusalText(entry, failure, usedPassword) {
  const name = entry.name
  if (failure.code === 'AUTH_FAILED') {
    if (usedPassword) {
      return (
        `Сервер ${name}: пароль не принят.\n` +
        `Проверьте пароль и сохраните его заново:  /ssh pass ${name} <пароль>`
      )
    }
    return (
      `Сервер ${name}: нужен вход по паролю — ключ на сервере не установлен.\n` +
      `Сохраните пароль:  /ssh pass ${name} <пароль>\n` +
      `Пароль вводится в этой строке (не в диалоге), поэтому в переписку он не попадает.`
    )
  }
  if (failure.code === 'HOST_KEY_CHANGED') {
    return (
      `Сервер ${name}: ключ хоста изменился, соединение отклонено.\n` +
      `Проверьте отпечаток вне SSH и обновите запись:\n` +
      `  ssh-keygen -R ${entry.host}\n` +
      `Плагин новый ключ сам не принимает — это защита от подмены сервера.`
    )
  }
  if (failure.code === 'HOST_UNRESOLVED') return `Сервер ${name}: адрес ${entry.host} не разрешается.`
  if (failure.code === 'UNREACHABLE') return `Сервер ${name}: сервер недоступен (${entry.host}).`
  return `Сервер ${name}: подключиться не удалось.`
}

/**
 * Turn a registry-write failure into an actionable message.
 *
 * A denied write is an ordinary condition — a read-only file, a permissions
 * problem, or a path owned by another user — so it deserves an explanation
 * rather than a raw errno, which reads like an internal crash.
 *
 * @param error - the thrown write failure.
 * @returns a message naming the file and the likely cause.
 */
export function describeWriteFailure(error) {
  const code = String(error?.code ?? '')
  const detail = String(error?.message ?? error)
  if (code === 'EPERM' || code === 'EACCES') {
    return (
      `Не удалось записать реестр: доступ запрещён.\n${detail}\n\n` +
      'Проверьте права на файл реестра и каталог: возможно, файл создан другим пользователем или защищён от записи.'
    )
  }
  if (code === 'EBUSY' || code === 'ENOTEMPTY') {
    return `Не удалось записать реестр: файл занят другой программой.\n${detail}`
  }
  return `Не удалось записать реестр: ${detail}`
}

/**
 * The refusal text for a command in the catastrophic tier.
 *
 * The guard and the execution path share it so they cannot drift: the guard is a
 * fast, synchronous refusal, while execution re-checks to stay authoritative.
 *
 * @param command - the refused command.
 * @param reason - why the classifier refused it.
 * @returns a message that names the command, the reason and the rule.
 */
export function blockedCommandText(command, reason) {
  return (
    `Refused by the SSH command guard: ${reason}.\n` +
    `Command: ${command}\n` +
    'This is the catastrophic tier and is never run through ssh_run, even with commandPolicy: off. ' +
    'If the operation is really needed, do it yourself on the server.'
  )
}

/** Long-wait commands need a pid and a log path, not just the shell's echo. */
function detachedReport(entry, command, report, logPath) {
  const match = DETACHED_PID.exec(report)
  const pid = match === null ? undefined : match[1]
  const lines = [
    pid === undefined
      ? `Started detached on "${entry.name}", but no pid could be read from the output.`
      : `Started detached on "${entry.name}": pid ${pid}.`,
    `Log: ${logPath}`,
  ]
  if (pid !== undefined) {
    lines.push(
      `Check progress with ssh_run: tail -n 50 ${shellQuote(logPath)}`,
      `Stop it with ssh_run: kill ${pid}`,
    )
  }
  lines.push('', report)
  return lines.join('\n')
}

/**
 * A short random suffix for the default detached log file.
 *
 * @returns a token safe to embed in a remote path.
 */
function detachedLogId() {
  return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`
}

/**
 * Build the draft 2020-12 object schema a Tool's `parameters` must carry.
 *
 * `parameters` is the model-facing JSON Schema itself, not a bare property map,
 * and DSH hands it to the provider verbatim. Passing a map of properties
 * produced `{"probe": {...}}`, which lenient OpenAI-compatible endpoints
 * ignore — the tools still worked, with their arguments unconstrained — while
 * every Anthropic front (OpenRouter, Bedrock, Azure, Vertex) refused the whole
 * request with `tools.25.custom.input_schema: JSON schema is invalid`.
 *
 * The `required: true` marker on a property is this module's own shorthand. It
 * is lifted into the schema's `required` array and dropped from the property,
 * because JSON Schema requires an array of names there: a boolean is a schema
 * error, not an ignored hint.
 *
 * @param properties - the tool's argument map, in declaration order.
 * @returns a complete object schema suitable for `parameters`.
 */
export function objectSchema(properties) {
  const required = []
  const fields = {}
  for (const [key, value] of Object.entries(properties ?? {})) {
    const { required: isRequired, ...field } = value
    if (isRequired === true) required.push(key)
    fields[key] = field
  }
  return {
    type: 'object',
    properties: fields,
    ...(required.length === 0 ? {} : { required }),
  }
}

/**
 * Mount the Host half.
 *
 * @param ctx - the plugin's Cordis context.
 * @param config - validated plugin configuration.
 */
export function apply(ctx, config) {
  // Guaranteed by the declared `inject`, which is what stops startup from
  // running this before the provider exists. `ctx.get` is kept as a defensive
  // read so a future inject change cannot reintroduce a silent failure.
  const subprocess = ctx.get('subprocess')
  if (subprocess === undefined) {
    throw new Error(
      'ssh-remote: the subprocess service is required; add a subprocess provider such as @deepseek-ai/dsh-subprocess-local to the profile',
    )
  }

  const home = resolveHome(undefined)
  const registryPath = config.registryPath ?? defaultRegistryPath(home)
  const sshConfigPath = config.sshConfigPath ?? defaultSshConfigPath()
  const resolved = {
    registryPath,
    sshPath: config.sshPath ?? defaultClient('ssh'),
    scpPath: config.scpPath ?? defaultClient('scp'),
    connectTimeoutMs: config.connectTimeoutMs ?? 10_000,
    serverAliveIntervalSec: config.serverAliveIntervalSec ?? 15,
    serverAliveCountMax: config.serverAliveCountMax ?? 3,
    defaultTimeoutMs: config.defaultTimeoutMs ?? 120_000,
    maxTimeoutMs: config.maxTimeoutMs ?? 1_800_000,
    maxOutputChars: config.maxOutputChars ?? 60_000,
    commandPolicy: config.commandPolicy === 'off' ? 'off' : 'standard',
    multiplex: config.multiplex === true,
    controlPath: config.controlPath ?? resolvePath(home, 'ssh-remote-%C.sock'),
    secretsPath: config.secretsPath ?? defaultSecretsPath(home),
    askpassDir: config.askpassDir ?? resolvePath(home, 'ssh-remote-askpass'),
    auditLogPath: config.auditLogPath ?? defaultAuditPath(home),
  }

  /** The Windows ACL pass receives the logger so a refused `icacls` is visible. */
  const aclOptions = { logger: ctx.logger }
  if (resolved.commandPolicy === 'off') {
    // Off is a deliberate choice, but it is worth one line in the log: a later
    // reader must be able to tell why no confirmation was asked.
    ctx.logger.warn(
      'ssh-remote: commandPolicy=off — risky commands run without confirmation. ' +
        'Catastrophic commands (rm -rf /, mkfs, dd to a device) are still refused.',
    )
  }

  /** In-memory snapshot. Refreshed from disk before every operation. */
  let hosts = []
  /** Default server name, used when a tool omits `host`. */
  let preferred
  /**
   * Non-fatal registry repairs from the last read, shown by `/ssh`.
   *
   * Kept separate from a fatal `problem` on purpose: a repaired row must not stop
   * the plugin from listing and using the servers that are fine.
   */
  let lastWarnings = []
  /** Serializes writes so two operations cannot interleave a read-modify-write. */
  let writeChain = Promise.resolve()

  /**
   * Re-read the registry from disk.
   *
   * Reading before each operation is deliberate: it keeps an external edit (or a
   * concurrent session) from being clobbered by a stale in-memory list, and the
   * file is small enough that the cost is irrelevant.
   *
   * Only a whole-file failure is raised. A repaired or skipped row is a warning:
   * the remaining servers are perfectly usable, and refusing every operation over
   * one bad entry would take the whole feature down for a cosmetic problem.
   *
   * @param surface - whether a fatal read problem should be raised to the caller.
   * @returns the current entries.
   */
  const loadHosts = (surface) => {
    const document = readRegistry(resolved.registryPath)
    hosts = document.hosts
    preferred = document.default
    // Warnings are cumulative for this read, so `/ssh` can surface them without
    // failing; each one is also logged.
    lastWarnings = document.warnings ?? []
    for (const warning of lastWarnings) ctx.logger.warn('ssh-remote: %s', warning)
    if (document.problem !== undefined) {
      ctx.logger.warn('ssh-remote: %s', document.problem)
      if (surface === true) throw new SshRemoteError(document.problem, 'REGISTRY_UNREADABLE')
    }
    return hosts
  }

  /** Persist the current list atomically. */
  const saveHosts = (next, nextDefault) => {
    hosts = next
    if (nextDefault !== undefined) preferred = nextDefault
    writeChain = writeChain.then(() =>
      writeRegistry(resolved.registryPath, next, preferred).catch((error) => {
        ctx.logger.warn('ssh-remote: could not persist the registry: %s', String(error?.message ?? error))
        throw error
      }),
    )
    return writeChain
  }

  /**
   * Resolve a requested server to a registry entry.
   *
   * The registry is the allowlist. `allowRawHosts` exists for deliberate
   * one-off use, and even then an unknown name never silently becomes a
   * connection: the caller must have opted in.
   *
   * A locked entry is resolved but then refused: locking must stop the operation
   * itself, not merely hide the server from a default-server lookup, or an
   * explicit `host` argument would walk straight past it.
   *
   * @param requested - the name supplied by the caller.
   * @returns the entry to connect with.
   */
  const resolveEntry = (requested) => {
    const name = typeof requested === 'string' ? requested.trim() : ''
    let entry
    if (name.length === 0) {
      const fallback = preferred === undefined ? undefined : findEntry(hosts, preferred)
      if (fallback === undefined) {
        const known = hosts.map((candidate) => candidate.name).join(', ')
        // A configured-but-stale default is a different problem from no default,
        // and saying "no default is set" while a name sits in the file is simply
        // untrue. Name the real condition so the fix is obvious.
        const detail =
          preferred === undefined
            ? 'No server was named and no default is set.'
            : `No server was named, and the configured default "${preferred}" is no longer registered.`
        throw new SshRemoteError(
          `${detail} Registered servers: ${known.length > 0 ? known : 'none'}. ` +
            (known.length > 0 ? 'Set one with /ssh default <name>.' : 'Add one with /ssh add.'),
          'HOST_REQUIRED',
        )
      }
      entry = fallback
    } else {
      entry = findEntry(hosts, name)
      if (entry === undefined) {
        if (config.allowRawHosts === true) return normalizeEntry({ name, host: name })
        const known = hosts.map((candidate) => candidate.name).join(', ')
        throw new SshRemoteError(
          `Unknown server "${name}". Registered servers: ${known.length > 0 ? known : 'none'}. ` +
            'Use ssh_host_add, or /ssh sync to import servers from the SSH config.',
          'HOST_UNKNOWN',
        )
      }
    }
    if (entry.locked === true) {
      throw new SshRemoteError(
        `Server "${entry.name}" is locked, so no command or transfer will run on it.\n` +
          `Unlock it with:  /ssh unlock ${entry.name}`,
        'HOST_LOCKED',
      )
    }
    return entry
  }

  /**
   * Resolve the authentication to use for one server.
   *
   * A stored password is used only when the entry itself does not name a key. A
   * key is strictly better — it cannot be guessed, replayed from a transcript, or
   * reused elsewhere — so an entry with `identityFile` never silently falls back
   * to a password that happens to be stored for the same name.
   *
   * @param entry - the server to connect to.
   * @returns the password to supply, or undefined for key or agent auth.
   */
  const passwordFor = (entry) => {
    if (entry.identityFile !== undefined) return undefined
    const document = readSecrets(resolved.secretsPath)
    if (document.problem !== undefined) {
      ctx.logger.warn('ssh-remote: %s', document.problem)
      return undefined
    }
    return document.passwords[entry.name]
  }

  /**
   * Run one client process and collect its outcome.
   *
   * @param argv - the complete command line.
   * @param options - stdin, working directory, deadline, cancellation, the
   *   password to deliver when one is required, and the audit facts.
   * @returns exit facts and captured streams.
   */
  const runProcess = async (argv, options) => {
    const startedAt = Date.now()
    const maxBytes = Math.max(resolved.maxOutputChars * 4, 65_536)
    const stdin = options.stdin === undefined ? 'ignore' : { data: options.stdin }

    // A password never becomes an argument or an SSH option: it is delivered
    // through a helper program that OpenSSH executes, so it stays out of the
    // process list that any local user can read.
    let askpass
    if (options.password !== undefined) {
      askpass = await createAskpass(resolved.askpassDir, options.password, { acl: aclOptions })
    }
    try {
      const handle = subprocess.spawn({
        argv,
        cwd: options.cwd,
        stdio: { stdin, stdout: { maxBytes }, stderr: { maxBytes } },
        graceMs: 5_000,
        ...(askpass === undefined ? {} : { env: { ...process.env, ...askpass.env } }),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      })

      let timedOut = false
      const timer = setTimeout(() => {
        timedOut = true
        // Terminate the managed range; `done` still resolves with the exit facts,
        // so the caller learns both that it timed out and how it ended.
        handle.terminate()
      }, options.timeoutMs)

      let outcome
      try {
        outcome = await handle.done
      } finally {
        clearTimeout(timer)
      }

      /** Read one collected stream from its start. */
      const read = (stream) => {
        const reader = handle.collected?.[stream]
        return reader === undefined ? { text: '', lossy: false } : reader.readFrom(0)
      }
      const stdout = read('stdout')
      const stderr = read('stderr')
      const result = {
        exitCode: outcome?.exitCode ?? null,
        signal: outcome?.signal ?? undefined,
        timedOut,
        stdout: stdout.text,
        stderr: stderr.text,
        spillPath: stdout.spillPath ?? stderr.spillPath,
        passwordAuth: options.password !== undefined,
      }
      // The action log is written after the outcome is known and before the
      // result is returned, so one call is exactly one line. A failure to write
      // is reported and swallowed: an audit problem must not fail a command.
      if (options.audit !== undefined) {
        const record = buildAuditRecord({
          ...options.audit,
          exitCode: result.exitCode,
          durationMs: Date.now() - startedAt,
          timedOut: result.timedOut,
          passwordAuth: result.passwordAuth,
        })
        try {
          await appendAudit(resolved.auditLogPath, record)
        } catch (error) {
          ctx.logger.warn('ssh-remote: could not write the audit log: %s', String(error?.message ?? error))
        }
      }
      return result
    } finally {
      // The password must not outlive the attempt, even on a throw.
      await askpass?.cleanup()
    }
  }

  /**
   * Run a remote command and either return its raw outcome or raise the failure.
   *
   * Kept separate from formatting so the read-only tools can post-process captured
   * lines (a capped list, one window of a file) while still sharing the timeout,
   * failure classification and audit behaviour of every other call.
   *
   * @param entry - the server.
   * @param command - the remote command.
   * @param options - cwd, timeout, stdin, cancellation, tty, detached, tool.
   * @returns the raw invocation outcome.
   */
  const executeCommand = async (entry, command, options) => {
    const password = passwordFor(entry)
    const argv = runArgv(resolved, entry, command, options.cwd, password !== undefined, {
      tty: options.tty === true,
      detached: options.detached === true,
      logPath: options.logPath,
    })
    const result = await runProcess(argv, {
      cwd: options.localCwd,
      timeoutMs: options.timeoutMs,
      stdin: options.stdin,
      signal: options.signal,
      password,
      audit: { tool: options.tool ?? 'ssh_run', server: entry.name, host: entry.host, command },
    })
    if (result.timedOut) {
      // Naming the command is not cosmetic: without it a hang is indistinguishable
      // from a slow server, and the report's whole P0 investigation started from
      // not knowing which command was stuck. The remote half is spelled out
      // because killing the local client does not stop the process on the server.
      throw new SshRemoteError(
        `The command on "${entry.name}" exceeded its ${options.timeoutMs} ms deadline and the local ssh client was terminated.\n` +
          `Command: ${command}\n` +
          'The remote process may still be running: killing the local client does not stop it, and an interrupted package upgrade ' +
          'can leave the dpkg lock held. For long work raise timeoutMs or start it detached (detached: true), then check the remote ' +
          'side before retrying.\n\n' +
          formatRunResult(result, resolved.maxOutputChars),
        'TIMEOUT',
      )
    }
    const failure = classifyFailure(result.exitCode, result.stderr, result.passwordAuth)
    if (failure !== undefined) {
      // Every failure — a broken connection and a legitimately failing remote
      // command alike — is raised, so the model never reads a red result as
      // success. The report still travels with the message.
      throw new SshRemoteError(`${failure.message}\n\n${formatRunResult(result, resolved.maxOutputChars)}`, failure.code)
    }
    return result
  }

  /**
   * Run a remote command and turn the outcome into the model-facing report.
   *
   * @param entry - the server.
   * @param command - the remote command.
   * @param options - cwd, timeout, stdin, cancellation, tty, detached, tool.
   * @returns the formatted report.
   */
  const runCommand = async (entry, command, options) => {
    const result = await executeCommand(entry, command, options)
    return formatRunResult(result, resolved.maxOutputChars)
  }

  /**
   * Resolve a local path the way the tool documentation promises.
   *
   * `resolvePath(localPath)` alone resolves against `process.cwd()` of the plugin
   * host, which is NOT the session workspace: a relative `ssh_put`/`ssh_get` path
   * silently pointed at the wrong directory and failed with an unexplained scp
   * exit 1. The session workspace is what the tool description and the UI both
   * mean, and it is already available as `localCwd`.
   *
   * @param localPath - the path as supplied by the caller.
   * @param localCwd - the session workspace, or undefined.
   * @returns an absolute local path.
   */
  const localPathFor = (localPath, localCwd) => resolvePath(localCwd ?? process.cwd(), localPath)

  /**
   * Copy a file in either direction.
   *
   * @param entry - the server.
   * @param localPath - the local file.
   * @param remotePath - the remote file.
   * @param direction - `'put'` or `'get'`.
   * @param options - cwd, timeout, cancellation.
   * @returns a short confirmation report.
   */
  const copyFile = async (entry, localPath, remotePath, direction, options) => {
    const absolute = localPathFor(localPath, options.localCwd)
    const password = passwordFor(entry)
    const argv = copyArgv(resolved, entry, absolute, remotePath, direction, password !== undefined)
    const result = await runProcess(argv, {
      cwd: options.localCwd,
      timeoutMs: options.timeoutMs,
      signal: options.signal,
      password,
      // The audit line records the transfer in human terms rather than as an scp
      // argv, whose first 200 characters are mostly option flags.
      audit: {
        tool: direction === 'put' ? 'ssh_put' : 'ssh_get',
        server: entry.name,
        host: entry.host,
        command: direction === 'put' ? `scp ${absolute} -> :${remotePath}` : `scp :${remotePath} -> ${absolute}`,
      },
    })
    if (result.timedOut) {
      throw new SshRemoteError(
        `The transfer with "${entry.name}" timed out after ${options.timeoutMs} ms.\n` +
          `Command: ${formatArgv(argv)}\n\n` +
          formatRunResult(result, resolved.maxOutputChars),
        'TIMEOUT',
      )
    }
    const failure = classifyFailure(result.exitCode, result.stderr, result.passwordAuth)
    if (failure !== undefined) {
      // The same diagnostic runCommand already carries. Without it a failed scp
      // was a bare "The remote command exited with code 1." — no path, no
      // command, and no sign of scp's own "No such file or directory".
      throw new SshRemoteError(`${failure.message}\n\n${formatRunResult(result, resolved.maxOutputChars)}`, failure.code)
    }
    const detail = truncate(result.stdout, 4_000)
    const from = direction === 'put' ? absolute : `${entry.name}:${remotePath}`
    const to = direction === 'put' ? `${entry.name}:${remotePath}` : absolute
    return `Copied ${from} -> ${to}${detail.text.length === 0 ? '' : `\n${detail.text}`}`
  }

  // --- confirmation ----------------------------------------------------------

  /**
   * Ask the human to confirm a registry change.
   *
   * Fails closed: without a reachable answerer the change is refused rather than
   * applied. This is the only path that can create or remove a server entry from
   * a tool call, so it must not degrade into silent consent.
   *
   * @param exec - the tool execution supplying the agent and cancellation.
   * @param questions - the questions to put to the user.
   * @returns the answer batch.
   */
  const confirm = async (exec, questions) => {
    const userQuestions = ctx.get('userQuestions')
    if (userQuestions === undefined) {
      throw new SshRemoteError(
        'This action needs a live user confirmation, and no question service is available in this profile.',
        'NO_ANSWERER',
      )
    }
    if (exec.agent === undefined) {
      throw new SshRemoteError('This action needs an owning agent session to ask for confirmation.', 'NO_AGENT')
    }
    try {
      return await userQuestions.ask({ questions, agent: exec.agent, signal: exec.signal })
    } catch (error) {
      throw new SshRemoteError(
        `The action was not performed because confirmation could not be obtained: ${String(error?.message ?? error)}`,
        'CONFIRM_FAILED',
      )
    }
  }

  /**
   * Read the human's decision from an answer batch.
   *
   * @param answer - the answer batch.
   * @param id - the question id.
   * @returns the chosen label, or undefined.
   */
  const decision = (answer, id) => {
    const item = answer?.answers?.find((entry) => entry.id === id)
    return item?.selected?.[0] ?? item?.custom
  }

  // --- tools -----------------------------------------------------------------

  /**
   * Register one tool with a normalized parameter schema.
   *
   * The normalization is not cosmetic: see {@link objectSchema} for the request
   * rejection that a bare property map causes on Anthropic-fronted providers.
   */
  const registerTool = (definition) =>
    ctx.tools.register({ ...definition, parameters: objectSchema(definition.parameters) })

  registerTool({
    name: 'ssh_hosts',
    description:
      'List the VPS servers registered for SSH access, with their address, user, port and key. ' +
      'Use it to discover which server names ssh_run, ssh_put and ssh_get accept.',
    parameters: {
      probe: {
        type: 'boolean',
        description: 'Also run a quick connection test against each server. Defaults to false.',
      },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    isConcurrencySafe: () => true,
    async execute(args, exec) {
      const current = loadHosts(true)
      if (current.length === 0) {
        return (
          `No servers are registered. The registry is ${resolved.registryPath}.\n` +
          'Import them from the SSH config with /ssh sync, or add one with ssh_host_add.'
        )
      }
      const lines = [`Registered servers (${current.length}) — registry ${resolved.registryPath}`, '']
      for (const entry of current) {
        const parts = [entry.user === undefined ? entry.host : `${entry.user}@${entry.host}`]
        if (entry.port !== undefined && entry.port !== 22) parts.push(`port ${entry.port}`)
        if (entry.identityFile !== undefined) parts.push(`key ${entry.identityFile}`)
        if (entry.workspace !== undefined) parts.push(`cwd ${entry.workspace}`)
        const marker = preferred === entry.name ? ' (default)' : ''
        lines.push(`  ${entry.name}${marker}`)
        lines.push(`      ${parts.join(', ')}`)
        if (entry.description !== undefined) lines.push(`      ${entry.description}`)

        if (args?.probe === true) {
          // A locked server is never probed: reaching out is an effect the lock
          // exists to prevent, and reporting "locked" is the truthful answer.
          if (entry.locked === true) {
            lines.push('      reachable: locked')
            continue
          }
          // The probe must exercise the SAME authentication a real call would
          // use, password included. Probing with key only reported a working
          // password server as unreachable, so the diagnostic contradicted the
          // very connection it was meant to verify.
          try {
            const password = passwordFor(entry)
            const probe = await runProcess(runArgv(resolved, entry, 'true', undefined, password !== undefined), {
              cwd: localCwd(exec),
              timeoutMs: resolved.connectTimeoutMs + 5_000,
              signal: exec.signal,
              password,
              audit: { tool: 'ssh_probe', server: entry.name, host: entry.host, command: 'true' },
            })
            // The exit code is checked here rather than only catching a throw:
            // a refused connection exits non-zero without rejecting, so a bare
            // try/catch would report every dead server as reachable.
            const failure = classifyFailure(probe.exitCode, probe.stderr, probe.passwordAuth)
            lines.push(
              failure === undefined
                ? `      reachable: yes${password === undefined ? '' : ' (password)'}`
                : `      reachable: no (${failure.code})`,
            )
          } catch (error) {
            lines.push(`      reachable: no (${String(error?.message ?? error)})`)
          }
        }
      }
      lines.push('', `Client: ${resolved.sshPath}`, `Host-key checking: ${STRICT_HOST_KEY}, ${BATCH_MODE}`)
      return lines.join('\n')
    },
  })

  registerTool({
    name: 'ssh_host_add',
    description:
      'Register a new VPS server for SSH access. The change always requires explicit user confirmation before it is stored. ' +
      'The key itself must already be installed; passwords are not supported.',
    parameters: {
      name: {
        type: 'string',
        required: true,
        description: 'Short selection name, for example "web1". Letters, digits, dot, dash or underscore.',
      },
      host: { type: 'string', required: true, description: 'Address or OpenSSH host alias.' },
      user: { type: 'string', description: 'SSH user. Defaults to the client configuration.' },
      port: { type: 'number', description: 'SSH port. Defaults to 22.' },
      identityFile: { type: 'string', description: 'Path to the private key to use for this server.' },
      workspace: { type: 'string', description: 'Default remote directory for relative paths.' },
      description: { type: 'string', description: 'Free-form note about what this server is for.' },
      replace: { type: 'boolean', description: 'Overwrite an existing entry with the same name. Defaults to false.' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args, exec) {
      const current = loadHosts(true)
      let entry
      try {
        entry = normalizeEntry({
          name: args.name,
          host: args.host,
          user: args.user,
          port: args.port,
          identityFile: args.identityFile,
          workspace: args.workspace,
          description: args.description,
          addedAt: new Date().toISOString(),
          addedBy: 'agent-confirmed',
        })
      } catch (error) {
        if (error instanceof RegistryError) throw new SshRemoteError(error.message, error.code)
        throw error
      }

      const existing = findEntry(current, entry.name)
      if (existing !== undefined && args.replace !== true) {
        throw new SshRemoteError(
          `A server named "${entry.name}" already exists (${existing.user === undefined ? existing.host : `${existing.user}@${existing.host}`}). ` +
            'Pass replace: true to overwrite it.',
          'NAME_TAKEN',
        )
      }

      const summary = [
        `name: ${entry.name}`,
        `host: ${entry.host}`,
        `user: ${entry.user ?? '(from SSH config)'}`,
        `port: ${entry.port ?? 22}`,
        `key: ${entry.identityFile ?? '(from SSH config / agent)'}`,
      ]
      if (entry.workspace !== undefined) summary.push(`workspace: ${entry.workspace}`)
      const answer = await confirm(exec, [
        {
          id: 'confirm-add',
          header: existing === undefined ? 'Add server' : 'Replace server',
          question:
            `${existing === undefined ? 'Register' : 'Replace'} this server for SSH access? ` +
            'Commands will run on it with the authority of your SSH key.\n\n' +
            summary.join('\n'),
          options: [
            { label: existing === undefined ? 'Add server' : 'Replace server', description: 'Store the entry and allow connections.' },
            { label: 'Cancel', description: 'Leave the registry unchanged.' },
          ],
        },
      ])
      const chosen = decision(answer, 'confirm-add')
      const approved = existing === undefined ? 'Add server' : 'Replace server'
      if (chosen !== approved) {
        return `Cancelled: "${entry.name}" was not registered.`
      }

      try {
        await saveHosts(upsertEntry(current, entry, args.replace === true))
      } catch (error) {
        if (error instanceof RegistryError) throw new SshRemoteError(error.message, error.code)
        throw new SshRemoteError(`The registry could not be written: ${String(error?.message ?? error)}`, 'REGISTRY_WRITE_FAILED')
      }
      return `Registered "${entry.name}" (${entry.user === undefined ? entry.host : `${entry.user}@${entry.host}`}).`
    },
  })

  registerTool({
    name: 'ssh_host_remove',
    description: 'Remove a server from the SSH registry. Always requires explicit user confirmation.',
    parameters: {
      name: { type: 'string', required: true, description: 'The registered server name to remove.' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    async execute(args, exec) {
      const current = loadHosts(true)
      const entry = findEntry(current, args.name)
      if (entry === undefined) {
        throw new SshRemoteError(`No server named "${args.name}" is registered.`, 'NAME_UNKNOWN')
      }
      const answer = await confirm(exec, [
        {
          id: 'confirm-remove',
          header: 'Remove server',
          question:
            `Remove "${entry.name}" (${entry.user === undefined ? entry.host : `${entry.user}@${entry.host}`}) from the registry?\n\n` +
            'This forgets the entry only; nothing on the server and no key material is touched.',
          options: [
            { label: 'Remove', description: 'Forget this server.' },
            { label: 'Cancel', description: 'Keep the entry.' },
          ],
        },
      ])
      if (decision(answer, 'confirm-remove') !== 'Remove') {
        return `Cancelled: "${entry.name}" was not removed.`
      }
      try {
        await saveHosts(removeEntry(current, entry.name))
      } catch (error) {
        if (error instanceof RegistryError) throw new SshRemoteError(error.message, error.code)
        throw new SshRemoteError(`The registry could not be written: ${String(error?.message ?? error)}`, 'REGISTRY_WRITE_FAILED')
      }
      return `Removed "${entry.name}".`
    },
  })

  registerTool({
    name: 'ssh_run',
    description:
      'Run a shell command on a registered VPS server and return its stdout, stderr and exit code. ' +
      'The command runs with the authority of your SSH key, so it can change the server. ' +
      'A catastrophic command is refused outright, and an irreversible but legitimate one asks the user first.',
    parameters: {
      host: { type: 'string', description: 'Registered server name. Defaults to the selected server.' },
      command: { type: 'string', required: true, description: 'Shell command to run on the server.' },
      cwd: { type: 'string', description: 'Remote working directory for the command.' },
      timeoutMs: { type: 'number', description: 'Deadline in milliseconds. Defaults to the configured value.' },
      stdin: { type: 'string', description: 'Text piped to the command standard input.' },
      tty: {
        type: 'boolean',
        description:
          'Allocate a pseudo-terminal so an interactive command (top, a password-prompting sudo) can run. ' +
          'Output then contains terminal control sequences. Defaults to false.',
      },
      detached: {
        type: 'boolean',
        description:
          'Start the command under nohup in the background and return its pid and log path immediately instead of waiting. ' +
          'Use it for long upgrades and builds, whose deadline would otherwise kill only the local client. Defaults to false.',
      },
      logPath: {
        type: 'string',
        description: 'Remote log file for a detached command. Defaults to /tmp/ssh-remote-<id>.log.',
      },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    presentCall: (args) => ({
      card: 'terminal',
      title: `${args.host === undefined ? '' : `${args.host}: `}${args.command}`,
      ...(args.cwd === undefined ? {} : { cwd: args.cwd }),
    }),
    async execute(args, exec) {
      const command = typeof args.command === 'string' ? args.command.trim() : ''
      if (command.length === 0) throw new SshRemoteError('command must be a non-empty string.', 'COMMAND_REQUIRED')
      if (args.tty === true && args.detached === true) {
        throw new SshRemoteError(
          'tty and detached cannot be combined: a background command has no terminal to allocate.',
          'COMMAND_INVALID',
        )
      }
      loadHosts(true)
      const entry = resolveEntry(args.host)

      // The guard already refused the catastrophic tier; this is the authoritative
      // check, because a guard is a synchronous fast path over a snapshot, and a
      // call that reaches execution must be refused on its own facts.
      const verdict = classifyCommand(command)
      if (verdict.tier === 'block') {
        throw new SshRemoteError(blockedCommandText(command, verdict.reason), 'COMMAND_BLOCKED')
      }
      if (verdict.tier === 'ask' && resolved.commandPolicy !== 'off') {
        // The model cannot approve its own irreversible command. Without a
        // reachable answerer `confirm` throws, which is the fail-closed result.
        const answer = await confirm(exec, [
          {
            id: 'confirm-command',
            header: 'Risky command',
            question:
              `Run this command on "${entry.name}" ` +
              `(${entry.user === undefined ? entry.host : `${entry.user}@${entry.host}`})?\n\n` +
              `${command}\n\n` +
              `Why it asks: ${verdict.reason}.\n` +
              `Working directory: ${args.cwd ?? entry.workspace ?? '(login directory)'}\n\n` +
              'This cannot be undone.',
            options: [
              { label: 'Run it', description: 'Execute the command once on this server.' },
              { label: 'Cancel', description: 'Run nothing.' },
            ],
          },
        ])
        if (decision(answer, 'confirm-command') !== 'Run it') {
          return `Cancelled: nothing was run on "${entry.name}".`
        }
      }

      const timeoutMs = clampTimeout(args.timeoutMs, resolved)
      const detached = args.detached === true
      const logPath = detached
        ? typeof args.logPath === 'string' && args.logPath.trim().length > 0
          ? args.logPath.trim()
          : `/tmp/ssh-remote-${detachedLogId()}.log`
        : undefined
      const report = await runCommand(entry, command, {
        cwd: args.cwd ?? entry.workspace,
        localCwd: localCwd(exec),
        timeoutMs,
        // A detached command must not compete for the closed channel's stdin.
        stdin: detached ? undefined : args.stdin,
        signal: exec.signal,
        tty: args.tty === true,
        detached,
        logPath,
      })
      return detached ? detachedReport(entry, command, report, logPath) : report
    },
  })

  registerTool({
    name: 'ssh_put',
    description: 'Copy a local file to a registered VPS server.',
    parameters: {
      host: { type: 'string', description: 'Registered server name. Defaults to the selected server.' },
      localPath: { type: 'string', required: true, description: 'Local file to send. Relative paths resolve against the session workspace.' },
      remotePath: { type: 'string', required: true, description: 'Destination path on the server.' },
      timeoutMs: { type: 'number', description: 'Deadline in milliseconds.' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    presentCall: (args) => ({ card: 'generic', title: `Send ${args.localPath} to ${args.remotePath}`, kind: 'move' }),
    async execute(args, exec) {
      loadHosts(true)
      const entry = resolveEntry(args.host)
      if (typeof args.localPath !== 'string' || args.localPath.trim().length === 0) {
        throw new SshRemoteError('localPath must be a non-empty string.', 'PATH_REQUIRED')
      }
      if (typeof args.remotePath !== 'string' || args.remotePath.trim().length === 0) {
        throw new SshRemoteError('remotePath must be a non-empty string.', 'PATH_REQUIRED')
      }
      return copyFile(entry, args.localPath, args.remotePath, 'put', {
        localCwd: localCwd(exec),
        timeoutMs: clampTimeout(args.timeoutMs, resolved),
        signal: exec.signal,
      })
    },
  })

  registerTool({
    name: 'ssh_get',
    description: 'Copy a file from a registered VPS server to the local machine.',
    parameters: {
      host: { type: 'string', description: 'Registered server name. Defaults to the selected server.' },
      remotePath: { type: 'string', required: true, description: 'File path on the server.' },
      localPath: { type: 'string', required: true, description: 'Local destination. Relative paths resolve against the session workspace.' },
      timeoutMs: { type: 'number', description: 'Deadline in milliseconds.' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    presentCall: (args) => ({ card: 'generic', title: `Fetch ${args.remotePath} to ${args.localPath}`, kind: 'move' }),
    async execute(args, exec) {
      loadHosts(true)
      const entry = resolveEntry(args.host)
      if (typeof args.remotePath !== 'string' || args.remotePath.trim().length === 0) {
        throw new SshRemoteError('remotePath must be a non-empty string.', 'PATH_REQUIRED')
      }
      if (typeof args.localPath !== 'string' || args.localPath.trim().length === 0) {
        throw new SshRemoteError('localPath must be a non-empty string.', 'PATH_REQUIRED')
      }
      return copyFile(entry, args.localPath, args.remotePath, 'get', {
        localCwd: localCwd(exec),
        timeoutMs: clampTimeout(args.timeoutMs, resolved),
        signal: exec.signal,
      })
    },
  })

  // --- read-only navigation --------------------------------------------------

  /** Split captured remote output into lines, ignoring one trailing newline. */
  const linesOf = (text) => {
    const value = String(text ?? '')
    if (value.length === 0) return []
    return value.replace(/\n$/, '').split('\n')
  }

  /**
   * Bound a remote listing to a line budget.
   *
   * The remote side is asked for one line more than the budget, so an extra line
   * is proof that more exist and a listing of exactly `limit` lines stays honest.
   *
   * @param text - captured stdout.
   * @param limit - the line budget.
   * @returns the visible lines and whether more exist.
   */
  const capLines = (text, limit) => {
    const lines = linesOf(text)
    if (lines.length <= limit) return { lines, truncated: false }
    return { lines: lines.slice(0, limit), truncated: true }
  }

  /**
   * Read one positive integer tool argument.
   *
   * @param value - the caller's value, if any.
   * @param fallback - the default.
   * @param maximum - the ceiling a larger request is clamped to.
   * @param label - the parameter name used in an error.
   * @returns a usable count.
   */
  const countArg = (value, fallback, maximum, label) => {
    if (value === undefined || value === null) return fallback
    const number = Number(value)
    if (!Number.isInteger(number) || number < 1) {
      throw new SshRemoteError(`${label} must be a positive integer, got ${value}.`, 'ARGUMENT_INVALID')
    }
    return Math.min(number, maximum)
  }

  /** Read a required remote path without rewriting the caller's bytes. */
  const requirePath = (value, label) => {
    if (typeof value !== 'string' || value.trim().length === 0) {
      throw new SshRemoteError(`${label} must be a non-empty string.`, 'PATH_REQUIRED')
    }
    return value
  }

  /**
   * Format one read-only listing: a header, the lines and an explicit cap note.
   *
   * @param header - what was read.
   * @param text - captured stdout.
   * @param limit - the line budget.
   * @param unit - what a line is, for the note.
   * @returns the model-facing report.
   */
  const renderListing = (header, text, limit, unit) => {
    const capped = capLines(text, limit)
    const body = capped.lines.length === 0 ? '(empty)' : capped.lines.join('\n')
    const trimmed = truncate(body, resolved.maxOutputChars)
    const parts = [header, '', trimmed.text]
    if (capped.truncated) {
      parts.push('', `… truncated: showing the first ${limit} ${unit}. Narrow the request to see more.`)
    }
    if (trimmed.truncated) parts.push(trimmed.note.trimStart())
    return parts.join('\n')
  }

  registerTool({
    name: 'ssh_read',
    description:
      'Read a text file on a registered VPS server without downloading it. ' +
      'Returns at most `limit` lines starting at line `offset`, and says when more lines follow. ' +
      'Use it to inspect a remote log or configuration instead of composing sed or tail commands for ssh_run.',
    parameters: {
      host: { type: 'string', description: 'Registered server name. Defaults to the selected server.' },
      path: { type: 'string', required: true, description: 'Remote file path, absolute or relative to the server default directory.' },
      offset: { type: 'number', description: '1-based line to start at. Defaults to 1.' },
      limit: { type: 'number', description: 'Maximum lines to return, at most 2000. Defaults to 200.' },
      timeoutMs: { type: 'number', description: 'Deadline in milliseconds.' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    isConcurrencySafe: () => true,
    presentCall: (args) => ({ card: 'terminal', title: `read ${args.path}` }),
    async execute(args, exec) {
      const path = requirePath(args.path, 'path')
      const offset = countArg(args.offset, 1, 50_000_000, 'offset')
      const limit = countArg(args.limit, 200, 2_000, 'limit')
      loadHosts(true)
      const entry = resolveEntry(args.host)
      // One extra line is requested: seeing it proves the window is not the end of
      // the file, so the tool never claims completeness it cannot know.
      const command = `sed -n '${offset},${offset + limit}p' -- ${shellQuote(path)}`
      const result = await executeCommand(entry, command, {
        cwd: entry.workspace,
        localCwd: localCwd(exec),
        timeoutMs: clampTimeout(args.timeoutMs, resolved),
        signal: exec.signal,
        tool: 'ssh_read',
      })
      const lines = linesOf(result.stdout)
      const truncated = lines.length > limit
      const visible = truncated ? lines.slice(0, limit) : lines
      const header =
        visible.length === 0
          ? `${path}: no lines at offset ${offset} (the file is shorter or empty)`
          : `${path}: lines ${offset}-${offset + visible.length - 1}`
      const parts = [header, '', visible.length === 0 ? '(empty)' : visible.join('\n')]
      if (truncated) {
        parts.push('', `… more lines follow. Continue with offset=${offset + visible.length} (limit=${limit}).`)
      }
      const trimmed = truncate(parts.join('\n'), resolved.maxOutputChars)
      return trimmed.note === undefined ? trimmed.text : `${trimmed.text}\n${trimmed.note.trimStart()}`
    },
  })

  registerTool({
    name: 'ssh_ls',
    description:
      'List a directory on a registered VPS server. Returns at most 200 entries and marks the list as truncated when more exist.',
    parameters: {
      host: { type: 'string', description: 'Registered server name. Defaults to the selected server.' },
      path: { type: 'string', description: 'Remote directory. Defaults to the server default directory.' },
      long: { type: 'boolean', description: 'Include permissions, owner, size and date. Defaults to true.' },
      timeoutMs: { type: 'number', description: 'Deadline in milliseconds.' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    isConcurrencySafe: () => true,
    presentCall: (args) => ({ card: 'terminal', title: `ls ${args.path ?? '.'}` }),
    async execute(args, exec) {
      const path = typeof args.path === 'string' && args.path.trim().length > 0 ? args.path : '.'
      const flags = args.long === false ? '-a' : '-la'
      loadHosts(true)
      const entry = resolveEntry(args.host)
      const limit = 200
      const command = `set -o pipefail; ls ${flags} -- ${shellQuote(path)} | head -n ${limit + 1}; ${PIPE_STATUS}`
      const result = await executeCommand(entry, command, {
        cwd: entry.workspace,
        localCwd: localCwd(exec),
        timeoutMs: clampTimeout(args.timeoutMs, resolved),
        signal: exec.signal,
        tool: 'ssh_ls',
      })
      return renderListing(`ls ${flags} ${path}`, result.stdout, limit, 'entries')
    },
  })

  registerTool({
    name: 'ssh_grep',
    description:
      'Search file contents under a directory on a registered VPS server. ' +
      'Returns matching lines as path:line:text, at most `maxMatches` of them, and marks the result as truncated when more exist. ' +
      'Binary files are skipped.',
    parameters: {
      host: { type: 'string', description: 'Registered server name. Defaults to the selected server.' },
      pattern: { type: 'string', required: true, description: 'Regular expression to search for.' },
      path: { type: 'string', required: true, description: 'Remote file or directory to search, recursive under a directory.' },
      glob: { type: 'string', description: 'Only search files whose name matches this shell glob, for example *.js.' },
      maxMatches: { type: 'number', description: 'Maximum matching lines to return, at most 1000. Defaults to 100.' },
      timeoutMs: { type: 'number', description: 'Deadline in milliseconds.' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    isConcurrencySafe: () => true,
    presentCall: (args) => ({ card: 'terminal', title: `grep ${args.pattern} in ${args.path}` }),
    async execute(args, exec) {
      const pattern = requirePath(args.pattern, 'pattern')
      const path = requirePath(args.path, 'path')
      const limit = countArg(args.maxMatches, 100, 1_000, 'maxMatches')
      const glob = typeof args.glob === 'string' && args.glob.trim().length > 0 ? args.glob.trim() : undefined
      loadHosts(true)
      const entry = resolveEntry(args.host)
      const include = glob === undefined ? '' : ` --include=${shellQuote(glob)}`
      // `-H` forces the file name even when a single file is searched, so every
      // result line keeps the documented `path:line:text` shape. Without it grep
      // drops the name for one file and the model has to guess which file a line
      // came from.
      const command =
        `set -o pipefail; grep -rnH --binary-files=without-match${include} -- ${shellQuote(pattern)} ${shellQuote(path)} ` +
        `| head -n ${limit + 1}; ${GREP_STATUS}`
      const result = await executeCommand(entry, command, {
        cwd: entry.workspace,
        localCwd: localCwd(exec),
        timeoutMs: clampTimeout(args.timeoutMs, resolved),
        signal: exec.signal,
        tool: 'ssh_grep',
      })
      const header = `grep ${pattern} in ${path}${glob === undefined ? '' : ` (${glob})`}`
      return renderListing(header, result.stdout, limit, 'matching lines')
    },
  })

  registerTool({
    name: 'ssh_glob',
    description:
      'Find files on a registered VPS server by name. Searches recursively under `path`, matching `pattern` as a shell glob ' +
      '(the same rule as find -name), and returns at most `maxResults` paths with a truncation note when more exist.',
    parameters: {
      host: { type: 'string', description: 'Registered server name. Defaults to the selected server.' },
      pattern: { type: 'string', required: true, description: 'Shell glob matched against the file name, for example *.log.' },
      path: { type: 'string', description: 'Remote directory to search. Defaults to the server default directory.' },
      maxResults: { type: 'number', description: 'Maximum paths to return, at most 2000. Defaults to 200.' },
      timeoutMs: { type: 'number', description: 'Deadline in milliseconds.' },
    },
    output: {
      schema: { type: 'string' },
      render: (_args, value) => [{ type: 'text', text: value }],
    },
    isConcurrencySafe: () => true,
    presentCall: (args) => ({ card: 'terminal', title: `find ${args.pattern} in ${args.path ?? '.'}` }),
    async execute(args, exec) {
      const pattern = requirePath(args.pattern, 'pattern')
      const path = typeof args.path === 'string' && args.path.trim().length > 0 ? args.path : '.'
      const limit = countArg(args.maxResults, 200, 2_000, 'maxResults')
      loadHosts(true)
      const entry = resolveEntry(args.host)
      const command = `set -o pipefail; find ${shellQuote(path)} -name ${shellQuote(pattern)} -print | head -n ${limit + 1}; ${PIPE_STATUS}`
      const result = await executeCommand(entry, command, {
        cwd: entry.workspace,
        localCwd: localCwd(exec),
        timeoutMs: clampTimeout(args.timeoutMs, resolved),
        signal: exec.signal,
        tool: 'ssh_glob',
      })
      return renderListing(`find ${path} -name ${pattern}`, result.stdout, limit, 'paths')
    },
  })

  // A guard is the only place that can refuse a call before it starts. It is
  // synchronous, so it reads the snapshot; the execution path re-validates
  // against a fresh read, making this a fast refusal rather than the authority.
  ctx.tools.guard((execution) => {
    const guarded = ['ssh_run', 'ssh_put', 'ssh_get', 'ssh_read', 'ssh_ls', 'ssh_grep', 'ssh_glob']
    if (!guarded.includes(execution.name)) return undefined
    // The catastrophic tier is refused here, before any process starts. The
    // classifier is pure and synchronous, which is exactly what a guard can use.
    if (execution.name === 'ssh_run') {
      const command = execution.arguments?.command
      if (typeof command === 'string' && command.trim().length > 0) {
        const verdict = classifyCommand(command)
        if (verdict.tier === 'block') return blockedCommandText(command, verdict.reason)
      }
    }
    const requested = execution.arguments?.host
    if (typeof requested !== 'string' || requested.trim().length === 0) return undefined
    const entry = findEntry(hosts, requested)
    if (entry !== undefined) {
      // A locked server must be refused here too: the guard is synchronous and
      // reads the snapshot, so it is the earliest point that can stop a call.
      if (entry.locked === true) {
        return `Server "${entry.name}" is locked; no command or transfer will run on it. Unlock it with /ssh unlock ${entry.name}.`
      }
      return undefined
    }
    if (config.allowRawHosts === true) return undefined
    return `Unknown server "${requested}"; only registered server names are reachable.`
  })

  // --- /ssh ------------------------------------------------------------------

  ctx.inject(['commands'], (commandCtx) => {
    /** The server list rendered as a preformatted report. */
    const renderHosts = () => {
      if (hosts.length === 0) {
        return [
          'Серверы SSH',
          '',
          'Пока ни один сервер не зарегистрирован.',
          `Реестр: ${resolved.registryPath}`,
          '',
          'Добавить: /ssh add — вручную, или /ssh sync — импорт из ~/.ssh/config.',
        ].join('\n')
      }
      const lines = ['Серверы SSH', '']
      for (const entry of hosts) {
        const where = entry.user === undefined ? entry.host : `${entry.user}@${entry.host}`
        const extra = entry.port === undefined || entry.port === 22 ? '' : ` порт ${entry.port}`
        const parts = []
        if (preferred === entry.name) parts.push('по умолчанию')
        // The lock is the most important state to surface: it explains why a
        // listed server refuses every operation.
        if (entry.locked === true) parts.push('ЗАБЛОКИРОВАН')
        const marker = parts.length === 0 ? '' : `  ← ${parts.join(', ')}`
        lines.push(`  ${entry.name.padEnd(14)} ${where}${extra}${marker}`)
      }
      lines.push('', `Реестр: ${resolved.registryPath}`)
      // Repairs are shown, not hidden, but they never block the listing.
      if (lastWarnings.length > 0) {
        lines.push('', 'Замечания к реестру:')
        for (const warning of lastWarnings) lines.push(`  • ${warning}`)
      }
      lines.push(
        'Проверка: /ssh <имя> или /ssh test <имя>   По умолчанию: /ssh default <имя>   Состояние: /ssh status',
        'Добавить: /ssh add   Импорт: /ssh sync   Убрать: /ssh remove <имя>',
        'Пароль (если на сервере нет ключа): /ssh pass <имя> <пароль>   Забыть: /ssh nopass <имя>',
        'Доступ: /ssh lock <имя> — запретить операции, /ssh unlock <имя> — разрешить',
      )
      return lines.join('\n')
    }

    /**
     * Set or clear the default server explicitly.
     *
     * Selecting a server and making it the default were the same implicit step,
     * so a plain reachability check silently changed which server tools used when
     * no `host` was given. This verb separates the two: `/ssh <имя>` only checks,
     * `/ssh default <имя>` deliberately changes the default.
     *
     * @param name - the server name, or empty to clear the default.
     * @returns the outcome to render.
     */
    const setDefault = async (name) => {
      if (name.length === 0) {
        if (preferred === undefined) return { kind: 'success', text: 'Сервер по умолчанию не задан.' }
        const previous = preferred
        try {
          // An empty string is written as an absent key by writeRegistry, which
          // is what "no default" means on disk.
          await saveHosts(hosts, '')
        } catch (error) {
          return { kind: 'error', text: describeWriteFailure(error) }
        }
        preferred = undefined
        return { kind: 'success', text: `Сервер по умолчанию сброшен (был "${previous}").` }
      }
      const entry = findEntry(hosts, name)
      if (entry === undefined) {
        const known = hosts.map((candidate) => candidate.name).join(', ')
        return { kind: 'error', text: `Неизвестный сервер "${name}". Зарегистрированы: ${known.length > 0 ? known : 'нет'}.` }
      }
      try {
        await saveHosts(hosts, entry.name)
      } catch (error) {
        return { kind: 'error', text: describeWriteFailure(error) }
      }
      return {
        kind: 'success',
        text:
          `Сервер по умолчанию: "${entry.name}".\n` +
          'Он используется, когда инструмент вызван без параметра host.',
      }
    }

    /**
     * Lock or unlock one server.
     *
     * Locking is the deliberate "stop touching this machine" switch. It keeps the
     * entry, its address and its credential intact, and refuses every subsequent
     * operation on that server — including the connection test, since opening a
     * connection is itself an effect.
     *
     * @param name - the server name.
     * @param locked - the state to set.
     * @returns the outcome to render.
     */
    const setLocked = async (name, locked) => {
      if (name.length === 0) {
        return { kind: 'error', text: `Использование: /ssh ${locked ? 'lock' : 'unlock'} <имя>` }
      }
      const entry = findEntry(hosts, name)
      if (entry === undefined) return { kind: 'error', text: `Неизвестный сервер "${name}".` }
      if ((entry.locked === true) === locked) {
        return {
          kind: 'success',
          text: `Сервер "${entry.name}" уже ${locked ? 'заблокирован' : 'разблокирован'}.`,
        }
      }
      // `locked` is added or removed rather than set to a value, so an unlocked
      // entry stays byte-identical to what it was before.
      const next = { ...entry }
      if (locked) next.locked = true
      else delete next.locked
      try {
        await saveHosts(hosts.map((candidate) => (candidate.name === entry.name ? next : candidate)))
      } catch (error) {
        return { kind: 'error', text: describeWriteFailure(error) }
      }
      return {
        kind: 'success',
        text: locked
          ? `Сервер "${entry.name}" заблокирован: команды и передача файлов на него больше не выполняются.\nРазблокировать:  /ssh unlock ${entry.name}`
          : `Сервер "${entry.name}" разблокирован: операции снова разрешены.`,
      }
    }

    /** A compact access summary: which servers the agent may actually use. */
    const renderStatus = () => {
      if (hosts.length === 0) return 'Серверы не зарегистрированы.'
      const lines = ['Доступ к серверам', '']
      const secrets = readSecrets(resolved.secretsPath)
      for (const entry of hosts) {
        const locked = entry.locked === true
        const hasPassword = secrets.passwords[entry.name] !== undefined
        const hasKey = entry.identityFile !== undefined
        const how = hasKey ? 'ключ' : hasPassword ? 'пароль' : 'нет ни ключа, ни пароля'
        const marker = preferred === entry.name ? '   ← по умолчанию' : ''
        lines.push(`  ${entry.name.padEnd(14)} ${locked ? 'запрещён ' : 'разрешён '}  (${how})${marker}`)
      }
      // A default naming a server that is gone is worth surfacing: it is the
      // state that makes a host-less call fail with a confusing message.
      if (preferred !== undefined && findEntry(hosts, preferred) === undefined) {
        lines.push('', `Внимание: сервер по умолчанию "${preferred}" больше не зарегистрирован.`)
        lines.push('Назначьте новый: /ssh default <имя>   или сбросьте: /ssh default')
      }
      lines.push(
        '',
        'По умолчанию: /ssh default <имя>   Сбросить: /ssh default',
        'Запретить: /ssh lock <имя>   Разрешить: /ssh unlock <имя>',
      )
      return lines.join('\n')
    }

    /**
     * Run a connection test and describe the outcome in plain language.
     *
     * The stored password is used exactly as a real operation would use it.
     * Omitting it would make the test lie in both directions: it would report
     * failure for a server that works by password, and it would make the
     * confirmation printed by `/ssh pass` contradict what was just stored.
     *
     * Output policy: a refusal is reported as one short Russian line plus the
     * exact command that fixes it. Dumping OpenSSH's English stderr made a normal
     * "this server needs a password" state look like a crash, which is what the
     * user sees first and has to interpret. The raw text is kept in
     * `technical` for the caller to append only where a human asks for details.
     *
     * @param entry - the server to test.
     * @returns a human-readable result and the classified failure code.
     */
    const testHost = async (entry, agent) => {
      // A locked server is reported as locked rather than probed: opening a
      // connection is itself an effect the lock is meant to prevent.
      if (entry.locked === true) {
        return { text: `Сервер ${entry.name}: заблокирован. Разблокировать: /ssh unlock ${entry.name}`, code: 'HOST_LOCKED' }
      }
      try {
        const password = passwordFor(entry)
        const result = await runProcess(runArgv(resolved, entry, 'true', undefined, password !== undefined), {
          cwd: process.cwd(),
          timeoutMs: resolved.connectTimeoutMs + 5_000,
          signal: undefined,
          password,
          audit: { tool: 'ssh_test', server: entry.name, host: entry.host, command: 'true' },
        })
        const failure = classifyFailure(result.exitCode, result.stderr, result.passwordAuth)
        if (failure === undefined) {
          return { text: `Сервер ${entry.name}: подключение работает${password === undefined ? '' : ' (по паролю)'}.` }
        }
        return { text: refusalText(entry, failure, password !== undefined), code: failure.code, technical: failure.message }
      } catch (error) {
        return { text: `Сервер ${entry.name}: подключиться не удалось.\n${String(error?.message ?? error)}` }
      }
    }

    /** Ask the user to pick a server from the registry. */
    const pickHost = async (agent, signal) => {
      const userQuestions = ctx.get('userQuestions')
      if (userQuestions === undefined) {
        return { text: renderHosts(), kind: 'success' }
      }
      const options = hosts.map((entry) => ({
        label: entry.name,
        description: `${entry.user === undefined ? entry.host : `${entry.user}@${entry.host}`}${entry.description === undefined ? '' : ` — ${entry.description}`}`,
      }))
      options.push({ label: 'Добавить новый сервер', description: 'Ввести адрес, пользователя и ключ вручную.' })
      options.push({ label: 'Импортировать из ~/.ssh/config', description: `Прочитать ${sshConfigPath} и добавить найденные хосты.` })

      const answer = await userQuestions.ask({
        agent,
        signal,
        questions: [
          {
            id: 'pick-host',
            header: 'Сервер SSH',
            question: 'Какой сервер использовать для SSH?',
            options,
          },
        ],
      })
      const chosen = decision(answer, 'pick-host')
      if (chosen === undefined) return { text: 'Сервер не выбран.', kind: 'success' }
      // Both branches run work that can take a moment, so they are awaited; an
      // unawaited call would render a Promise object as the command output.
      if (chosen === 'Добавить новый сервер') return { text: await addFlow(agent, signal), kind: 'success' }
      if (chosen === 'Импортировать из ~/.ssh/config') return { text: await syncFlow(), kind: 'success' }
      const entry = findEntry(hosts, chosen)
      if (entry === undefined) return { text: `Неизвестный сервер "${chosen}".`, kind: 'error' }
      await saveHosts(hosts, entry.name)
      const tested = await testHost(entry, agent)
      // The refusal text already names the cure, so no second instruction is
      // appended here; doing so produced the duplicated double-advice the user saw.
      return { text: tested.text, kind: 'success' }
    }

    /**
     * The one place a password enters the system.
     *
     * The password is supplied as the command's own input, never through
     * `userQuestions`: a question answer is steered into the agent as a user
     * message, so a password typed there would be readable by the model. A
     * command's input never becomes a model message, and this command additionally
     * declares `recordInput: false` so the value is not written into the session
     * log either.
     *
     * @param rawAfterVerb - the text following the `pass` verb, untrimmed.
     * @param agent - the invoking session, used only for reachability feedback.
     * @returns the outcome to render.
     */
    const passFlow = async (rawAfterVerb, agent) => {
      // Only the separator after the verb is dropped. The password keeps every
      // other byte, including trailing spaces: silently trimming it would store a
      // credential different from the one the user typed.
      const rest = rawAfterVerb.replace(/^\s+/, '')
      const match = /^(\S+)(\s+)([\s\S]*)$/.exec(rest)
      if (match === null) {
        return { kind: 'error', text: 'Использование: /ssh pass <имя> <пароль> — пароль не попадает в лог сессии.' }
      }
      const name = match[1]
      // Skip the separator run between the name and the password, then keep the
      // remainder exactly as typed.
      const password = match[3]
      if (password.length === 0) {
        return { kind: 'error', text: `Пароль для "${name}" пуст. Использование: /ssh pass <имя> <пароль>` }
      }
      const entry = findEntry(hosts, name)
      if (entry === undefined) {
        const known = hosts.map((candidate) => candidate.name).join(', ')
        return { kind: 'error', text: `Неизвестный сервер "${name}". Зарегистрированы: ${known.length > 0 ? known : 'нет'}.` }
      }
      try {
        const document = readSecrets(resolved.secretsPath)
        await writeSecrets(resolved.secretsPath, setPassword(document.passwords, entry.name, password), {
          acl: aclOptions,
        })
      } catch (error) {
        return { kind: 'error', text: `Не удалось сохранить пароль: ${String(error?.message ?? error)}` }
      }
      // Never echo the password back; confirm by testing the connection instead.
      const verified = await testHost(entry, agent)
      return {
        kind: 'success',
        text:
          `Пароль для "${entry.name}" сохранён.\n` +
          `Файл: ${resolved.secretsPath}\n\n` +
          verified.text,
      }
    }

    /** Forget a stored password. */
    const nopassFlow = async (name) => {
      if (name.length === 0) return { kind: 'error', text: 'Использование: /ssh nopass <имя>' }
      const entry = findEntry(hosts, name)
      if (entry === undefined) return { kind: 'error', text: `Неизвестный сервер "${name}".` }
      try {
        const document = readSecrets(resolved.secretsPath)
        await writeSecrets(resolved.secretsPath, removePassword(document.passwords, entry.name), {
          acl: aclOptions,
        })
      } catch (error) {
        return { kind: 'error', text: `Не удалось изменить хранилище паролей: ${String(error?.message ?? error)}` }
      }
      return { kind: 'success', text: `Пароль для "${entry.name}" удалён. Дальше используется ключ или агент.` }
    }

    /** Interactive manual entry. */
    const addFlow = async (agent, signal) => {
      const userQuestions = ctx.get('userQuestions')
      if (userQuestions === undefined) return 'Для добавления сервера нужен доступный диалог вопросов.'
      const answer = await userQuestions.ask({
        agent,
        signal,
        questions: [
          { id: 'name', header: 'Имя', question: 'Короткое имя сервера (например web1):' },
          { id: 'host', header: 'Адрес', question: 'Адрес сервера или алиас из ~/.ssh/config:' },
          { id: 'user', header: 'Пользователь', question: 'Пользователь SSH (пусто — из конфигурации):' },
          { id: 'port', header: 'Порт', question: 'Порт SSH (пусто — 22):' },
          {
            id: 'key',
            header: 'Ключ',
            question: 'Путь к приватному ключу. Если ключа нет — оставьте пустым, пароль задаётся потом через /ssh pass:',
          },
          { id: 'description', header: 'Заметка', question: 'Заметка о сервере, необязательно (например «нет ключа, есть пароль»):' },
        ],
      })
      const field = (id) => decision(answer, id) ?? answer?.answers?.find((item) => item.id === id)?.custom
      try {
        const entry = normalizeEntry({
          name: field('name'),
          host: field('host'),
          user: field('user'),
          port: field('port'),
          identityFile: field('key'),
          description: field('description'),
          addedAt: new Date().toISOString(),
          addedBy: 'user',
        })
        await saveHosts(upsertEntry(hosts, entry, false))
        return `Сервер "${entry.name}" добавлен.`
      } catch (error) {
        return `Сервер не добавлен: ${String(error?.message ?? error)}`
      }
    }

    /**
     * Import servers discovered in the SSH config and render the outcome.
     *
     * Always returns display text: the picker path calls it directly, so a
     * structured return would leak an object into the command output.
     *
     * @returns the report to show the user.
     */
    const syncFlow = async () => {
      let text
      try {
        text = readFileSync(sshConfigPath, 'utf-8')
      } catch (error) {
        if (error?.code === 'ENOENT') return `Файл ${sshConfigPath} не найден. Добавьте сервер через /ssh add.`
        return `Не удалось прочитать ${sshConfigPath}: ${String(error?.message ?? error)}`
      }
      const { found, skipped } = parseSshConfig(text)
      if (found.length === 0) {
        return `В ${sshConfigPath} не найдено ни одного пригодного Host-блока. Пропущено: ${skipped.join(', ') || '—'}`
      }
      const merged = mergeDiscovered(hosts, found)
      try {
        await saveHosts(merged.hosts)
      } catch (error) {
        // Report the failure instead of throwing: an unhandled throw would abort
        // the whole command with no explanation of what went wrong.
        return describeWriteFailure(error)
      }
      const lines = [
        `Импортировано из ${sshConfigPath}: добавлено ${merged.added.length}, уже было ${found.length - merged.added.length}.`,
      ]
      if (merged.added.length > 0) lines.push('', `Добавлены: ${merged.added.join(', ')}`)
      if (skipped.length > 0) {
        lines.push(
          '',
          `Пропущены неподдерживаемые или шаблонные блоки: ${skipped.join(', ')}.`,
          'Include, Match и шаблоны с * не разворачиваются — добавьте такие серверы через /ssh add, чтобы адрес не оказался угаданным.',
        )
      }
      lines.push('', renderHosts())
      return lines.join('\n')
    }

    commandCtx.commands.register({
      name: 'ssh',
      description:
        'Выбрать сервер SSH, проверить подключение, добавить сервер, импортировать из ~/.ssh/config или сохранить пароль',
      // `input` is REQUIRED for this command to accept any argument at all.
      //
      // The Web client decides how to run a picked command by reading this
      // descriptor: with `input` present it "claims" the composer so the user can
      // type arguments; without it the command is run detached with no input, so
      // `/ssh pass ...` was never delivered to the handler and arrived as an
      // ordinary chat message instead. Omitting it made every subcommand
      // unreachable.
      //
      // `hint` is also what the menu displays after the name, and the client only
      // offers a command with a hint while the slash token is leading.
      input: {
        hint:
          '[имя | status | default <имя> | add | sync | test <имя> | pass <имя> <пароль> | nopass <имя> | lock <имя> | unlock <имя> | remove <имя>]',
      },
      // The `/ssh pass` password travels in this command's input. Declaring
      // `recordInput: false` keeps that input out of the `command/run` log event,
      // so the secret is not written into the session the agent can read.
      recordInput: false,
      handler: async ({ agent, rawInput, signal }) => {
        // Every failure path must return a CommandResult: the Host validates the
        // returned shape and a thrown error escapes as a failed command instead of
        // a readable message. A registry write that is denied is a normal
        // condition (read-only file, permissions), not a crash.
        try {
          loadHosts(true)

          // Detect `pass` on the UNTRIMMED input: a password may legitimately end
          // with a space, and trimming the line first would store a different
          // credential from the one the user typed.
          const raw = String(rawInput ?? '')
          const passMatch = /^\s*pass(?:\s+([\s\S]*))?$/.exec(raw)
          if (passMatch !== null) {
            return await passFlow(passMatch[1] ?? '', agent)
          }

          const argument = raw.trim()
          if (argument.length === 0) {
            const picked = await pickHost(agent, signal)
            return { kind: picked.kind, text: picked.text }
          }

          if (argument.startsWith('nopass')) {
            return await nopassFlow(argument.slice('nopass'.length).trim())
          }

          const [verb, ...rest] = argument.split(/\s+/)
          const target = rest.join(' ').trim()

          if (verb === 'add') {
            const text = await addFlow(agent, signal)
            // A server added without a key will need a password, so say so now
            // rather than leaving the user to discover it at the first connection.
            // The registry is re-read because addFlow wrote to it.
            const added = loadHosts(false).at(-1)
            if (added !== undefined && added.identityFile === undefined && !/не добавлен/.test(text)) {
              return {
                kind: 'success',
                text: `${text}\n\nКлюч не указан. Если на сервере его нет, сохраните пароль: /ssh pass ${added.name} <пароль>`,
              }
            }
            return { kind: 'success', text }
          }
          if (verb === 'sync') {
            return { kind: 'success', text: await syncFlow() }
          }
          if (verb === 'lock') {
            return await setLocked(target, true)
          }
          if (verb === 'unlock') {
            return await setLocked(target, false)
          }
          if (verb === 'status') {
            return { kind: 'success', text: renderStatus() }
          }
          if (verb === 'default') {
            return await setDefault(target)
          }
          if (verb === 'test') {
            if (target.length === 0) return { kind: 'error', text: 'Укажите имя сервера: /ssh test <имя>' }
            const entry = findEntry(hosts, target)
            if (entry === undefined) return { kind: 'error', text: `Неизвестный сервер "${target}".\n\n${renderHosts()}` }
            return { kind: 'success', text: (await testHost(entry, agent)).text }
          }
          if (verb === 'remove') {
            if (target.length === 0) return { kind: 'error', text: 'Укажите имя сервера: /ssh remove <имя>' }
            const entry = findEntry(hosts, target)
            if (entry === undefined) return { kind: 'error', text: `Неизвестный сервер "${target}".` }
            const wasDefault = preferred === entry.name
            try {
              // Clearing a default that named this server is part of removing it.
              // Leaving it behind made the plugin later claim "no default is set"
              // while a stale name sat in the file.
              await saveHosts(removeEntry(hosts, entry.name), wasDefault ? '' : preferred)
            } catch (error) {
              return { kind: 'error', text: describeWriteFailure(error) }
            }
            if (wasDefault) preferred = undefined
            return {
              kind: 'success',
              text: wasDefault
                ? `Сервер "${entry.name}" удалён из реестра. Он был по умолчанию, поэтому умолчание сброшено.`
                : `Сервер "${entry.name}" удалён из реестра.`,
            }
          }

          // A bare argument is a server name. This only CHECKS the server: making
          // it the default is a separate, deliberate action, so a routine
          // reachability test cannot silently redirect the tools.
          const entry = findEntry(hosts, argument)
          if (entry === undefined) return { kind: 'error', text: `Неизвестный сервер "${argument}".\n\n${renderHosts()}` }
          const checked = (await testHost(entry, agent)).text
          const isDefault = preferred === entry.name
          return {
            kind: 'success',
            text: isDefault
              ? checked
              : `${checked}\n\nСделать сервером по умолчанию:  /ssh default ${entry.name}`,
          }
        } catch (error) {
          // Nothing may escape: an unhandled throw becomes a failed command with
          // no explanation, which is exactly how a denied registry write looked
          // like a missing command.
          return { kind: 'error', text: String(error?.message ?? error) }
        }
      },
    })
  })

  loadHosts(false)
  // A crash can leave a password file in the scratch directory; clear it before
  // anything else. The cleanup is QUEUED rather than fire-and-forget, and
  // createAskpass waits on that queue: an unsequenced rm -rf races with the
  // first connection and breaks it.
  void queueAskpassCleanup(resolved.askpassDir)
  ctx.effect(() => () => {
    void queueAskpassCleanup(resolved.askpassDir)
  })
  ctx.logger.info(
    'ssh-remote: active, %d server(s) in %s, client %s',
    hosts.length,
    resolved.registryPath,
    resolved.sshPath,
  )
}

/**
 * Clamp a requested deadline into the configured bounds.
 *
 * An unbounded deadline would let one call hang a session indefinitely, so the
 * ceiling is always enforced; a missing value takes the configured default.
 *
 * @param requested - the caller's value, if any.
 * @param resolved - resolved plugin configuration.
 * @returns a usable deadline in milliseconds.
 */
function clampTimeout(requested, resolved) {
  if (requested === undefined) return resolved.defaultTimeoutMs
  if (!Number.isFinite(requested) || requested <= 0) {
    throw new SshRemoteError(`timeoutMs must be a positive number, got ${requested}.`, 'TIMEOUT_INVALID')
  }
  return Math.min(Math.floor(requested), resolved.maxTimeoutMs)
}
