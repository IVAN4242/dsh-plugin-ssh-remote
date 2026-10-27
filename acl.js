/**
 * Owner-only access control for the plugin's own files, including Windows.
 *
 * `chmod` cannot express "this file is mine alone" on Windows: it is a no-op
 * there, so `ssh-remote-secrets.json` inherited whatever the profile directory
 * granted, and any process running as the same user could read it. `icacls`
 * speaks the Windows ACL model, so it is used to remove inherited entries and
 * grant the owning account full control.
 *
 * Design rules:
 *  - No shell: the argv is passed to `spawn` directly, so a path containing
 *    spaces, quotes or `&` cannot turn into a command.
 *  - Best effort: a failure is logged and swallowed. Failing to tighten an ACL
 *    must never fail the write of a password, because then the connection would
 *    break for a reason that has nothing to do with the credential.
 *  - The executable output is not collected: only the exit code matters, and
 *    capturing stdio across a process boundary is denied by the DSH sandbox.
 *
 * @module dsh-plugin-ssh-remote/acl
 */

import { spawn } from 'node:child_process'
import { userInfo } from 'node:os'

/** How long `icacls` is given before it is killed. */
export const ACL_TIMEOUT_MS = 5_000

/**
 * Build `DOMAIN\User` from the account that owns the file.
 *
 * The environment is consulted only for the domain and a fallback name: the
 * authoritative name comes from the OS, so an inherited `USERNAME` from another
 * context cannot grant the wrong account access.
 *
 * @param env - environment to read the domain from.
 * @param username - the account name; defaults to the current user.
 * @returns the identity string, or undefined when no name is available.
 */
export function windowsIdentity(env = process.env, username) {
  let name = username
  if (name === undefined) {
    try {
      name = userInfo().username
    } catch {
      name = env.USERNAME
    }
  }
  if (typeof name !== 'string' || name.length === 0) return undefined
  const domain = env.USERDOMAIN
  return typeof domain === 'string' && domain.length > 0 ? `${domain}\\${name}` : name
}

/**
 * Build the `icacls` argument list that makes a path owner-only.
 *
 * For a directory the grant is marked inheritable (`(OI)(CI)`), which is what
 * protects files created inside it afterwards — the askpass scratch directory
 * exists for a few seconds but holds a password during exactly those seconds.
 *
 * @param path - the file or directory to restrict.
 * @param identity - `DOMAIN\User`.
 * @param options - `inheritable: true` for a directory.
 * @returns the argv, ready to spawn without a shell.
 */
export function icaclsArgv(path, identity, options = {}) {
  const grant = options.inheritable === true ? `${identity}:(OI)(CI)F` : `${identity}:F`
  return ['icacls', String(path), '/inheritance:r', '/grant:r', grant]
}

/**
 * Run a program with no captured streams and a deadline.
 *
 * @param argv - the complete argument list.
 * @param timeoutMs - how long to wait before killing it.
 * @returns the exit code, or -1 when it had to be killed.
 */
export function runIgnored(argv, timeoutMs = ACL_TIMEOUT_MS) {
  return new Promise((resolve, reject) => {
    let child
    try {
      child = spawn(argv[0], argv.slice(1), { stdio: 'ignore', windowsHide: true })
    } catch (error) {
      reject(error)
      return
    }
    const timer = setTimeout(() => {
      try {
        child.kill()
      } catch {
        // Already gone; the exit event settles the promise.
      }
      resolve(-1)
    }, timeoutMs)
    child.on('error', (error) => {
      clearTimeout(timer)
      reject(error)
    })
    child.on('close', (code) => {
      clearTimeout(timer)
      resolve(code ?? -1)
    })
  })
}

/**
 * Restrict a path to its owner where the platform has a real ACL model.
 *
 * @param path - the file or directory to restrict.
 * @param options - platform, identity, runner, logger and timeout overrides.
 * @returns whether the restriction was applied, plus the argv used.
 */
export async function hardenPathAcl(path, options = {}) {
  const platform = options.platform ?? process.platform
  // On POSIX a mode change is the correct mechanism, and it is already applied by
  // the caller; running icacls there would just fail.
  if (platform !== 'win32') return { applied: false, reason: 'not windows' }
  const identity = options.identity ?? windowsIdentity(options.env ?? process.env, options.username)
  if (identity === undefined) return { applied: false, reason: 'no user identity' }
  const argv = icaclsArgv(path, identity, { inheritable: options.inheritable === true })
  const run = options.run ?? runIgnored
  const timeoutMs = options.timeoutMs ?? ACL_TIMEOUT_MS
  try {
    const exitCode = await run(argv, timeoutMs)
    if (exitCode !== 0) {
      options.logger?.warn('ssh-remote: could not restrict access to %s (icacls exited %s)', path, exitCode)
      return { applied: false, argv, exitCode }
    }
    return { applied: true, argv, exitCode }
  } catch (error) {
    // A missing icacls or a denied call is not worth failing a password write.
    options.logger?.warn('ssh-remote: could not restrict access to %s: %s', path, String(error?.message ?? error))
    return { applied: false, argv, error }
  }
}
