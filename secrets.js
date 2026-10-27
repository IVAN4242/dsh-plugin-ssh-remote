/**
 * The password store: per-server passwords, kept in the plugin's own file
 * inside the Harness home.
 *
 * Scope and honesty about the threat model:
 *  - Only `/ssh pass` writes here. No tool the model can call accepts a
 *    password, so the agent cannot add or read one.
 *  - The file is chmod 600 where the platform honours it. On Windows `chmod` is a
 *    no-op, so the file's ACL is tightened with `icacls` instead: inherited
 *    entries are removed and the owning account is granted full control. That
 *    leaves your account and administrators, not every process of every user.
 *  - A process running as your OS user can still read this file. That is inherent
 *    to a file-backed store; the agent's tools run as you. Passwords are kept here
 *    because the alternative — typing one at every connection — is worse, not
 *    because this is a security boundary.
 *  - Keys remain strongly preferred. A stored password is a fallback for servers
 *    where no key is installed yet.
 *
 * @module dsh-plugin-ssh-remote/secrets
 */

import { randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { chmod, mkdir, rm, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { hardenPathAcl } from './acl.js'
import { replaceFile } from './atomic.js'

/** On-disk shape version, so a future change can migrate deliberately. */
export const SECRETS_VERSION = 1

/**
 * The default password store location inside the Harness home.
 *
 * @param home - the Harness home directory.
 * @returns an absolute file path.
 */
export function defaultSecretsPath(home) {
  return join(home, 'ssh-remote-secrets.json')
}

/**
 * Tighten a file's permissions where the platform supports it.
 *
 * On POSIX this is the real protection. On Windows `chmod` cannot express
 * owner-only access at all, so the ACL path is used instead (see {@link hardenAcl})
 * and a failure here is swallowed rather than reported as a guarantee that was
 * never available.
 *
 * @param path - the file to restrict.
 */
async function restrictPermissions(path) {
  try {
    await chmod(path, 0o600)
  } catch {
    // Windows cannot express this; the ACL is what protects the file there.
  }
}

/**
 * Tighten the Windows ACL of one path, best effort.
 *
 * @param path - the file or directory to restrict.
 * @param options - resolved plugin ACL options (logger, runner, platform).
 */
async function hardenAcl(path, options) {
  if (options === undefined) return
  await hardenPathAcl(path, options)
}

/**
 * Read the password store.
 *
 * A missing file is the normal first run. A malformed file yields no passwords
 * and a problem description: guessing at a damaged secret store could silently
 * connect with the wrong credential, so the failure is surfaced instead.
 *
 * @param path - the store file.
 * @returns stored passwords, keyed by server name, plus an optional problem.
 */
export function readSecrets(path) {
  let raw
  try {
    raw = readFileSync(path, 'utf-8')
  } catch (error) {
    if (error?.code === 'ENOENT') return { passwords: {} }
    return { passwords: {}, problem: `The password store could not be read: ${String(error?.message ?? error)}` }
  }
  let parsed
  try {
    parsed = JSON.parse(raw)
  } catch (error) {
    return {
      passwords: {},
      problem:
        `The password store at ${path} is not valid JSON (${String(error?.message ?? error)}), so no stored password is used. ` +
        'Fix or delete the file, then run /ssh pass again.',
    }
  }
  const passwords = {}
  const source = parsed?.passwords
  if (source !== undefined && typeof source === 'object' && source !== null) {
    for (const [name, value] of Object.entries(source)) {
      // An empty value is treated as absent: a blank can never masquerade as a
      // configured password, matching the convention of the built-in store.
      if (typeof value === 'string' && value.length > 0) passwords[name] = value
    }
  }
  return { passwords }
}

/**
 * Persist the password store atomically.
 *
 * The temporary name carries the pid and a random id. A fixed `${path}.tmp` was
 * shared by every process of this user, so the desktop and the web profile (or a
 * second Harness instance) overwrote each other's temporary file and one rename
 * carried away the other's write.
 *
 * @param path - the store file.
 * @param passwords - passwords keyed by server name.
 * @param options - `acl` options for the Windows ACL pass.
 */
export async function writeSecrets(path, passwords, options = {}) {
  await mkdir(dirname(path), { recursive: true })
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`
  await writeFile(temporary, `${JSON.stringify({ version: SECRETS_VERSION, passwords }, null, 2)}\n`, {
    encoding: 'utf-8',
    mode: 0o600,
  })
  await restrictPermissions(temporary)
  // Hardened BEFORE the rename: the rename keeps the ACL, and doing it afterwards
  // would leave the passwords readable through the inherited profile ACL for the
  // few milliseconds the file exists under its final name.
  await hardenAcl(temporary, options.acl)
  // `rename` is atomic on the same volume, so a reader never sees a partial file.
  // The helper retries the transient Windows failures instead of failing the save.
  await replaceFile(temporary, path)
  await restrictPermissions(path)
}

/**
 * Store one password, replacing any previous value for that server.
 *
 * @param passwords - the current map.
 * @param name - the server name.
 * @param value - the password.
 * @returns an updated map.
 */
export function setPassword(passwords, name, value) {
  return { ...passwords, [name]: value }
}

/**
 * Forget one password.
 *
 * @param passwords - the current map.
 * @param name - the server name.
 * @returns an updated map.
 */
export function removePassword(passwords, name) {
  const next = { ...passwords }
  delete next[name]
  return next
}

/**
 * Delete the transient askpass scratch directory.
 *
 * Called on activation and disposal so a crash cannot leave a password file
 * behind for the next run to trip over.
 *
 * @param directory - the scratch directory.
 */
export async function clearAskpassDirectory(directory) {
  try {
    await rm(directory, { recursive: true, force: true })
  } catch {
    // A leftover scratch file is harmless once the directory is recreated.
  }
}

/**
 * Serializes scratch-directory cleanup against password creation.
 *
 * Activation cleanup is inherently concurrent with whatever the session does
 * next, and an unsequenced `rm -rf` of the root will happily delete a
 * subdirectory a connection is writing into — which surfaces as an opaque "file
 * not found" from Windows and a failed login. Every cleanup is therefore chained
 * here, and {@link createAskpass} waits for that chain.
 */
let cleanupBarrier = Promise.resolve()

/**
 * Queue a cleanup that all later password creation will wait for.
 *
 * @param directory - the scratch root to remove.
 * @returns a promise that settles when the cleanup has run.
 */
export function queueAskpassCleanup(directory) {
  cleanupBarrier = cleanupBarrier.then(
    () => clearAskpassDirectory(directory),
    () => clearAskpassDirectory(directory),
  )
  return cleanupBarrier
}

/**
 * Create the transient material that lets OpenSSH read one password.
 *
 * Why this shape: Windows has no `sshpass`, and passing a password as an
 * argument or an SSH option would expose it in the process list where any user
 * can read it. OpenSSH instead asks an `SSH_ASKPASS` program for the secret, and
 * that program is executed with the invoking process's environment. So the
 * password goes into a file, and the helper prints the file.
 *
 * The helper uses `type` (Windows) or `cat` (POSIX), neither of which interprets
 * the file's contents — which is what makes an arbitrary password, including one
 * containing `%`, `&` or quotes, safe to deliver. Writing the password into the
 * batch file itself would let a `%` or `&` execute.
 *
 * The scratch directory lives under the Harness home rather than the system temp
 * directory: on POSIX `/tmp` is world-writable, which would invite a symlink
 * attack against a file that holds a password.
 *
 * Per-call subdirectories are used rather than one shared directory. A cleanup
 * that removes the directory while a later call is writing into it is a race
 * that breaks the connection; giving each call its own directory means cleanup
 * can never touch another call's files.
 *
 * @param directory - the scratch root directory.
 * @param password - the password to deliver.
 * @param options - `acl` options for the Windows ACL pass.
 * @returns environment variables for the client and a cleanup function.
 */
export async function createAskpass(directory, password, options = {}) {
  // Wait out any queued cleanup before writing, so a concurrent `rm -rf` of the
  // root cannot delete this call's directory or files mid-flight.
  await cleanupBarrier.catch(() => {})
  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`
  const own = join(directory, id)
  // `recursive` makes this safe even if the root was just removed.
  await mkdir(own, { recursive: true })
  // The directory is hardened before the files exist: the inheritable grant then
  // covers `secret` and the shim, which live for the length of one connection.
  await hardenAcl(own, { ...options.acl, inheritable: true })
  const secretPath = join(own, 'secret')
  const shimPath = join(own, process.platform === 'win32' ? 'askpass.cmd' : 'askpass.sh')

  // The trailing newline is what `type` and `cat` emit as a line for ssh to read.
  await writeFile(secretPath, `${password}\n`, { encoding: 'utf-8', mode: 0o600 })
  await restrictPermissions(secretPath)

  const shim =
    process.platform === 'win32'
      ? '@echo off\r\ntype "%DSH_SSH_ASKPASS_FILE%"\r\n'
      : '#!/bin/sh\nexec cat "$DSH_SSH_ASKPASS_FILE"\n'
  await writeFile(shimPath, shim, { encoding: 'utf-8', mode: 0o700 })
  await restrictPermissions(shimPath)

  return {
    env: {
      // The client runs the helper instead of prompting on a terminal.
      SSH_ASKPASS: shimPath,
      // `force` makes the helper authoritative even with no terminal and no
      // DISPLAY, so the prompt can never fall through to an interactive one
      // that nothing would answer.
      SSH_ASKPASS_REQUIRE: 'force',
      DSH_SSH_ASKPASS_FILE: secretPath,
    },
    /** Remove this call's files; safe to call more than once. */
    async cleanup() {
      await rm(own, { recursive: true, force: true })
    },
  }
}
