/**
 * The action log: one JSON line per remote client invocation.
 *
 * Why it exists: with root on several machines, "what did the agent do
 * yesterday" had no answer. Output lives in a session and sessions are deleted;
 * this file is the durable record of what was run where and how it ended.
 *
 * Rules:
 *  - The command is REDACTED before it is written. A log that captures a secret
 *    is a secret leak with extra steps, so redaction happens inside this module
 *    rather than at a call site that could forget it.
 *  - A failure to write never fails the operation. The log is an audit aid, not a
 *    gate; an unwritable file is reported by the caller's logger and the command's
 *    result still travels to the model.
 *  - Writes are serialized and rotated by size, so two conversations cannot
 *    interleave a line and the file cannot grow without a bound.
 *
 * @module dsh-plugin-ssh-remote/audit
 */

import { appendFile, mkdir, rename, rm, stat } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { redact } from './args.js'

/** Rotation threshold; past this the file becomes `<path>.1` and starts over. */
export const AUDIT_ROTATE_BYTES = 10 * 1024 * 1024

/** How much of the command is kept. Enough to recognise it, not a transcript. */
export const AUDIT_COMMAND_CHARS = 200

/**
 * The default audit log location inside the Harness home.
 *
 * @param home - the Harness home directory.
 * @returns an absolute file path.
 */
export function defaultAuditPath(home) {
  return join(home, 'ssh-remote-audit.jsonl')
}

/**
 * Build one audit record from an invocation's facts.
 *
 * Newlines inside a command are folded to spaces so a single record stays one
 * readable, `jq`-friendly line.
 *
 * @param input - the invocation facts.
 * @returns the record to serialize.
 */
export function buildAuditRecord(input = {}) {
  const command = redact(input.command ?? '')
    .text.replace(/\s+/g, ' ')
    .trim()
    .slice(0, AUDIT_COMMAND_CHARS)
  return {
    ts: input.ts ?? new Date().toISOString(),
    server: input.server ?? '',
    host: input.host ?? '',
    tool: input.tool ?? 'ssh',
    command,
    exitCode: input.exitCode ?? null,
    durationMs: Math.max(0, Math.round(input.durationMs ?? 0)),
    timedOut: input.timedOut === true,
    passwordAuth: input.passwordAuth === true,
  }
}

/** Serializes appends, so rotation cannot race a write from another call. */
let appendChain = Promise.resolve()

/**
 * Append one record, rotating the file when it has outgrown its budget.
 *
 * @param path - the audit file.
 * @param record - the record to append.
 * @param options - optional `maxBytes` override, mainly for tests.
 */
export async function appendAudit(path, record, options = {}) {
  const maxBytes = options.maxBytes ?? AUDIT_ROTATE_BYTES
  const line = `${JSON.stringify(record)}\n`
  const write = async () => {
    await mkdir(dirname(path), { recursive: true })
    try {
      const info = await stat(path)
      if (info.size > 0 && info.size + Buffer.byteLength(line, 'utf-8') > maxBytes) {
        const archive = `${path}.1`
        // Windows refuses to rename onto an existing file, so the previous
        // archive is removed first; keeping two rotations is out of scope.
        await rm(archive, { force: true })
        await rename(path, archive)
      }
    } catch (error) {
      // A missing file is the normal first write; any other stat failure must
      // not stop the append itself.
      if (error?.code !== 'ENOENT') throw error
    }
    await appendFile(path, line, { encoding: 'utf-8' })
  }
  // Chained on both outcomes so one failed write does not wedge every later one.
  appendChain = appendChain.then(write, write)
  return appendChain
}
