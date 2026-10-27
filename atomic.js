/**
 * Atomic file replacement, with the retry Windows needs.
 *
 * Every persisted file here is written to a unique temporary name and renamed
 * over the target: `rename` is atomic within one volume, so a reader sees either
 * the old document or the new one, never a half-written file.
 *
 * On Windows the rename itself can fail with `EPERM`, `EACCES` or `EBUSY` even
 * though nothing is wrong with the paths: an antivirus scanner, the search
 * indexer or a backup agent can hold the destination open for a few
 * milliseconds after it was last written. Treating that as a hard failure turned
 * a routine registry save into an error the user could not act on. Retrying a
 * few times with a growing pause rides out the transient holder; a genuine
 * permission problem still surfaces, because it keeps failing and the last error
 * is rethrown unchanged.
 *
 * @module dsh-plugin-ssh-remote/atomic
 */

import { rename } from 'node:fs/promises'

/** Errors that mean "someone else held the file for a moment", not "denied". */
const TRANSIENT = new Set(['EPERM', 'EACCES', 'EBUSY'])

/** Total rename attempts. Five tries over ~300 ms is invisible to a user. */
const ATTEMPTS = 5

/** Base pause in milliseconds; each retry waits one step longer. */
const STEP_MS = 20

/**
 * Rename `temporary` over `target`, retrying transient Windows failures.
 *
 * The temporary file is left in place when every attempt fails, so the caller
 * can decide whether to clean it up; nothing is ever written into `target`
 * partially.
 *
 * @param temporary - the fully written temporary file.
 * @param target - the file it should become.
 */
export async function replaceFile(temporary, target) {
  let lastError
  for (let attempt = 0; attempt < ATTEMPTS; attempt += 1) {
    try {
      await rename(temporary, target)
      return
    } catch (error) {
      if (!TRANSIENT.has(error?.code)) throw error
      lastError = error
      if (attempt < ATTEMPTS - 1) {
        await new Promise((resolve) => setTimeout(resolve, STEP_MS * (attempt + 1)))
      }
    }
  }
  throw lastError
}
