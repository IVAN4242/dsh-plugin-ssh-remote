/**
 * Unit tests for the host-key helpers: fingerprint format, known_hosts parsing
 * and the append decision. No network and no files — the probe and the write
 * live in `index.js` and are covered through the page API in `test-ui.mjs`.
 */
import assert from 'node:assert/strict'

import { fingerprintOf, mergeKnownHosts, parseKnownHosts } from './hostkey.js'

// GitHub publishes this host key and its fingerprint, so the value is an
// external authority for "the number ssh-keygen would print", not a snapshot of
// whatever this code happened to compute.
const GITHUB_BLOB = 'AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'
const GITHUB_SHA256 = 'SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU'

let passed = 0
const failures = []
const ok = (label, body) => {
  try {
    body()
    passed += 1
  } catch (error) {
    failures.push({ label, error })
  }
}

ok('a fingerprint matches the one ssh-keygen prints', () => {
  assert.equal(fingerprintOf(GITHUB_BLOB), GITHUB_SHA256)
})

ok('a blob that is not base64 has no fingerprint', () => {
  assert.equal(fingerprintOf('not a key !!'), undefined)
  assert.equal(fingerprintOf(''), undefined)
  assert.equal(fingerprintOf(undefined), undefined)
})

ok('parsing keeps usable lines and ignores the rest', () => {
  const text = [
    '# a comment',
    '',
    `example.com ssh-ed25519 ${GITHUB_BLOB}`,
    `[example.com]:2222 ssh-ed25519 ${GITHUB_BLOB}`,
    'only-two-fields ssh-ed25519',
    `hashed.example |1|abcdef=|ghijkl= ssh-ed25519 ${GITHUB_BLOB}`,
    'bad.example ssh-ed25519 !!!notbase64',
  ].join('\n')
  const keys = parseKnownHosts(text)
  assert.equal(keys.length, 2)
  assert.equal(keys[0].hostField, 'example.com')
  assert.equal(keys[0].fingerprint, GITHUB_SHA256)
  assert.equal(keys[1].hostField, '[example.com]:2222')
  // A hashed line (`HashKnownHosts yes`) carries no readable address, so it is
  // skipped: nothing here could match it, and pretending otherwise would let the
  // merge believe an address already has a key of a different type.
})

ok('a new key is appended and a recorded one is not duplicated', () => {
  const key = { hostField: 'example.com', type: 'ssh-ed25519', blob: GITHUB_BLOB, fingerprint: GITHUB_SHA256 }
  const line = `example.com ssh-ed25519 ${GITHUB_BLOB}`

  const empty = mergeKnownHosts('', [key])
  assert.deepEqual(empty.added, [line])
  assert.equal(empty.text, `${line}\n`)

  // No trailing newline in the existing file: the separator must be added, or
  // the first appended line would glue itself onto the previous one.
  const glued = mergeKnownHosts(`other.example ssh-ed25519 ${GITHUB_BLOB}`, [key])
  assert.equal(glued.text, `other.example ssh-ed25519 ${GITHUB_BLOB}\n${line}\n`)

  const again = mergeKnownHosts(`${line}\n`, [key])
  assert.deepEqual(again.added, [])
  assert.equal(again.text, `${line}\n`)
})

ok('a different key for the same address is a conflict, never an append', () => {
  // This is the changed-key case. A "trust" button must not turn it into an
  // accepted entry: that is exactly the warning the plugin exists to keep.
  const other = 'AAAAC3NzaC1lZDI1NTE5AAAAIOtherKeyBlobThatIsDifferent0000000000000'
  const merged = mergeKnownHosts(`example.com ssh-ed25519 ${other}\n`, [
    { hostField: 'example.com', type: 'ssh-ed25519', blob: GITHUB_BLOB, fingerprint: GITHUB_SHA256 },
  ])
  assert.deepEqual(merged.added, [])
  assert.deepEqual(merged.conflict, { hostField: 'example.com', type: 'ssh-ed25519' })
})

for (const failure of failures) {
  console.error(`✗ ${failure.label}`)
  console.error(failure.error)
}
console.log(`\n${passed} passed, ${failures.length} failed`)
if (failures.length > 0) process.exitCode = 1
