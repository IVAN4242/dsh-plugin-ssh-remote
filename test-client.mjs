/**
 * Smoke test for the Client half outside a browser: load the module through the
 * module-loader hook, run `apply` against a fake Cordis context, and call the
 * section component once to catch reference errors on the empty path.
 *
 * Not a render test — no DOM, no layout. It proves the file parses, the factory
 * and apply contract are wired, and the slot/locale registrations are what the
 * page expects.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

let captured
globalThis.window = {
  __ModuleLoader__: {
    load(entry) {
      captured = entry
    },
  },
}

const React = {
  createElement(type, props, ...children) {
    return { type, props: props ?? {}, children }
  },
  Fragment: Symbol('Fragment'),
  useState(initial) {
    return [typeof initial === 'function' ? initial() : initial, () => {}]
  },
  useEffect() {},
  useCallback(fn) {
    return fn
  },
  useMemo(fn) {
    return fn()
  },
  useRef(value) {
    return { current: value }
  },
}

const source = readFileSync(new URL('./client.js', import.meta.url), 'utf-8')
// The bundle is a script for the page, so evaluate it with a module-owned
// `window` shim rather than importing it.
const runner = new Function('window', 'require', `${source}\n`)
runner(globalThis.window, (specifier) => {
  if (specifier === 'react') return React
  throw new Error(`unexpected require: ${specifier}`)
})

assert.ok(captured !== undefined, 'the module did not register a factory')
assert.equal(captured.id, 'dsh-plugin-ssh-remote')

const plugin = captured.factory((specifier) => {
  if (specifier === 'react') return React
  throw new Error(`unexpected factory require: ${specifier}`)
})

assert.deepEqual(plugin.inject, ['slots', 'locale'])

/** Collected registrations. */
const registers = []
const dictionaries = []
const subscribed = []
const disposers = []

const locale = {
  register(ns, id, dict) {
    dictionaries.push({ ns, id, dict })
    return () => {}
  },
  bind(ns) {
    return (key) => (dictionaries.find((entry) => entry.ns === ns && entry.id === 'en')?.dict[key] ?? `?${key}`)
  },
  subscribe(listener) {
    subscribed.push(listener)
    return () => {}
  },
}

const slots = {
  inject(key, callback) {
    assert.equal(key, 'settings.section')
    const dispose = callback()
    disposers.push(dispose)
    return () => {}
  },
  register(options, factory) {
    registers.push({ options, factory })
    return () => {}
  },
}

const ctx = {
  locale,
  slots,
  effect(callback) {
    const dispose = callback()
    disposers.push(dispose)
    return dispose
  },
}

plugin.apply(ctx)

assert.equal(dictionaries.length, 2, 'both dictionaries must register')
assert.deepEqual(dictionaries.map((entry) => entry.id).sort(), ['en', 'ru'])
assert.equal(registers.length, 1)
assert.equal(registers[0].options.name, 'settings.section')
assert.equal(registers[0].options.id, 'ssh-remote')
assert.equal(registers[0].options.order, 35)
assert.equal(typeof registers[0].options.label, 'function')
assert.equal(registers[0].options.label(), 'SSH')

// The component must build its tree without touching a browser global: the
// empty path is what a fresh profile shows first.
const element = registers[0].factory({})
const tree = element.type({ t: registers[0].options.label.__t ?? ((key) => key), locale })
assert.equal(tree.type, 'section')
assert.ok(Array.isArray(tree.children))

// Every locale key used by the component exists in both dictionaries.
const [en, ru] = [
  dictionaries.find((entry) => entry.id === 'en').dict,
  dictionaries.find((entry) => entry.id === 'ru').dict,
]
const enKeys = Object.keys(en).sort()
const ruKeys = Object.keys(ru).sort()
assert.deepEqual(ruKeys, enKeys, 'the Russian dictionary must cover every English key')

console.log(`client smoke ok: ${enKeys.length} locale keys, section "${registers[0].options.id}" at order ${registers[0].options.order}`)

// ---------- render with data ----------

/** The registry projection the Host returns, exercised card by card. */
const DATA = {
  ok: true,
  default: 'web1',
  warnings: ['one repaired row'],
  paths: { registry: 'C:/home/hosts.json', sshConfig: 'C:/home/.ssh/config', sshClient: 'C:/ssh.exe' },
  servers: [
    {
      name: 'web1', host: '203.0.113.9', user: 'root', port: 2222,
      identityFile: '~/.ssh/id_ed25519', workspace: '/srv/app', description: 'production',
      addedAt: '2026-01-01T00:00:00.000Z', addedBy: 'ui', locked: true, isDefault: true, hasPassword: true,
    },
    {
      name: 'db', host: 'db.example', user: null, port: 22,
      identityFile: null, workspace: null, description: null,
      addedAt: null, addedBy: null, locked: false, isDefault: false, hasPassword: false,
    },
  ],
}

const dataReact = {
  ...React,
  useState(initial) {
    const value = typeof initial === 'function' ? initial() : initial
    if (value !== null && typeof value === 'object' && 'status' in value && 'data' in value) {
      return [{ status: 'ready', data: DATA, error: undefined }, () => {}]
    }
    return [value, () => {}]
  },
}

let capturedData
globalThis.window.__ModuleLoader__.load = (entry) => {
  capturedData = entry
}
new Function('window', 'require', `${source}\n`)(globalThis.window, (specifier) => {
  if (specifier === 'react') return dataReact
  throw new Error(`unexpected require: ${specifier}`)
})
const dataPlugin = capturedData.factory((specifier) => {
  if (specifier === 'react') return dataReact
  throw new Error(`unexpected factory require: ${specifier}`)
})

const dataRegisters = []
const dataLocale = {
  register: () => () => {},
  bind: () => (key) => key,
  subscribe: () => () => {},
}
dataPlugin.apply({
  locale: dataLocale,
  slots: { inject: (_key, callback) => callback(), register: (options, factory) => { dataRegisters.push({ options, factory }); return () => {} } },
  effect: (callback) => callback(),
})

const rendered = dataRegisters[0].factory({}).type({ t: (key) => key, locale: dataLocale })

/**
 * Render every function component in the tree once, so a card's own code runs
 * on both a fully populated server and a bare one.
 */
function renderAll(node, depth = 0) {
  if (node === null || node === undefined || typeof node !== 'object') return
  if (Array.isArray(node)) {
    for (const child of node) renderAll(child, depth)
    return
  }
  if (depth > 30) throw new Error('render tree is too deep')
  if (typeof node.type === 'function') {
    const child = node.type(node.props)
    renderAll(child, depth + 1)
    return
  }
  renderAll(node.children, depth + 1)
}

renderAll(rendered)

/** Collect every string leaf of the tree. */
function texts(node, out = []) {
  if (node === null || node === undefined) return out
  if (typeof node === 'string' || typeof node === 'number') {
    out.push(String(node))
    return out
  }
  if (Array.isArray(node)) {
    for (const child of node) texts(child, out)
    return out
  }
  if (typeof node === 'object') {
    texts(node.children, out)
    if (typeof node.type === 'function') {
      // Already rendered above; read the rendered text instead of the props.
      texts(node.type(node.props), out)
    }
  }
  return out
}

const leaves = texts(rendered).join(' | ')
for (const expected of ['web1', '203.0.113.9', 'db.example', 'C:/home/hosts.json', 'one repaired row']) {
  assert.ok(leaves.includes(expected), `the rendered tree is missing ${expected}`)
}

console.log('client render ok: both a populated and a bare server rendered')

// ---------- render the form and the delete confirmation ----------

/** Render the section with one hook slot overridden, as if the user interacted. */
function renderWithHook(overrides) {
  let call = 0
  const react = {
    ...React,
    useState(initial) {
      const index = call
      call += 1
      if (index in overrides) return [overrides[index], () => {}]
      const value = typeof initial === 'function' ? initial() : initial
      if (value !== null && typeof value === 'object' && 'status' in value && 'data' in value) {
        return [{ status: 'ready', data: DATA, error: undefined }, () => {}]
      }
      return [value, () => {}]
    },
    useEffect() {},
    useCallback(fn) {
      return fn
    },
  }
  let entry
  globalThis.window.__ModuleLoader__.load = (loadEntry) => {
    entry = loadEntry
  }
  new Function('window', 'require', `${source}\n`)(globalThis.window, (specifier) => {
    if (specifier === 'react') return react
    throw new Error(`unexpected require: ${specifier}`)
  })
  const plugin = entry.factory((specifier) => {
    if (specifier === 'react') return react
    throw new Error(`unexpected factory require: ${specifier}`)
  })
  const registers = []
  const locale = { register: () => () => {}, bind: () => (key) => key, subscribe: () => () => {} }
  plugin.apply({
    locale,
    slots: { inject: (_key, callback) => callback(), register: (options, factory) => { registers.push({ options, factory }); return () => {} } },
    effect: (callback) => callback(),
  })
  return { tree: registers[0].factory({}).type({ t: (key) => key, locale }), t: (key) => key }
}

// Hook order in SettingsSection: 0 state, 1 busy, 2 notice, 3 tests, 4 editor,
// 5 confirmRemove, 6 locale revision.
const addForm = renderWithHook({ 4: { mode: 'add' } })
renderAll(addForm.tree)
const addLeaves = texts(addForm.tree).join(' | ')
for (const expected of ['addTitle', 'fieldName', 'fieldHost', 'fieldPort', 'fieldKey', 'password', 'passwordHint', 'save', 'cancel']) {
  assert.ok(addLeaves.includes(expected), `the add form is missing ${expected}`)
}

const editForm = renderWithHook({ 4: { mode: 'edit', server: DATA.servers[0] } })
renderAll(editForm.tree)
const editLeaves = texts(editForm.tree).join(' | ')
for (const expected of ['editTitle', 'fieldKey', 'password', 'passwordForget', 'passwordHint']) {
  assert.ok(editLeaves.includes(expected), `the edit form is missing ${expected}`)
}

const confirm = renderWithHook({ 5: 'web1' })
renderAll(confirm.tree)
const confirmLeaves = texts(confirm.tree).join(' | ')
assert.ok(confirmLeaves.includes('confirmRemove'), 'the delete confirmation is missing')

console.log('client forms ok: add, edit (with password controls) and delete confirmation render')

// A failed test whose code is HOST_KEY_UNKNOWN must offer the one-time trust,
// while a changed key must NOT: that distinction is the point of the classifier.
const firstConnect = renderWithHook({ 3: { web1: { state: 'error', code: 'HOST_KEY_UNKNOWN', text: 'not confirmed' } } })
renderAll(firstConnect.tree)
assert.ok(texts(firstConnect.tree).join(' | ').includes('trustKey'), 'no trust action for an unknown key')

const changedKey = renderWithHook({ 3: { web1: { state: 'error', code: 'HOST_KEY_CHANGED', text: 'changed' } } })
renderAll(changedKey.tree)
assert.ok(!texts(changedKey.tree).join(' | ').includes('trustKey'), 'a changed key must not offer a trust button')

const keyConfirm = renderWithHook({
  6: { name: 'web1', state: 'confirm', keys: [{ type: 'ssh-ed25519', fingerprint: 'SHA256:abc' }] },
})
renderAll(keyConfirm.tree)
const keyLeaves = texts(keyConfirm.tree).join(' | ')
assert.ok(keyLeaves.includes('SHA256:abc'), 'the fingerprint is not shown before trusting')
assert.ok(keyLeaves.includes('trustKeyConfirm'), 'no confirm action for the fingerprint')

console.log('client trust flow ok: unknown key offers confirmation, changed key does not')


