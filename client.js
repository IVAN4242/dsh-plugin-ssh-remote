/**
 * SSH Remote — Client half: the server manager in Settings.
 *
 * A Terminus-like list of the servers this profile may SSH into: add, edit,
 * forget, set the default, lock, run a connection test, import from
 * `~/.ssh/config`, and store a password. The page is a `settings.section`
 * entry, so it appears as "SSH" in the Settings sidebar beside General and
 * Models.
 *
 * Data and actions travel over one exact route, `/api/ssh-remote`, which the
 * Host half registers on the Connection Fetch handler. That route is behind the
 * host's own login fence and refuses every non-owner Peer, so this half does
 * no authentication of its own and holds no credential: the registry, the
 * password store and the probe stay on the Host, where `/ssh` and the agent
 * tools already use them.
 *
 * Loaded by the browser module system: the factory id must equal the package
 * name, and React comes from the browser module table rather than a bundled
 * copy. No JSX, no imports, no build step.
 */
window.__ModuleLoader__.load({
  id: 'dsh-plugin-ssh-remote',
  factory(require) {
    const React = require('react')
    const h = React.createElement

    /** Locale namespace owned by this plugin. */
    const NS = 'ssh-remote'

    /** Exact route the Host half mounts on Connection's Fetch handler. */
    const API = '/api/ssh-remote'

    /** German-style baseline dictionaries: English plus Russian. */
    const EN = {
      nav: 'SSH',
      title: 'SSH servers',
      intro:
        'Servers this agent may reach over SSH. The registry is the allowlist: only the names listed here are connectable, '
        + 'and every command runs with the authority of your SSH key.',
      add: 'Add server',
      refresh: 'Refresh',
      import: 'Import from ~/.ssh/config',
      empty: 'No servers are registered yet.',
      emptyHint: 'Add one, or import the hosts already present in your SSH config.',
      loading: 'Loading…',
      loadFailed: 'The registry could not be read.',
      retry: 'Retry',
      badgeDefault: 'default',
      badgeLocked: 'locked',
      badgeKey: 'key',
      badgePassword: 'password',
      badgeNoAuth: 'no key or password',
      test: 'Test',
      testing: 'Testing…',
      testOk: 'Connection works.',
      edit: 'Edit',
      makeDefault: 'Make default',
      lock: 'Lock',
      unlock: 'Unlock',
      remove: 'Delete',
      confirmRemove: 'Delete "{name}" from the registry? Nothing on the server and no key material is touched.',
      cancel: 'Cancel',
      addTitle: 'New server',
      editTitle: 'Edit server',
      fieldName: 'Name',
      fieldHost: 'Address',
      fieldUser: 'User',
      fieldPort: 'Port',
      fieldKey: 'Private key path',
      fieldWorkspace: 'Default remote directory',
      fieldDescription: 'Note',
      placeholderName: 'web1',
      nameHint: 'Several words are fine: "Example VPS Server".',
      placeholderHost: 'example.com or an SSH config alias',
      placeholderUser: 'root',
      placeholderPort: '22',
      placeholderKey: '~/.ssh/id_ed25519',
      placeholderWorkspace: '/srv/app',
      placeholderDescription: 'What this server is for',
      save: 'Save',
      saving: 'Saving…',
      password: 'Password',
      passwordSaved: 'Saved',
      passwordNone: 'Not set',
      passwordPlaceholderNew: 'Password (needed only if no key is installed)',
      passwordForget: 'Forget',
      passwordPlaceholder: 'New password, replaces the stored one',
      passwordHint: 'Saved through a helper program, never on a command line, and never shown again.',
      keyHint: 'A key is safer: it cannot be guessed or replayed from a transcript.',
      trustKey: 'Trust this key',
      trustKeyTitle: 'Host key not confirmed yet',
      trustKeyHint: 'Compare this fingerprint with the one the provider shows. The key is written to known_hosts only after you confirm.',
      trustKeyConfirm: 'Trust and record',
      trustKeyScanning: 'Asking the server for its key…',
      trustKeySaved: 'Key recorded in {path}.',
      registryLabel: 'Registry',
      configLabel: 'SSH config',
      clientLabel: 'SSH client',
      imported: 'Imported {added}, skipped {skipped} block(s).',
      importedNone: 'Nothing new to import.',
      failed: 'The operation failed.',
      saved: 'Saved "{name}".',
      removed: 'Removed "{name}".',
      defaultSet: '"{name}" is now the default server.',
      lockedOn: '"{name}" is locked.',
      lockedOff: '"{name}" is unlocked.',
      warnings: 'Registry remarks',
      lockedHint: 'Locked: no command or transfer runs on this server until you unlock it.',
    }

    const RU = {
      nav: 'SSH',
      title: 'Серверы SSH',
      intro:
        'Серверы, доступные агенту по SSH. Реестр — это список разрешённых: подключаться можно только к именам отсюда, '
        + 'и каждая команда выполняется с правами вашего ключа.',
      add: 'Добавить сервер',
      refresh: 'Обновить',
      import: 'Импорт из ~/.ssh/config',
      empty: 'Пока ни один сервер не зарегистрирован.',
      emptyHint: 'Добавьте сервер или импортируйте хосты из своего SSH-конфига.',
      loading: 'Загрузка…',
      loadFailed: 'Не удалось прочитать реестр.',
      retry: 'Повторить',
      badgeDefault: 'по умолчанию',
      badgeLocked: 'заблокирован',
      badgeKey: 'ключ',
      badgePassword: 'пароль',
      badgeNoAuth: 'нет ключа и пароля',
      test: 'Проверить',
      testing: 'Проверка…',
      testOk: 'Подключение работает.',
      edit: 'Изменить',
      makeDefault: 'Сделать по умолчанию',
      lock: 'Заблокировать',
      unlock: 'Разблокировать',
      remove: 'Удалить',
      confirmRemove: 'Удалить «{name}» из реестра? На сервере ничего не меняется, ключи не затрагиваются.',
      cancel: 'Отмена',
      addTitle: 'Новый сервер',
      editTitle: 'Изменить сервер',
      fieldName: 'Имя',
      fieldHost: 'Адрес',
      fieldUser: 'Пользователь',
      fieldPort: 'Порт',
      fieldKey: 'Путь к приватному ключу',
      fieldWorkspace: 'Рабочий каталог по умолчанию',
      fieldDescription: 'Заметка',
      placeholderName: 'web1',
      nameHint: 'Можно несколько слов: «Тестовый сервер 1».',
      placeholderHost: 'example.com или алиас из SSH-конфига',
      placeholderUser: 'root',
      placeholderPort: '22',
      placeholderKey: '~/.ssh/id_ed25519',
      placeholderWorkspace: '/srv/app',
      placeholderDescription: 'Для чего этот сервер',
      save: 'Сохранить',
      saving: 'Сохранение…',
      password: 'Пароль',
      passwordSaved: 'Сохранён',
      passwordNone: 'Не задан',
      passwordPlaceholderNew: 'Пароль (нужен, только если нет ключа)',
      passwordForget: 'Забыть',
      passwordPlaceholder: 'Новый пароль заменит сохранённый',
      passwordHint: 'Сохраняется через программу-помощник, не попадает в командную строку и больше не показывается.',
      keyHint: 'Ключ надёжнее: его нельзя угадать или перехватить из переписки.',
      trustKey: 'Доверить ключ',
      trustKeyTitle: 'Ключ хоста ещё не подтверждён',
      trustKeyHint: 'Сравните отпечаток с тем, что показывает провайдер. Ключ попадёт в known_hosts только после вашего подтверждения.',
      trustKeyConfirm: 'Доверить и записать',
      trustKeyScanning: 'Запрашиваю ключ у сервера…',
      trustKeySaved: 'Ключ записан в {path}.',
      registryLabel: 'Реестр',
      configLabel: 'SSH-конфиг',
      clientLabel: 'Клиент SSH',
      imported: 'Импортировано: {added}, пропущено блоков: {skipped}.',
      importedNone: 'Новых серверов нет.',
      failed: 'Операция не выполнена.',
      saved: 'Сохранено: «{name}».',
      removed: 'Удалено: «{name}».',
      defaultSet: '«{name}» теперь сервер по умолчанию.',
      lockedOn: '«{name}» заблокирован.',
      lockedOff: '«{name}» разблокирован.',
      warnings: 'Замечания к реестру',
      lockedHint: 'Заблокирован: команды и передача файлов не выполняются, пока не разблокируете.',
    }

    const CSS = `
.sshr-section { display: flex; flex-direction: column; gap: 14px; max-width: 860px; color: var(--dsw-alias-label-primary); }
.sshr-title { margin: 0; font-size: 18px; font-weight: 600; }
.sshr-intro { margin: 0; font-size: 13px; line-height: 20px; color: var(--dsw-alias-label-secondary); }
.sshr-bar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
.sshr-grow { flex: 1 1 auto; }
.sshr-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 10px; }
.sshr-card { border: 0.5px solid var(--dsw-alias-border-l1); border-radius: 10px; background: var(--dsw-alias-bg-layer-1); padding: 12px 14px; display: flex; flex-direction: column; gap: 8px; }
.sshr-card[data-locked='true'] { border-color: var(--dsw-alias-state-warn-primary); }
.sshr-head { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.sshr-name { font-size: 14px; font-weight: 600; line-height: 20px; }
.sshr-where { font-size: 12.5px; color: var(--dsw-alias-label-secondary); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow-wrap: anywhere; }
.sshr-note { font-size: 12.5px; color: var(--dsw-alias-label-secondary); overflow-wrap: anywhere; }
.sshr-badge { font-size: 11px; line-height: 16px; padding: 1px 6px; border-radius: 999px; border: 0.5px solid var(--dsw-alias-border-l2); color: var(--dsw-alias-label-secondary); white-space: nowrap; }
.sshr-badge[data-tone='default'] { border-color: var(--dsw-alias-brand-primary); color: var(--dsw-alias-brand-primary); }
.sshr-badge[data-tone='locked'] { border-color: var(--dsw-alias-state-warn-primary); color: var(--dsw-alias-state-warn-primary); }
.sshr-badge[data-tone='ok'] { border-color: var(--dsw-alias-state-success-primary); color: var(--dsw-alias-state-success-primary); }
.sshr-actions { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 2px; }
.sshr-btn { font: inherit; font-size: 12.5px; line-height: 18px; padding: 4px 10px; border-radius: 8px; border: 0.5px solid var(--dsw-alias-border-l2); background: transparent; color: var(--dsw-alias-label-primary); cursor: pointer; }
.sshr-btn:hover:not(:disabled) { background: var(--dsw-alias-bg-layer-2); }
.sshr-btn:disabled { opacity: 0.55; cursor: default; }
.sshr-btn:focus-visible { outline: var(--dsw-focus-ring-width, 2px) solid var(--dsw-alias-brand-primary); outline-offset: 2px; }
.sshr-btn[data-kind='primary'] { background: var(--dsw-alias-brand-primary); border-color: var(--dsw-alias-brand-primary); color: var(--dsw-alias-bg-base); }
.sshr-btn[data-kind='danger'] { border-color: var(--dsw-alias-state-error-primary); color: var(--dsw-alias-state-error-primary); }
.sshr-form { display: flex; flex-direction: column; gap: 10px; }
.sshr-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; }
.sshr-field { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
.sshr-label { font-size: 12px; color: var(--dsw-alias-label-secondary); }
.sshr-input { font: inherit; font-size: 13px; line-height: 20px; padding: 5px 8px; border-radius: 8px; border: 0.5px solid var(--dsw-alias-border-l2); background: var(--dsw-alias-bg-base); color: var(--dsw-alias-label-primary); width: 100%; box-sizing: border-box; }
.sshr-input:focus-visible { outline: var(--dsw-focus-ring-width, 2px) solid var(--dsw-alias-brand-primary); outline-offset: 1px; }
.sshr-hint { font-size: 11.5px; color: var(--dsw-alias-label-secondary); }
.sshr-status { font-size: 12.5px; line-height: 18px; white-space: pre-wrap; overflow-wrap: anywhere; }
.sshr-status[data-tone='ok'] { color: var(--dsw-alias-state-success-primary); }
.sshr-status[data-tone='error'] { color: var(--dsw-alias-state-error-primary); }
.sshr-notice { font-size: 12.5px; line-height: 18px; padding: 8px 10px; border-radius: 8px; background: var(--dsw-alias-bg-layer-2); color: var(--dsw-alias-label-primary); white-space: pre-wrap; }
.sshr-notice[data-tone='error'] { border: 0.5px solid var(--dsw-alias-state-error-primary); color: var(--dsw-alias-state-error-primary); }
.sshr-notice[data-tone='ok'] { border: 0.5px solid var(--dsw-alias-state-success-primary); }
.sshr-empty { border: 0.5px dashed var(--dsw-alias-border-l2); border-radius: 10px; padding: 18px; text-align: center; color: var(--dsw-alias-label-secondary); font-size: 13px; display: flex; flex-direction: column; gap: 6px; }
.sshr-foot { border-top: 0.5px solid var(--dsw-alias-border-l1); padding-top: 10px; display: flex; flex-direction: column; gap: 3px; font-size: 11.5px; color: var(--dsw-alias-label-secondary); }
.sshr-foot code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; overflow-wrap: anywhere; }
.sshr-warn { font-size: 12px; color: var(--dsw-alias-state-warn-primary); }
`

    /**
     * Call the Host route.
     *
     * A transport failure (the route missing, a 401 from a stale page) is turned
     * into the same `{ ok: false }` shape the Host uses, so callers have one
     * branch to handle and the page always says something specific.
     */
    async function call(action, args) {
      let response
      try {
        response = await fetch(API, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ action, ...(args ?? {}) }),
        })
      } catch (error) {
        return { ok: false, error: `The host did not answer: ${String(error?.message ?? error)}` }
      }
      let payload
      try {
        payload = await response.json()
      } catch {
        return { ok: false, error: `The host answered with HTTP ${response.status} and no JSON.` }
      }
      if (payload === null || typeof payload !== 'object') {
        return { ok: false, error: `The host answered with an unexpected body (HTTP ${response.status}).` }
      }
      return payload
    }

    /** Format one locale string, replacing `{name}` placeholders. */
    function format(text, values) {
      return String(text).replace(/\{(\w+)\}/g, (whole, key) => (values[key] === undefined ? whole : String(values[key])))
    }

    /** One labelled text field. */
    function Field(props) {
      const { label, value, placeholder, onChange, type, autoFocus, hint, id } = props
      return h(
        'label',
        { className: 'sshr-field', htmlFor: id },
        h('span', { className: 'sshr-label' }, label),
        h('input', {
          id,
          className: 'sshr-input',
          type: type ?? 'text',
          value: value ?? '',
          placeholder: placeholder ?? '',
          autoFocus: autoFocus === true,
          autoComplete: 'off',
          spellCheck: false,
          onChange: (event) => onChange(event.target.value),
        }),
        hint === undefined ? null : h('span', { className: 'sshr-hint' }, hint),
      )
    }

    /** A small state badge on a server card. */
    function Badge(props) {
      const { children, tone } = props
      return h('span', { className: 'sshr-badge', 'data-tone': tone }, children)
    }

    /** One button with the shared look. */
    function Button(props) {
      const { children, onClick, disabled, kind, title, type } = props
      return h(
        'button',
        {
          type: type ?? 'button',
          className: 'sshr-btn',
          'data-kind': kind,
          disabled: disabled === true,
          title,
          onClick,
        },
        children,
      )
    }

    /**
     * The add/edit form.
     *
     * Local draft state only: nothing is sent until Save, so a half-typed entry
     * never reaches the allowlist. `originalName` tells the Host which entry was
     * opened, which is what makes renaming onto an existing name a refusal
     * rather than a silent replacement.
     */
    function ServerForm(props) {
      const { t, entry, busy, onCancel, onSave } = props
      const isNew = entry === undefined
      const [draft, setDraft] = React.useState(() => ({
        name: entry?.name ?? '',
        host: entry?.host ?? '',
        user: entry?.user ?? '',
        port: entry?.port === undefined || entry.port === 22 ? '' : String(entry.port),
        identityFile: entry?.identityFile ?? '',
        workspace: entry?.workspace ?? '',
        description: entry?.description ?? '',
      }))
      const [password, setPassword] = React.useState('')
      const [passwordBusy, setPasswordBusy] = React.useState(false)
      const [passwordNote, setPasswordNote] = React.useState(undefined)

      const set = (key) => (value) => setDraft((previous) => ({ ...previous, [key]: value }))
      const submit = (event) => {
        event.preventDefault()
        if (busy) return
        onSave({
          ...draft,
          port: draft.port.trim() === '' ? undefined : draft.port,
          originalName: isNew ? undefined : entry.name,
          // The password travels with the entry: adding a server that needs one
          // must not require a save first and a second visit after. An empty
          // field means "leave whatever is stored".
          ...(password.length > 0 ? { password } : {}),
        })
      }

      /** Forget the stored credential without leaving the form. */
      const forgetPassword = async () => {
        if (passwordBusy) return
        setPasswordBusy(true)
        setPasswordNote(undefined)
        const payload = await call('clearPassword', { name: entry.name })
        setPasswordBusy(false)
        if (payload.ok !== true) {
          setPasswordNote({ tone: 'error', text: payload.error ?? t('failed') })
          return
        }
        setPassword('')
        setPasswordNote({ tone: 'ok', text: t('passwordNone') })
        props.onChanged?.(payload)
      }

      return h(
        'form',
        { className: 'sshr-form', onSubmit: submit },
        h('div', { className: 'sshr-head' }, h('span', { className: 'sshr-name' }, isNew ? t('addTitle') : format(t('editTitle'), { name: entry.name }))),
        h(
          'div',
          { className: 'sshr-grid' },
          h(Field, { id: 'sshr-name', label: t('fieldName'), value: draft.name, placeholder: t('placeholderName'), hint: t('nameHint'), autoFocus: true, onChange: set('name') }),
          h(Field, { id: 'sshr-host', label: t('fieldHost'), value: draft.host, placeholder: t('placeholderHost'), onChange: set('host') }),
          h(Field, { id: 'sshr-user', label: t('fieldUser'), value: draft.user, placeholder: t('placeholderUser'), onChange: set('user') }),
          h(Field, { id: 'sshr-port', label: t('fieldPort'), value: draft.port, placeholder: t('placeholderPort'), onChange: set('port') }),
          h(Field, {
            id: 'sshr-key',
            label: t('fieldKey'),
            value: draft.identityFile,
            placeholder: t('placeholderKey'),
            hint: t('keyHint'),
            onChange: set('identityFile'),
          }),
          h(Field, {
            id: 'sshr-workspace',
            label: t('fieldWorkspace'),
            value: draft.workspace,
            placeholder: t('placeholderWorkspace'),
            onChange: set('workspace'),
          }),
        ),
        h(Field, {
          id: 'sshr-description',
          label: t('fieldDescription'),
          value: draft.description,
          placeholder: t('placeholderDescription'),
          onChange: set('description'),
        }),
        h(
          'div',
          { className: 'sshr-field' },
          h(
            'span',
            { className: 'sshr-label' },
            isNew ? t('password') : `${t('password')}: ${entry.hasPassword ? t('passwordSaved') : t('passwordNone')}`,
          ),
          h(
            'div',
            { className: 'sshr-bar' },
            h('input', {
              className: 'sshr-input',
              type: 'password',
              style: { maxWidth: '280px' },
              autoComplete: 'new-password',
              placeholder: isNew ? t('passwordPlaceholderNew') : t('passwordPlaceholder'),
              value: password,
              onChange: (event) => setPassword(event.target.value),
            }),
            isNew || !entry.hasPassword
              ? null
              : h(Button, { disabled: busy || passwordBusy, onClick: () => void forgetPassword() }, t('passwordForget')),
          ),
          h('span', { className: 'sshr-hint' }, t('passwordHint')),
          passwordNote === undefined
            ? null
            : h('span', { className: 'sshr-status', 'data-tone': passwordNote.tone, role: 'status' }, passwordNote.text),
        ),
        h(
          'div',
          { className: 'sshr-bar' },
          h(Button, { type: 'submit', kind: 'primary', disabled: busy }, busy ? t('saving') : t('save')),
          h(Button, { disabled: busy, onClick: onCancel }, t('cancel')),
        ),
      )
    }

    /** One server card with its actions and inline test result. */
    function ServerCard(props) {
      const { t, server, busy, test, keyFlow, confirmRemove, onEdit, onTest, onDefault, onLock, onAskRemove, onRemove, onCancelRemove, onScanKey, onTrustKey, onCancelKey } = props
      const where = `${server.user === null ? '' : `${server.user}@`}${server.host}${server.port === 22 ? '' : `:${server.port}`}`
      return h(
        'div',
        { className: 'sshr-card', role: 'listitem', 'data-locked': server.locked ? 'true' : undefined },
        h(
          'div',
          { className: 'sshr-head' },
          h('span', { className: 'sshr-name' }, server.name),
          server.isDefault ? h(Badge, { tone: 'default' }, t('badgeDefault')) : null,
          server.locked ? h(Badge, { tone: 'locked' }, t('badgeLocked')) : null,
          server.identityFile === null ? null : h(Badge, null, t('badgeKey')),
          server.hasPassword ? h(Badge, null, t('badgePassword')) : null,
          server.identityFile === null && !server.hasPassword ? h(Badge, { tone: 'locked' }, t('badgeNoAuth')) : null,
        ),
        h('div', { className: 'sshr-where' }, where),
        server.description === null ? null : h('div', { className: 'sshr-note' }, server.description),
        server.workspace === null ? null : h('div', { className: 'sshr-note' }, `${t('fieldWorkspace')}: ${server.workspace}`),
        server.identityFile === null ? null : h('div', { className: 'sshr-note' }, `${t('fieldKey')}: ${server.identityFile}`),
        server.locked ? h('div', { className: 'sshr-warn' }, t('lockedHint')) : null,
        test === undefined
          ? null
          : h(
              'div',
              { className: 'sshr-status', 'data-tone': test.state === 'running' ? undefined : test.state === 'ok' ? 'ok' : 'error', role: 'status' },
              test.state === 'running' ? t('testing') : test.text,
            ),
        test?.code === 'HOST_KEY_UNKNOWN' && keyFlow === undefined
          ? h('div', { className: 'sshr-actions' }, h(Button, { disabled: busy, onClick: onScanKey }, t('trustKey')))
          : null,
        keyFlow === undefined
          ? null
          : h(
              'div',
              { className: 'sshr-form' },
              h('div', { className: 'sshr-name' }, t('trustKeyTitle')),
              keyFlow.state === 'scanning' ? h('div', { className: 'sshr-status' }, t('trustKeyScanning')) : null,
              keyFlow.state === 'error'
                ? h('div', { className: 'sshr-status', 'data-tone': 'error', role: 'alert' }, keyFlow.error)
                : null,
              keyFlow.keys === undefined || keyFlow.keys.length === 0
                ? null
                : h(
                    'div',
                    { className: 'sshr-field' },
                    keyFlow.keys.map((key) => h('div', { key: key.type, className: 'sshr-where' }, `${key.type}  ${key.fingerprint}`)),
                    h('span', { className: 'sshr-hint' }, t('trustKeyHint')),
                  ),
              h(
                'div',
                { className: 'sshr-bar' },
                keyFlow.keys === undefined || keyFlow.keys.length === 0
                  ? null
                  : h(
                      Button,
                      { kind: 'primary', disabled: busy || keyFlow.state === 'saving', onClick: onTrustKey },
                      keyFlow.state === 'saving' ? t('saving') : t('trustKeyConfirm'),
                    ),
                h(Button, { disabled: keyFlow.state === 'saving', onClick: onCancelKey }, t('cancel')),
              ),
            ),
        confirmRemove
          ? h(
              'div',
              { className: 'sshr-form' },
              h('div', { className: 'sshr-note' }, format(t('confirmRemove'), { name: server.name })),
              h(
                'div',
                { className: 'sshr-bar' },
                h(Button, { kind: 'danger', disabled: busy, onClick: onRemove }, t('remove')),
                h(Button, { disabled: busy, onClick: onCancelRemove }, t('cancel')),
              ),
            )
          : h(
              'div',
              { className: 'sshr-actions' },
              h(Button, { disabled: busy || server.locked, title: server.locked ? t('lockedHint') : undefined, onClick: onTest }, t('test')),
              h(Button, { disabled: busy, onClick: onEdit }, t('edit')),
              server.isDefault ? null : h(Button, { disabled: busy, onClick: onDefault }, t('makeDefault')),
              h(Button, { disabled: busy, onClick: onLock }, server.locked ? t('unlock') : t('lock')),
              h(Button, { kind: 'danger', disabled: busy, onClick: onAskRemove }, t('remove')),
            ),
      )
    }

    /** The Settings section. */
    function SettingsSection(props) {
      const { t, locale } = props
      const [state, setState] = React.useState({ status: 'loading', data: undefined, error: undefined })
      const [busy, setBusy] = React.useState(false)
      const [notice, setNotice] = React.useState(undefined)
      const [tests, setTests] = React.useState({})
      const [editor, setEditor] = React.useState(undefined)
      const [confirmRemove, setConfirmRemove] = React.useState(undefined)
      const [keyFlow, setKeyFlow] = React.useState(undefined)

      const apply = (payload) => {
        if (payload.ok !== true) {
          setState((previous) => ({ ...previous, status: previous.data === undefined ? 'error' : previous.status, error: payload.error ?? t('failed') }))
          setBusy(false)
          return false
        }
        setState({ status: 'ready', data: payload, error: undefined })
        setBusy(false)
        return true
      }

      const load = React.useCallback(async () => {
        setState((previous) => ({ ...previous, status: 'loading', error: undefined }))
        const payload = await call('state')
        if (payload.ok !== true) {
          setState({ status: 'error', data: undefined, error: payload.error ?? t('loadFailed') })
          return
        }
        setState({ status: 'ready', data: payload, error: undefined })
      }, [t])

      React.useEffect(() => {
        void load()
        // `t` is bound per locale: a language switch rebinds and this reloads no
        // data, but the text below re-renders with the new dictionary.
      }, [load])

      // A bound translate function reads the active locale when it is CALLED, so
      // the copy follows a language switch only if this component renders again.
      // Subscribing to the locale service is that render trigger; without it the
      // page kept the language it was opened in.
      const [, setLocaleRevision] = React.useState(0)
      React.useEffect(() => {
        if (locale === undefined || typeof locale.subscribe !== 'function') return undefined
        return locale.subscribe(() => setLocaleRevision((previous) => previous + 1))
      }, [locale])

      /** Run one mutating action and report its outcome. */
      const mutate = async (action, args, success) => {
        if (busy) return { ok: false }
        setBusy(true)
        setNotice(undefined)
        const payload = await call(action, args)
        const ok = apply(payload)
        if (ok) {
          if (success !== undefined) setNotice({ tone: 'ok', text: success(payload) })
          setEditor(undefined)
          setConfirmRemove(undefined)
        } else {
          setNotice({ tone: 'error', text: payload.error ?? t('failed') })
        }
        return payload
      }

      const runTest = async (server) => {
        setTests((previous) => ({ ...previous, [server.name]: { state: 'running' } }))
        const payload = await call('test', { name: server.name })
        const text = payload.ok === true ? payload.test?.text : payload.error
        setTests((previous) => ({
          ...previous,
          [server.name]: {
            state: payload.ok === true && payload.test?.ok === true ? 'ok' : 'error',
            // The code is what decides whether the card offers "Trust this key";
            // the text alone would make the page parse prose.
            code: payload.test?.code ?? null,
            text: text ?? t('failed'),
          },
        }))
        if (payload.ok === true && payload.servers !== undefined) apply(payload)
      }

      const data = state.data
      const servers = data?.servers ?? []

      /**
       * Ask the server for its key and show the fingerprints.
       *
       * Nothing is written yet: the human has to see the value they are about to
       * trust, which is the whole point of strict host-key checking.
       */
      const scanKey = async (server) => {
        setNotice(undefined)
        setKeyFlow({ name: server.name, state: 'scanning' })
        const payload = await call('keyScan', { name: server.name })
        if (payload.ok !== true) {
          setKeyFlow({ name: server.name, state: 'error', error: payload.error ?? t('failed') })
          return
        }
        setKeyFlow({ name: server.name, state: 'confirm', keys: payload.keys ?? [] })
      }

      /** Record only the fingerprints that are on screen, then retest. */
      const trustKey = async (server) => {
        const flow = keyFlow
        if (flow === undefined || flow.keys === undefined) return
        setKeyFlow({ ...flow, state: 'saving' })
        const payload = await call('keyTrust', {
          name: server.name,
          fingerprints: flow.keys.map((key) => key.fingerprint),
        })
        if (payload.ok !== true) {
          setKeyFlow({ name: server.name, state: 'error', error: payload.error ?? t('failed') })
          return
        }
        setKeyFlow(undefined)
        apply(payload)
        if (payload.test !== undefined) {
          setTests((previous) => ({
            ...previous,
            [server.name]: { state: payload.test.ok === true ? 'ok' : 'error', text: payload.test.text ?? t('failed') },
          }))
        }
        setNotice({ tone: 'ok', text: format(t('trustKeySaved'), { path: payload.trusted?.path ?? '' }) })
      }

      return h(
        'section',
        { className: 'sshr-section', 'aria-busy': busy || state.status === 'loading' ? 'true' : undefined },
        h('style', null, CSS),
        h('h2', { className: 'sshr-title' }, t('title')),
        h('p', { className: 'sshr-intro' }, t('intro')),
        state.status === 'loading' && data === undefined
          ? h('div', { className: 'sshr-notice' }, t('loading'))
          : null,
        state.status === 'error'
          ? h(
              'div',
              { className: 'sshr-notice', 'data-tone': 'error' },
              `${t('loadFailed')} ${state.error ?? ''}`,
              h('div', { style: { marginTop: '8px' } }, h(Button, { onClick: () => void load() }, t('retry'))),
            )
          : null,
        notice === undefined
          ? null
          : h('div', { className: 'sshr-notice', 'data-tone': notice.tone, role: 'status' }, notice.text),
        data === undefined
          ? null
          : h(
              'div',
              { className: 'sshr-bar' },
              h(Button, { kind: 'primary', disabled: busy, onClick: () => { setEditor({ mode: 'add' }); setConfirmRemove(undefined) } }, t('add')),
              h(
                Button,
                {
                  disabled: busy,
                  onClick: async () => {
                    setBusy(true)
                    setNotice(undefined)
                    const payload = await call('import')
                    setBusy(false)
                    if (payload.ok !== true) {
                      setNotice({ tone: 'error', text: payload.error ?? t('failed') })
                      return
                    }
                    apply(payload)
                    const added = payload.imported?.added ?? []
                    setNotice({
                      tone: 'ok',
                      text: added.length === 0
                        ? t('importedNone')
                        : format(t('imported'), { added: added.join(', '), skipped: (payload.imported?.skipped ?? []).length }),
                    })
                  },
                },
                t('import'),
              ),
              h(Button, { disabled: busy, onClick: () => void load() }, t('refresh')),
            ),
        editor !== undefined && editor.mode === 'add'
          ? h('div', { className: 'sshr-card' }, h(ServerForm, {
              t,
              busy,
              onCancel: () => setEditor(undefined),
              onChanged: (payload) => { apply(payload) },
              onSave: (draft) => void mutate('save', draft, () => format(t('saved'), { name: draft.name })),
            }))
          : null,
        servers.length === 0 && state.status === 'ready'
          ? h('div', { className: 'sshr-empty' }, h('span', null, t('empty')), h('span', null, t('emptyHint')))
          : null,
        h(
          'div',
          { className: 'sshr-list', role: 'list' },
          servers.map((server) => (editor !== undefined && editor.mode === 'edit' && editor.server.name === server.name
            ? h(
                'div',
                { key: server.name, className: 'sshr-card', role: 'listitem' },
                h(ServerForm, {
                  t,
                  busy,
                  entry: server,
                  onCancel: () => setEditor(undefined),
                  onChanged: (payload) => { apply(payload) },
                  onSave: (draft) => void mutate('save', draft, () => format(t('saved'), { name: draft.name })),
                }),
              )
            : h(ServerCard, {
                key: server.name,
                t,
                server,
                busy,
                test: tests[server.name],
                keyFlow: keyFlow?.name === server.name ? keyFlow : undefined,
                onScanKey: () => void scanKey(server),
                onTrustKey: () => void trustKey(server),
                onCancelKey: () => setKeyFlow(undefined),
                confirmRemove: confirmRemove === server.name,
                onEdit: () => { setEditor({ mode: 'edit', server }); setConfirmRemove(undefined) },
                onTest: () => void runTest(server),
                onDefault: () => void mutate('default', { name: server.name }, () => format(t('defaultSet'), { name: server.name })),
                onLock: () => void mutate(server.locked ? 'unlock' : 'lock', { name: server.name }, () => (server.locked ? format(t('lockedOff'), { name: server.name }) : format(t('lockedOn'), { name: server.name }))),
                onRemove: () => void mutate('remove', { name: server.name }, () => format(t('removed'), { name: server.name })),
                onAskRemove: () => setConfirmRemove(server.name),
                onCancelRemove: () => setConfirmRemove(undefined),
              }))),
        ),
        data === undefined
          ? null
          : h(
              'div',
              { className: 'sshr-foot' },
              h('span', null, `${t('registryLabel')}: `, h('code', null, data.paths?.registry ?? '')),
              h('span', null, `${t('configLabel')}: `, h('code', null, data.paths?.sshConfig ?? '')),
              h('span', null, `${t('clientLabel')}: `, h('code', null, data.paths?.sshClient ?? '')),
              (data.warnings ?? []).length === 0
                ? null
                : h(
                    'div',
                    null,
                    h('span', { className: 'sshr-warn' }, `${t('warnings')}:`),
                    h('ul', { className: 'sshr-warn', style: { margin: '4px 0 0', paddingLeft: '18px' } },
                      (data.warnings ?? []).map((warning, index) => h('li', { key: index }, warning))),
                  ),
            ),
      )
    }

    return {
      inject: ['slots', 'locale'],
      apply(ctx) {
        // Dictionaries and the slot registration are effects of this plugin's
        // fiber, so unloading the plugin removes both.
        ctx.effect(() => ctx.locale.register(NS, 'en', EN), 'ssh-remote: en dictionary')
        ctx.effect(() => ctx.locale.register(NS, 'ru', RU), 'ssh-remote: ru dictionary')
        const t = ctx.locale.bind(NS)
        const locale = ctx.locale
        ctx.slots.inject('settings.section', () => ctx.slots.register(
          {
            name: 'settings.section',
            // A fresh id adds a section beside the shipped ones. `order` sits
            // after Agent presets (20) and before the plugin market (40).
            id: 'ssh-remote',
            order: 35,
            label: () => t('nav'),
            locale: NS,
          },
          () => h(SettingsSection, { t, locale }),
        ))
      },
    }
  },
})
