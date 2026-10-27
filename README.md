# SSH Remote — a DeepSeek Harness plugin

**English** | [Русский](README.ru.md)

Operate any number of VPS servers over SSH from inside [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness):
a server registry, the `/ssh` command, `ssh_run` / `ssh_put` / `ssh_get`, four
read-only navigation tools, a destructive-command guard, secret redaction, and an
action log.

Authentication is by key where one is configured, and by a stored password
otherwise. The plugin ships **no server addresses**: you add your own, so one
installation works with any number of machines.

> Status: 0.1.0, tested against Harness `0.2.1-rc.3`. DSH is a developer preview
> and breaks compatibility between releases, so pin the Harness version you run.

## Why this one

Most SSH tooling for an agent makes the whole session remote: the shell, the file
tools and the editor are replaced by their remote counterparts, and you pick one
host per workspace. This plugin is the other shape:

- **Several hosts at once.** `ssh_run` with `host: "web1"`, then `host: "db1"`,
  in the same session. Local `bash`/`read`/`edit` keep working on local files.
- **Zero dependencies.** It drives the system `ssh`/`scp` instead of
  reimplementing the protocol, so `~/.ssh/config`, `known_hosts` and the agent
  all behave exactly as they do in a terminal.
- **Guardrails on by default.** Catastrophic commands never run, irreversible
  ones ask first, secrets are cut from output before the model sees it, and every
  call lands in an audit log.
- **Small enough to read.** Six source files, no client bundle, no build step.

If you want a full remote workspace — remote file editing, a terminal panel, LSP —
use [`dsh-ssh`](https://github.com/UynajGI/dsh-ssh),
[`dsh-remote-ssh`](https://github.com/ZhangFengshun/dsh-remote-ssh) or
[`dsh-ssh-ops`](https://github.com/caoyiwei850/dsh-ssh-ops) instead. They are
larger and solve a different problem.

## Install

```
# from npm, once published
dsh plugin --profile web add dsh-plugin-ssh-remote

# from a local checkout
plugin_manager action=install_bundle target=<absolute path to this folder>
```

Then add servers with `/ssh sync` (import from `~/.ssh/config`) or `/ssh add`.

## Quick start

```
/ssh add                # add a server by hand
/ssh pass web1 <pass>   # only if no key is installed on that server yet
/ssh test web1          # check the connection
```

Then just ask the agent: *"check disk usage on web1"*, *"tail the nginx error log
on web1"*, *"copy ./dist.tar.gz to web1 and unpack it in /srv/app"*.

## Tools

| Tool | What it does | Limits |
|---|---|---|
| `ssh_run` | Run a command, return stdout, stderr and exit code. | Command policy, `timeoutMs`, `tty`, `detached`, `logPath`. |
| `ssh_read` | Read a file by line window. | `offset` (1-based), `limit` ≤ 2000; says when lines continue. |
| `ssh_ls` | List a directory. | 200 entries, `long: false` for names only. |
| `ssh_grep` | Search file contents. | `glob`, `maxMatches` ≤ 1000, binary files skipped. |
| `ssh_glob` | Find files by name. | `maxResults` ≤ 2000, pattern as in `find -name`. |
| `ssh_put` / `ssh_get` | Upload or download one file. | Local path is not sandboxed (see Limits). |
| `ssh_hosts` / `ssh_host_add` / `ssh_host_remove` | Manage the registry. | Every change asks for confirmation first. |

## `/ssh` commands

```
/ssh                  # list servers; pick one from the list
/ssh web1             # test a server (does NOT change the default)
/ssh default web1     # make a server the default
/ssh status           # what is allowed, how login works, which server is default
/ssh add              # add a server manually
/ssh sync             # import from ~/.ssh/config
/ssh pass web1 <pass> # store a password (only for a server without a key)
/ssh nopass web1      # forget the password
/ssh lock web1        # block every operation with this server
/ssh unlock web1      # allow it again
/ssh remove web1      # drop it from the registry
```

## Configuration

`profile-patch-snippet.yml` restates every key: a patch **replaces** the row's
whole `config` instead of merging, so a profile-level patch must list every key
it wants to keep.

| Key | Default | Meaning |
|---|---|---|
| `registryPath` | `$DSH_HOME/ssh-remote-hosts.json` | Server registry. |
| `secretsPath` | `$DSH_HOME/ssh-remote-secrets.json` | Saved passwords. |
| `auditLogPath` | `$DSH_HOME/ssh-remote-audit.jsonl` | Action log. |
| `askpassDir` | `$DSH_HOME/ssh-remote-askpass` | Scratch directory for the password helper. |
| `sshConfigPath` | `~/.ssh/config` | Source for `/ssh sync`. |
| `allowRawHosts` | `false` | Accept an address that is not in the registry (turns the allowlist off). |
| `sshPath` / `scpPath` | platform default | OpenSSH clients; on Windows `%SystemRoot%\System32\OpenSSH\`. |
| `connectTimeoutMs` | `10000` | Connection timeout. |
| `defaultTimeoutMs` | `120000` | Default command deadline. |
| `maxTimeoutMs` | `1800000` | Ceiling any `timeoutMs` is clamped to. |
| `maxOutputChars` | `60000` | Per-stream output ceiling; head and tail are kept. |
| `commandPolicy` | `standard` | `standard` asks about irreversible commands; `off` stops asking (catastrophic ones are still refused). |
| `multiplex` | `false` | OpenSSH connection sharing; needs a POSIX local endpoint. |

## Safety model

- **The registry is the allowlist.** A connection needs a registered name.
  `allowRawHosts` is off by default, and even when on, an address is never
  substituted silently.
- **Host-key checking is never relaxed.** Always `StrictHostKeyChecking=yes`,
  including in password mode; a changed key stops the command and asks you to
  verify the fingerprint yourself.
- **No interactive prompts.** Key auth uses `BatchMode=yes`; password auth allows
  exactly one attempt, so a command can never hang waiting for input.
- **Catastrophic commands are refused before the process starts.** `rm -rf /`,
  `mkfs`, `dd` to a device, `shutdown` and similar are blocked even when wrapped
  in `sudo`, `nohup` or `sh -c`. Irreversible but legitimate commands (`rm -rf`
  on an absolute path, `apt purge`, `docker system prune`, `DROP DATABASE`) ask
  once, with the command, the server and the working directory shown. No
  answerer means no execution.
- **Secrets are cut before the model sees them.** Private-key blocks, AWS keys,
  `sk-…`, JWTs, `password=`/`token=`/`api_key=`, `Authorization: Bearer …` and
  credentials in URLs are replaced with `redacted:<kind>`, and the report says
  how many were removed.
- **Every call is logged.** One JSON line per client call in
  `ssh-remote-audit.jsonl`, command already redacted, rotated at 10 MB.

The command policy reads text, it does not evaluate it. `rm -rf $(echo /)`,
`find / -delete`, or a script uploaded with `ssh_put` and run afterwards are not
caught. **The real boundary is a dedicated server user without `sudo`**; keep
`root` for manual work.

## Limits

- **No multiplexing on Windows.** Each call is a new connection, which shows up as
  latency. `multiplex: true` works only on a POSIX local endpoint.
- **Local paths are not sandboxed.** `ssh_put` can send any file your user can
  read. Every transfer is logged, but the local sandbox does not apply.
- **No terminal, no remote editing, no LSP.** These are tools, not a workspace.
  Use one of the plugins linked above for that.
- **No ProxyJump.** The registry has no jump-chain support; put the hops in
  `~/.ssh/config` and sync, or connect to the bastion and hop manually.
- **The registry is per profile.** One file per `$DSH_HOME`; concurrent writes are
  serialized inside the plugin, but a manual edit during a run is picked up on the
  next operation.
- **`/ssh sync` does not expand `Include`, `Match` or `*` patterns.** Such blocks
  are listed as skipped rather than guessed.
- **Editing the installed code needs a Harness restart.** Node caches ES modules
  by URL, so toggling the bundle does not reload changed code.
- **The `/ssh` interface speaks Russian.** Tool descriptions — what the model
  reads — are English, but the `/ssh` output, prompts and picker labels are
  Russian. An English locale is the next planned change.

## Tests

```
npm install          # one peer dependency, @deepseek-ai/schemastery, for the tests
npm test             # both suites
```

```
node test-args.mjs   # argv, failures, command policy, redaction, registry,
                     # ssh-config parser, passwords, ACL, audit, atomic writes
node test-host.mjs   # tools, policy gate, confirmation, /ssh, guard
```

No network, no real server: the host half runs against a fake `subprocess`.
`node test-live.mjs <name>` is the optional live checklist (40 checks) against a
registered server.

## License

MIT. Not affiliated with DeepSeek AI.
