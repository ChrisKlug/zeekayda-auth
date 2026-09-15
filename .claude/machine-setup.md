# Machine setup for working on ZeeKayDa.Auth with Claude Code

What a development machine needs before the agent workflow in this repository (`work-on-issue`,
`adversarial-review`, `check-code-coverage`, the Stop hook, the LSP-first navigation skill) works
without improvisation. Written after a fresh Linux machine cost most of a session to bootstrap
(2026-09-15, PR #684). `CONTRIBUTING.md` covers the human workflow; this covers the tooling.

Each item says whether it is **required** for the loop or **optional**, and how to verify it.

## 1. .NET SDK — required

`global.json` pins the `10.0.3xx` band with patch roll-forward, so a `10.0.4xx` SDK alone does
**not** satisfy it. Install system-wide so hooks and every subprocess see it on `PATH`:

```sh
# Ubuntu/Debian, Microsoft package feed:
sudo apt-get install -y dotnet-sdk-10.0
# or, user-local, exact band:
curl -fsSL https://dot.net/v1/dotnet-install.sh | bash -s -- --channel 10.0.3xx --install-dir "$HOME/.dotnet"
```

A user-local install is not on the `PATH` the Claude Code Stop hook runs with, so the hook fails
every turn with `dotnet: command not found`. Either install system-wide, or add to
`~/.claude/settings.json`:

```json
"env": {
  "PATH": "/home/<you>/.dotnet:/home/<you>/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
  "DOTNET_ROOT": "/home/<you>/.dotnet",
  "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
  "DOTNET_USE_POLLING_FILE_WATCHER": "1"
}
```

Verify: `dotnet --version` prints `10.0.3xx`; `bash .claude/hooks/scripts/check-format.sh` runs
without a "command not found".

Then restore the repo's local tools (Stryker) and the optional report generator:

```sh
dotnet tool restore
dotnet tool install -g dotnet-reportgenerator-globaltool   # optional, HTML coverage reports
```

## 2. C# language server — required for the code-navigation skill

Every agent brief says "LSP first"; without a server they silently fall back to grep.

```sh
dotnet tool install --global csharp-ls
```

then in Claude Code: `/plugin install csharp-lsp@claude-plugins-official`. `~/.dotnet/tools` must be
on `PATH` (add it to the `env.PATH` above if the SDK is user-local).

Verify: `csharp-ls --version`; in a session, `ToolSearch("select:LSP")` then a `goToDefinition`
on any `.cs` file returns a location.

`.claude/skills/restart-lsp` handles `csharp-ls` as well as `Microsoft.CodeAnalysis.LanguageServer`
and `OmniSharp`.

## 3. GitHub CLI and Copilot CLI — required for review and PRs

- `gh` must be installed and logged in (`gh auth status`). It is used for issues, PRs, the
  coverage baseline download, and as the Copilot credential.
- Copilot CLI is what `adversarial-review` runs. It is not an npm package; no node needed:

```sh
curl -fsSL https://gh.io/copilot-install | PREFIX="$HOME/.local" bash
```

The review script calls `copilot` from `PATH`, so `~/.local/bin` must be on the `PATH` the harness
uses (see the `env.PATH` above). Authenticate once with `copilot login`, or export
`GH_TOKEN="$(gh auth token)"` before running the script.

Verify: `copilot --version`; `bash .claude/skills/adversarial-review/run.sh code` on any committed
branch returns a verdict rather than "copilot CLI not found".

## 4. Git identity and DCO — required

The DCO check blocks any PR whose commits lack `Signed-off-by`. Every commit on `main` carries
`Signed-off-by: Chris Klug <chris@59north.com>`. Either configure the identity globally, or keep
passing it per command; in both cases **always** commit with `--signoff`:

```sh
git config --global user.name "Chris Klug"
git config --global user.email "chris@59north.com"
git commit --signoff ...
```

There is no git config that makes `--signoff` the default for `git commit`; a global alias
(`git config --global alias.ci 'commit --signoff'`) or a `prepare-commit-msg` hook are the options.

Verify: `git log -1 --format=%B` on a fresh commit shows the trailer.

## 5. Test-suite environment — required

Two machine defaults break the suite in ways that look like real failures:

- **inotify.** The ASP.NET Core test hosts create hundreds of file watchers; the default
  `fs.inotify.max_user_instances=128` fails ~230 tests with "The configured user limit (128) on
  the number of inotify instances has been reached". Either raise it:

  ```sh
  echo fs.inotify.max_user_instances=1024 | sudo tee /etc/sysctl.d/60-inotify.conf
  sudo sysctl --system
  ```

  or keep `DOTNET_USE_POLLING_FILE_WATCHER=1` in the `env` above (already set on this machine).

- **umask.** `LocalSigningKeyFileSystemTests` creates temp directories and expects them not to be
  group-writable; with the Ubuntu default umask `002` two tests fail with
  `signing.dev_keys.directory_component_writable_by_others`. Run tests under `umask 022`, or put
  `umask 022` in `~/.zshenv`. (The tests should create their directories with explicit modes; that
  is a test defect worth an issue.)

Verify: `umask 022; dotnet test ZeeKayDa.Auth.Linux.slnf` is green.

## 6. CodeScene MCP — optional, expected by Stage 3

`work-on-issue` Stage 3 asks the main session to run CodeScene `analyze_change_set` on production
files. Without the server that step is skipped and only the CI check runs. Install the standalone
binary (no node needed) and register it at user level:

```sh
gh release download -R codescene-oss/codescene-mcp-server -p 'cs-mcp-linux-amd64.zip' -D /tmp
unzip -o /tmp/cs-mcp-linux-amd64.zip -d /tmp && install -m 755 /tmp/cs-mcp-linux-amd64 ~/.local/bin/cs-mcp
claude mcp add codescene --scope user -- "$HOME/.local/bin/cs-mcp"
```

Then, in a session, ask Claude to log in to CodeScene (OAuth), or pass
`--env CS_ACCESS_TOKEN=<token>` to `claude mcp add` instead.

Verify: `claude mcp list` shows `codescene ... Connected`; `ToolSearch("codescene")` finds the tools.

## 7. Aspire CLI — optional

`.claude/settings.json` registers an `aspire mcp start` MCP server. Without the Aspire CLI that
server fails to start (harmless, but noisy). Install it if the Aspire tooling is wanted:

```sh
dotnet tool install -g aspire.cli
```

## 8. Not needed

- Node/npm: nothing in the loop uses them (Copilot CLI ships as a binary).
- Docker: present, unused by the loop.

## Verification checklist

```sh
dotnet --version            # 10.0.3xx
csharp-ls --version
copilot --version
gh auth status
git config user.email       # or pass -c on each commit
umask                       # 022
cat /proc/sys/fs/inotify/max_user_instances   # >= 1024, or the polling env var is set
bash .claude/hooks/scripts/check-format.sh    # no "command not found"
umask 022; dotnet build ZeeKayDa.Auth.Linux.slnf && dotnet test ZeeKayDa.Auth.Linux.slnf
```
