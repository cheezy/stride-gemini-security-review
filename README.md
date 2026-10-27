# Stride Security Review for Gemini CLI

AI-powered, semantic security review of your code changes — from Gemini CLI.

This extension provides a security-review command, skill, and custom agent for projects that use [Stride](https://www.stridelikeaboss.com). It is the Gemini CLI port of [`cheezy/stride-security-review`](https://github.com/cheezy/stride-security-review) (Claude Code). Review the current diff (or the full tree) for real, exploitable vulnerabilities — analyzed **semantically rather than by pattern-matching** — and get findings grouped by severity, with SARIF output, severity gating for CI, and a considerations mode that verifies a task's `security_considerations` were actually mitigated by the diff.

The distinguishing property is semantic analysis: a `grep` hit on `eval(` is not a finding; `eval(user_input)` at a trust boundary is. The `security-reviewer` agent understands control flow, data flow, and the surrounding context before flagging an issue, and it explicitly filters out low-impact noise (denial-of-service, rate-limiting, memory-exhaustion) unless it intersects another vulnerability class.

> **GitHub Topic:** This repo should be tagged with `gemini-cli-extension` for auto-indexing in the Gemini extension gallery.

## Installation

### Recommended: install as a Gemini CLI extension

```bash
gemini extensions install https://github.com/cheezy/stride-gemini-security-review
```

Gemini CLI clones the extension, auto-loads `GEMINI.md`, registers the `commands/*.toml` slash command (`/security-review`), and discovers the `skills/` and `agents/` directories.

### Manual install (fallback)

Clone the repo and run the bundled installer to copy the extension into your Gemini extensions directory:

```bash
git clone https://github.com/cheezy/stride-gemini-security-review.git

# Global (all projects): ~/.gemini/extensions/stride-gemini-security-review/
./stride-gemini-security-review/install.sh

# Project-local: .gemini/extensions/stride-gemini-security-review/
./stride-gemini-security-review/install.sh --project
```

On Windows, use the PowerShell installer:

```powershell
.\stride-gemini-security-review\install.ps1            # global
.\stride-gemini-security-review\install.ps1 -Project   # project-local
```

The installers copy `gemini-extension.json`, `GEMINI.md`, and the `commands/`, `skills/`, `agents/`, `lib/`, `fixtures/`, `policies/`, `packs/` and `modes/` directories into the target extension location.

To install straight from `main` without cloning first, pipe the bootstrap installer from raw GitHub to your shell:

```bash
curl -fsSL https://raw.githubusercontent.com/cheezy/stride-gemini-security-review/main/install.sh | bash
```

## Quick start

1. **Install** the extension (above) and restart Gemini CLI in a project with staged or committed changes.
2. **Review the current diff** — the default, "is this change safe to merge?" mode:

   ```text
   /security-review
   ```

   You get findings grouped by severity (critical → high → medium → low → info), each with the file, line, vulnerability class, CWE/OWASP mapping, a description of the trust boundary crossed, and a remediation.
3. **Scan the whole tree** — "what latent issues are in this codebase right now?":

   ```text
   /security-review --full
   ```
4. **Gate a PR in CI** — exit non-zero on any finding at or above a severity:

   ```text
   /security-review --base origin/main --fail-on critical
   ```
5. **Verify a task's declared security considerations were mitigated**:

   ```text
   /security-review --considerations threat-model.md
   ```

## The `/security-review` command

Native slash command, authored as TOML in `commands/security-review.toml`. It reviews the working-tree diff against `HEAD` by default and accepts these flags (full semantics live in the command body):

| Flag | Effect |
|------|--------|
| `--full` | Review every tracked text file (batched, size- and binary-filtered) instead of the diff. |
| `--json` | Raw JSON output for piping into tools (mutually exclusive with `--sarif`). |
| `--sarif` | SARIF v2.1.0 output for GitHub Code Scanning / SARIF viewers (mutually exclusive with `--json`). |
| `--maestro` | Classify each finding by MAESTRO 7-layer agentic-AI threat layer. |
| `--rci [N]` | Run N additional recursive critique-and-refine passes over the findings (clamped to 3). Every pass re-sends the considerations, MAESTRO and patches directives, so `consideration_verdicts`, `maestro_layer` and `patch` survive it. |
| `--baseline [path]` | Suppress already-acknowledged findings recorded in a baseline file. A finding that backs a `partial` or `unmitigated` consideration verdict is never suppressed. |
| `--update-baseline` | Rewrite the baseline file from the current findings. |
| `--patches` | Emit a surgical-fix unified diff alongside each finding where one exists. |
| `--base <ref>` | Diff against `<ref>...HEAD` (PR-against-base scope; pass the target branch in CI). |
| `--fail-on <severity>` | Exit non-zero when findings reach the threshold or, with `--considerations`, on an `unmitigated` verdict, a `partial` verdict no finding backs, or missing or malformed verdicts — the CI security gate. It runs after human-readable, `--json` and `--sarif` output alike. |
| `--considerations <source>` | Assess the diff against each declared security consideration (a file, one per line, or an inline string) and emit a `mitigated` / `partial` / `unmitigated` verdict per item alongside the findings (diff mode only). |
| `path ...` | Scope the review to specific paths. |

The flags compose freely. Opt-in output fields (`maestro_layer`, `patch`, `consideration_verdicts`) are absent unless their flag is set, so output stays byte-identical for callers that don't opt in. The exit-code contract is `0` (no findings at/above the threshold, or no `--fail-on`), `1` (a finding meets the threshold or, with `--considerations`, an `unmitigated` verdict, a `partial` verdict no finding backs, or missing or malformed verdicts, including an array whose entries do not answer the considerations in order), `2` (usage error).

**Opt-in rules travel with their flag.** The agent prompt carries only a one-line gate for `maestro_layer`, `patch` and `rci_passes`; the MAESTRO layer table and its mapping, the patch rules and the RCI critique directive live in the slash command, which sends each one only when its flag is set. A caller that dispatches the agent directly gets these fields only by sending the same blocks (see "Opt-in directive blocks" in [`commands/security-review.toml`](commands/security-review.toml)).

The command needs git 2.44 or later: its git lines pass `--no-lazy-fetch` so that none of them starts a program the reviewed repository configures (see *Tools and the working tree* below), and on an older git it stops with `/security-review needs git 2.44 or later` (exit `2`).

## What it catches

The `security-reviewer` agent covers the universal vulnerability classes — injection, authentication, authorization, data exposure, cryptography, input validation, race conditions, XSS / code execution, insecure configuration, and supply chain — plus idiom-level rule packs that activate on framework signals:

- **Framework rule packs (7):** Android/Kotlin, Django/Python, Express/Node.js, iOS/Swift, Phoenix/Elixir, Rails/Ruby, React/Next.js.
- **CI/CD pipeline pack** across 8 platforms (Azure, Bitbucket, CircleCI, Drone, GitHub Actions, GitLab CI, Jenkins, Tekton). Adding a ninth platform means listing its file path in [`packs/ci-cd.md`](packs/ci-cd.md) and mapping its syntax onto the five existing rules; the rule count stays fixed and only the example column grows.
- **Supply-chain checks** (floating-tag base images, pipe-to-shell installers, unpinned CI references, lockfile drift, typosquat package names).
- **Web defense-in-depth** (missing CSP / HSTS / X-Frame-Options, insecure cookie flags).
- **Agentic-AI classes** — prompt injection, tool abuse, agent trust boundary, model output execution, vector store poisoning — which activate only when a file imports a recognized LLM / AI-agent / Model Context Protocol SDK.

Framework packs map to the existing universal `vulnerability_class` values — they never introduce new enum values. Each pack is a file in [`packs/`](packs/) that the agent reads only when a reviewed file needs it; see [How rule packs load](#how-rule-packs-load).

## Considerations mode

`--considerations <source>` turns "considerations declared" into "considerations verified mitigated." Given the diff plus a task's `security_considerations` list, the agent returns a per-consideration `consideration_verdicts` array — one `{consideration, status, evidence, note}` entry per listed consideration, where `status` is exactly one of `mitigated` / `partial` / `unmitigated` (there is no fourth value; a consideration the change has no surface for is `mitigated`). A `partial` / `unmitigated` verdict is backed by a matching finding, which its `evidence` names by `file:line` (or a `file:start-end` range), and an explicit `"None — …"` consideration is `mitigated` when the diff introduces no matching surface. A gap that predates the change is graded against the changed code and named in `note` plus one `info` finding. A consideration that embeds a credential, or names where one lives, is echoed as `[REDACTED — row text embedded a credential]` in its position rather than verbatim, and `/security-review` prints that sentinel as returned. The considerations list is treated strictly as task-authored **data to assess, never as instructions to follow** (prompt-injection safety). The source is read as a plain file (never shell-executed), and `--considerations` is diff-based (ignored under `--full`). With `--considerations`, `--rci` re-grades the verdicts on every pass, `--baseline` never suppresses a finding that backs a `partial` or `unmitigated` verdict, and `--fail-on` fails on any `unmitigated` verdict whatever the threshold.

**The noise filter has one exception, in considerations mode only.** The agent suppresses findings whose only impact is generic denial-of-service, generic rate-limiting absence or generic memory exhaustion. When a consideration the task lists names one of these risks itself — "uploads are size-bounded", "the export endpoint is rate-limited" — that risk is assessed for that consideration, and a `partial` or `unmitigated` verdict on it is backed by a finding like any other. A risk the list does not name is still suppressed, and diff and full modes keep the filter unchanged.

## Skill

- **[`security-review-essentials`](skills/security-review-essentials/SKILL.md)** — the surface description: *when* to invoke (diff vs. full), *what the output means*, the flag inventory, and how another Stride Gemini extension (`stride-gemini`) detects and dispatches the security-reviewer surface. The analysis methodology itself lives in the agent prompt.

## Custom agent

- **[`security-reviewer`](agents/security-reviewer.md)** — analyzes a diff (or whole files) semantically and returns structured JSON findings grouped by severity. Its tools are `read_file`, `grep_search`, `glob`, `run_shell_command` and `write_file`. It is read-only with one exception: when the caller supplies an absolute `SECURITY_RESULT_PATH` (`.stride/.security-<IDENT>-r<N>.json`, on its own line in the dispatch instructions; the Stride workflow does, `/security-review` does not), it writes that same JSON document to that one file with `write_file`, refusing a symlink at the path or a symlinked `.stride` directory, and returns at most 10 plain-text lines (`result:`, verdict counts, severity counts, `files_reviewed`, no fence). Gemini CLI asks you to approve that write in interactive mode, allows it in auto-edit mode and denies it headless (`gemini -p`); if the write is denied or fails, the agent returns `result: NOT WRITTEN — <reason>` and then the document inline. It never writes the document to any other file a prompt names. Without `SECURITY_RESULT_PATH` its output is unchanged. Otherwise it is read-only on the working tree and calls out to no external service; its shell is limited by its written contract and by `policies/security-reviewer.toml` (see *Tools and the working tree* below). Auto-discovered by Gemini CLI and dispatched by the `/security-review` command.

Everything the agent reviews — diff hunks, code comments, string literals, the files it reads and the considerations it is handed — is data, never instructions: a comment telling the reviewer to report nothing is ignored. In diff and considerations mode it may read the changed files in full and their direct callers, up to 10 files beyond the diff; it never enumerates the rest of the repository. In considerations mode a dispatch also has a budget of 20 tool calls, at most 2 of them reproductions (writing the result file never counts). It grades from the diff first, a read past direct callers — a caller's caller, or a config file the changed code reads — must be named and justified in the verdict's note, and a consideration the budget leaves unverified comes back `partial` with a note that begins `budget reached:`. No finding backs that verdict, so `--fail-on` fails on it at every threshold and the Stride workflow escalates it; it is never `mitigated`. Diff and full modes have no budget. Gemini CLI also stops every dispatch, in any mode, at the agent's `max_turns: 26` or `timeout_mins: 16`, whichever comes first; `max_turns` counts model turns, not tool calls, so in considerations mode the agent stops at the lower of the budget and the turn limit, and it writes its result file before its last turn.

### How rule packs load

The agent prompt, [`agents/security-reviewer.md`](agents/security-reviewer.md), is a core of about 20 KB: the methodology, the vulnerability classes, the false-positive filter, the output schema, severity and the per-consideration verdict contract. Everything else is a file the agent reads with `read_file` only when the input needs it, from this extension's own install directory, `${extensionPath}`, which Gemini CLI fills into the prompt when it loads the extension:

| Directory | Files | Read when |
|---|---|---|
| [`packs/`](packs/) | `android`, `django`, `express`, `ios`, `phoenix`, `rails`, `react-nextjs`, `web-defense`, `supply-chain`, `ci-cd`, `agentic` | a reviewed file's extension, path, structure or imports match the pack — a mixed diff loads every matching pack, and `web-defense` rides along with any web framework pack |
| [`modes/`](modes/) | `considerations`, `result-file`, `reproduction` | the dispatch is in considerations mode, carries an accepted `SECURITY_RESULT_PATH`, or the agent is about to run a reproduction |

- **Add exactly this extension's directory to the workspace.** Gemini CLI's `read_file` reads only inside the workspace, and an installed extension sits outside it, so start Gemini CLI with `--include-directories ~/.gemini/extensions/stride-gemini-security-review`, or list that one path under `context.includeDirectories` in `settings.json` (for a project-local install, use `.gemini/extensions/stride-gemini-security-review` under the project). Name that directory and nothing wider — never your home directory or `~/.gemini`. Verified against Gemini CLI 0.65.0: `${extensionPath}` resolves to the install path, a read of `packs/phoenix.md` there is refused as outside the workspace without the setting and succeeds with it, in both the absolute and the `~` form. For an extension installed with `gemini extensions link`, `${extensionPath}` is the linked source directory, so include that directory instead: checked the same way, the reads succeed with the source directory included and are refused with only `~/.gemini/extensions/stride-gemini-security-review`, which for a link holds just the link record.
- **An included directory is a full workspace directory.** Gemini CLI does not make it read-only: in that session your main agent can also write there, as it can anywhere else in the workspace. That directory also holds the agent's own prompt, `policies/` and `lib/`, so a main session steered by the repository it is working on, with writes approved, could change the reviewer itself; keep write approval on in sessions that include it, and reinstall if you suspect a change. The subagent's own contract and `policies/security-reviewer.toml` still keep it read-only.
- **Only file types and imports choose a pack.** Text inside the diff — a comment or string asking for a pack, or for one to be skipped — never loads, skips or limits one.
- **A missing pack never means no review.** If a pack cannot be read (the directory not in the workspace, a denied read, a deleted file), the agent reviews with the core rules alone and adds nothing to its output. A result file is never written without `modes/result-file.md`, and nothing is ever run without `modes/reproduction.md`.
- **The reads are instructions, not code under review.** They are allowed in every mode and do not count toward the 10-file read limit or the considerations-mode tool budget, though each read takes a model turn of the agent's `max_turns`.
- **The directories sit at the extension root, not under `agents/`.** Gemini CLI 0.65.0 parses every `.md` file directly in an extension's `agents/` directory as an agent definition, so a pack there fails to load as one; `lib/check_agent_contract.sh` refuses any `.md` file below `agents/` but the agent, as upstream does.

**Adding a pack.** Write `packs/<name>.md` with no YAML frontmatter, an activation predicate built from file extension AND an import or identifier signal (never a path alone), and 4–6 idiomatic rules mapped to existing `vulnerability_class` values. Then add its row to the loading table in the agent prompt, its name to the `PACKS` list and its hash to `PACK_SHA256` in `lib/check_agent_contract.sh` and its PowerShell mirror, which fail on a pack the table does not name, a name with no file, and any file below `agents/` but the agent; `install.sh` and `install.ps1` copy the whole directory.

### Tools and the working tree

The agent's tools are `read_file`, `grep_search`, `glob`, `run_shell_command` and `write_file`, and it is **read-only on the working tree**: it never creates, modifies, moves or deletes anything in the repository it reviews, tracked or untracked, not even to restore it afterwards. It inspects code with `read_file`, `grep_search` and `glob`, writes only its result file with `write_file`, and uses `run_shell_command` for three things only — the result file's link check, a short list of read-only commands (`ls`, `wc` and five git forms — `git --no-pager --no-lazy-fetch -c core.fsmonitor=false -c gpg.program=false -c gpg.ssh.program=false -c gpg.x509.program=false ls-files`, `git --no-pager --no-lazy-fetch -c core.fsmonitor=false -c gpg.program=false -c gpg.ssh.program=false -c gpg.x509.program=false diff --cached --no-ext-diff --no-textconv --submodule=short`, `git --no-pager --no-lazy-fetch -c core.fsmonitor=false -c gpg.program=false -c gpg.ssh.program=false -c gpg.x509.program=false diff --no-ext-diff --no-textconv --submodule=short <commit> <commit>`, `git --no-pager --no-lazy-fetch -c core.fsmonitor=false -c gpg.program=false -c gpg.ssh.program=false -c gpg.x509.program=false log --no-ext-diff --no-textconv --submodule=short --no-show-signature` and `git --no-pager --no-lazy-fetch -c core.fsmonitor=false -c gpg.program=false -c gpg.ssh.program=false -c gpg.x509.program=false show --no-ext-diff --no-textconv --submodule=short --no-show-signature` — never a bare `git diff` against the working tree, which rewrites `.git/index`), and, when reading cannot settle a question, one reproduction inside a temporary copy. In considerations mode a reproduction only confirms a specific claim stated in a verdict's note or a finding's description, and a dispatch runs at most two.

The flags on those git forms stop git running a program named in the reviewed repository's config or attributes — a `core.fsmonitor` hook, `diff.external`, a `diff.<driver>.command`, a textconv driver, the `gpg.program` (or `gpg.ssh.program` or `gpg.x509.program`) that `log.showSignature`, a `%G` placeholder in a `format.pretty` default or a `pretty.<name>` alias would call, a `core.pager` when the shell has a terminal, a submodule's own diff programs when `diff.submodule=diff`, or the `core.sshCommand`, credential helper or proxy a partial clone's lazy fetch would start — which would run outside any sandbox with the agent's full environment. `--no-lazy-fetch` also keeps a lazy fetch from writing a pack into `.git/objects`, and needs git 2.44 or later; an older git rejects it and runs nothing, and the agent then reads with `read_file`. Local config does not travel with a clone, so this takes a planted `.git/config`, but a reviewer that never runs reviewed code should not run a program the repository names either. The agent never drops a flag, adds `--ext-diff`, `--textconv` or `--show-signature`, or puts a `%G` signature placeholder in `--format` or `--pretty`, which runs `gpg.program` whatever the flags say; it reads the working tree with `read_file` rather than through git: `git ls-files -m` and `git diff-index` without `--cached` run a configured clean filter. The probe's copy step lists files with `git --no-lazy-fetch -c core.fsmonitor=false ls-files` for the same reason — in a sparse partial clone `--exclude-standard` would otherwise lazy-fetch a skip-worktree `.gitignore` — and the probe refuses to run, grading by reading, on a git older than 2.44.

`/security-review` runs its own git lines in your session before the agent starts — the `--base` ref check, the diff, the changed-file list and the full-mode listing — and they carry the same options: the `--base` check `git --no-lazy-fetch rev-parse`, the listing the first form above, and each diff the `diff` options plus `-c diff.autoRefreshIndex=false -c core.hooksPath=/dev/null`, because a diff against the working tree would otherwise rewrite `.git/index` and run the repository's `post-index-change` hook. On a git older than 2.44 the command stops with `/security-review needs git 2.44 or later` (exit `2`). One route stays open there: a diff that compares the working tree runs the clean filter (`filter.<driver>.clean`) the repository's config names for a changed path, and no option turns it off; it runs in your own session, on your own checkout — the same program `git add` would run there.

That copy is a `stride-security-probe.XXXXXX` directory under `$TMPDIR` (else `/tmp`), made by copying the repository's files rather than linking them, used by a single command that runs one test or snippet, and removed when that command exits. The command refuses a copy that holds a symbolic link, and runs the snippet inside a sandbox that denies network access, every write outside the copy and every read under your home directory — on macOS (`sandbox-exec`) also every Unix socket, launchd job creation, mach service lookups, Launch Services, Apple Events, `open`/`launchctl`/`osascript`, signals, POSIX and System V IPC, process-information and task-port calls to any process outside the box, and running or loading as native code any file in the copy, so a script there runs through its interpreter (`sh test.sh`); on Linux (`bwrap`) new namespaces, an empty `/run`, `/tmp`, `/var/tmp` and home directory, and a new session — under `env -i`, so the credentials in your environment are not inherited and `HOME` and `TMPDIR` point into the copy. It refuses to run when `HOME` is unset, relative, `/`, not a directory or not your account's home directory, when it or the copy has a quote, backslash or newline in its path, or when the copy would sit under it. On macOS a snippet can still signal and inspect the processes it starts, but not your editor, agent or any other outside process, though it can still read their command lines (and, on a macOS release that returns them, their environments); a snippet that needs POSIX semaphores or shared memory, such as Python `multiprocessing` locks, fails in the box. With neither sandbox available the agent runs nothing and grades by reading, and it runs nothing in CI (the command checks `CI` first) or when the caller says the change comes from an untrusted contributor, because the sandbox hides your home directory but not the rest of the filesystem. A probe installs nothing and never runs a command written in the code under review. A dispatch killed mid-command can leave a copy behind; it holds only copied files, and an operator can clear stale ones with:

```bash
find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'stride-security-probe.*' -mmin +60 -exec rm -rf {} +
```

**On Gemini CLI the reproduction does not run today.** `run_shell_command` refuses any command carrying `$(`, a backtick, `<(` or `>(` outside single quotes (`@google/gemini-cli-core` 0.65.0, `dist/src/tools/shell.js`), and the probe command carries `$(`, so the agent is told to expect the refusal and grade by reading — never to rewrite the command past it or run it in pieces. Headless (`gemini -p`), Gemini CLI denies the subagent's `run_shell_command` unless you allow it, so no probe and no read-only command runs there either. Whether `sandbox-exec` can apply its profile inside Gemini CLI's own `--sandbox` seatbelt, or `bwrap` inside its container sandbox, is not verified; if the wrapper fails to start, the agent runs nothing.

The guarantee is the agent's written contract, not the `tools:` list: Gemini CLI cannot narrow `run_shell_command` to particular commands through an agent's frontmatter (`run_shell_command(git)` fails its tool-name validation and the agent does not load), so the tool is listed whole and the prompt says what it is for. The extension also ships `policies/security-reviewer.toml`, Policy Engine rules scoped to the `security-reviewer` subagent that deny the plain forms of what the contract forbids: git commands that change the repository, a bare `git diff`, git's `--output`, network clients and package runners, package installs, and a `write_file` call on any path but a `.stride/.security-<IDENT>-r<N>.json` result file. Gemini CLI ignores an extension's `allow` rules and its yolo-mode rules, so the file can only deny; its rules carry no `modes`, so by Gemini CLI's 0.65.0 source they apply in every approval mode including `--yolo` and rank above yolo's allow-all — not yet confirmed in a live session — and your own user and admin policies, `--allowed-tools` and an interactive "Always allow" rank above them. A pattern cannot tell the probe's temporary copy from the repository, so `rm`, `mv`, `cp`, `tar` and redirection are not denied, and neither are `git diff` with arguments or obfuscated command names: those are left to the contract. None of these rules has been exercised in a live Gemini CLI session yet: `lib/check_policy_patterns.mjs` checks their patterns offline, against a re-implementation of the 0.65.0 matcher and a modelled split of compound commands, which is not the same as Gemini CLI denying a call, so do not rely on them under `--yolo` until a live check is recorded. `lib/check_agent_contract.sh` pins the contract, checks the `tools:` list against it and holds the policy file to deny-only, subagent-scoped rules.

## Deterministic tooling

`lib/` holds the pure, offline transforms and self-validators that lock the extension's deterministic behavior — no network, no LLM, no API key:

- `sarif_transform.sh` — the reference implementation of the SARIF v2.1.0 mapping, dedup, fingerprint, fail-on and baseline-suppression (`suppress`) transforms. `failon` gates on consideration verdicts as well as finding severities: an `unmitigated` verdict, a `partial` verdict no finding backs, and a missing, short, malformed or out-of-position verdict array each trip it at every threshold. `suppress` never drops a finding that backs an open verdict. Both take exactly one findings document and an optional consideration count or considerations file, and exit 2 on anything else (an empty file, documents run together, a `findings` value that is not an array, an empty third argument, or an all-digit one that also names a file). The SARIF `driver.version` is read from `gemini-extension.json`. It implements Step 4's *A finding that backs a verdict* and the Step 4.6 and Step 6 rules of `commands/security-review.toml`, whose prose stays authoritative.
- `run_transform_tests.sh` — golden-file + spec-assertion tests (TAP 13) that lock those transforms byte-for-byte, including the verdict gate, the rule that a baseline never drops a finding backing a verdict, the input and argument refusals, and a guard self-test that deletes each input and position guard from a copy of the script and checks the bad input then gets through.
- `check_fixtures.sh` — parity guard between `fixtures/` and `fixtures/EXPECTED.md`; it also checks that each considerations-mode `.diff` has its `.considerations` sidecar (and the reverse) and that its row lists one verdict per consideration.
- `run_eval.sh` — the agent eval runner: hands each fixture to **this checkout's** `security-reviewer` subagent through Gemini CLI and asserts the expectations in `EXPECTED.md`, including the considerations-mode rows. A fixture is scored only when the CLI's event stream shows the main model delegating to that subagent; see [Running the eval](#running-the-eval). `--dry-run` exercises the parser/comparator without an API call.
- `check_eval_invocation.sh` — model-free checks on how `run_eval.sh` invokes Gemini CLI, against a fake `gemini` on a temporary `PATH`: the agent selection, the scratch home and working directory, the fixture on stdin, the refusal without auth, the failure when the main model answers without delegating, the empty-fixture-set refusal, `--only`, the prompt opening with the agent's one mode tag (`/security-review invocation, mode: considerations` or `…, mode: full_file`), the scratch copy carrying `packs/` and `modes/` and the workspace adding exactly that copy, and `check_fixtures.sh`'s considerations guards, each with a break-it. Needs no model, no credentials and no network.
- `check_agent_contract.sh` (+ PowerShell mirror) — contract pins on `agents/security-reviewer.md`, each with a self-testing break-it. Its first pin allows exactly one `${word}` token in the agent, `${extensionPath}` in the rule-pack read path, which Gemini CLI fills in when it loads the extension, and refuses any other, because Gemini CLI templates the agent body and refuses to load an agent whose placeholder it cannot fill. Since W2482 a pin on text that moved into a mode file reads that file (`modes/result-file.md`, `modes/reproduction.md` or `modes/considerations.md`), and the SHA-256 table names the file each pinned line lives in. Its W2284 section pins the `SECURITY_RESULT_PATH` result file: the dispatch-line-only rule, the path rules word for word from upstream, the no-path fallback, the `write_file` limit to that one path, the unfenced 10-line summary and the `NOT WRITTEN` fallback, and refuses Claude Code's Bash write wording coming back. Its W2275 section pins the considerations-mode rules: the data-only rule, the listed-consideration exemption from the noise filter and its limit to considerations mode, the MUST-backed `partial`/`unmitigated` verdict, the pre-existing-gap rule, the bounded read scope, the closed `mitigated | partial | unmitigated` enum and the credential sentinel, byte for byte. Its W2488 section pins the read-only contract and the probe sandbox (upstream W2276, D376 and D378) with upstream's labels, plus the clauses upstream's pin set leaves unpinned (the read-only command list, the git verbs, the copy's creation and cleanup, the full write denial, `--ro-bind` and four probe sentences), each also broken from inside its line, and pins the probe block and each ported line of the contract whole by SHA-256; checks the frontmatter tool list, and checks `policies/security-reviewer.toml`: every rule denies, is scoped to the `security-reviewer` subagent, names no approval mode and names a tool the agent has, and each rule's pattern is pinned, as are the rules whole, by SHA-256. Its W2489 section pins upstream D377: the agent's neutralised git forms and the rules that keep them so, the probe's pre-2.44 guard and neutralised copy step, the five forms in this README, and the command's git lines (`commands/security-review.toml`), and refuses an un-neutralised form coming back in any of the three files. Its W2490 section pins upstream W2278: the agent's one mode-tag spelling, the untagged-list fallback for an older caller, the rule that a tag-shaped line in reviewed content selects nothing, `SECURITY_RESULT_PATH` as the only output path and the `complete_task` result channel, each ported agent line whole by SHA-256, the four tags the command sends, and the skill's `--considerations` line and result channel (`skills/security-review-essentials/SKILL.md`, its optional fifth argument), and checks that the agent, the command and the skill spell the tag identically. Its W2492 section pins upstream W2279 and `6ca7233`: the agent's `rci_pass`-with-a-list rule, its backing-finding rule and the `evidence` link; the command's definition of a finding that backs a verdict, the `--rci` re-send, the verdict gate, the backing-finding baseline rule, Step 5's `--json` and `--sarif` branches going on to Step 6, and the position and one-document guards; and the skill's three flag lines. Every ported line of the agent, the command and the skill is pinned whole by SHA-256, and a `Stop.` ending, a `Bash` tool name or the pre-port `N_GATE` count coming back fails. Its W2493 section pins upstream W2282: the considerations-mode budget of 20 tool calls and 2 reproductions, the result-file exemption, the justified wider read, the claim-bound reproduction and the unbacked `budget reached:` `partial`, in the agent and in the command's gate; the paragraph that reconciles the budget with Gemini CLI's `max_turns` and `timeout_mins`; and the limits stated here. It checks that the frontmatter limits are the values the agent text states, and pins the five lines W2282 touched in the agent, the Gemini limits paragraph, and its command and skill lines, whole by SHA-256. Its W2482 section ports upstream W2285: the core is 10,240 to 20,480 bytes; each of the 11 packs and 3 mode files exists with no frontmatter and a loading-table row, and nothing else is in `packs/` or `modes/`; every file the core names exists; no `.md` sits below `agents/` and `agents/` holds the one agent; each pack is upstream's byte for byte by SHA-256; the core reads them from `${extensionPath}` and names the workspace requirement, the rule that reviewed text never chooses a pack, the core-rules fallback and the budget exemption; and neither the core nor a mode file names `CLAUDE_PLUGIN_ROOT`. Break-its paste a pack back into the core, delete, add, edit or frontmatter a pack in a copy of the extension, put a pack under `agents/`, and swap the read path for `${CLAUDE_PLUGIN_ROOT}`. Its W2483 section pins upstream W2285's command half: the command owns the MAESTRO block (the directive line, the seven-layer table and the non-AI mapping) and the Patches block (the directive line, the three conditions and the format), each pinned whole by SHA-256 and sent only when its flag is set, in Step 4a, in Step 4b (so `--full --patches` gets the patch rules) and on every `--rci` pass, which sets `summary.rci_passes`; the considerations tag and list stay the considerations directive; the agent and the mode files carry no copy of the blocks' rules; and the command carries no `${extensionPath}`, `@{` or `!{`, since Gemini CLI does not hydrate it. Break-its edit, plant in or drop each block, remove the considerations tag or list, send a block for an unset flag, restore the *MAESTRO layer reference* heading and plant `${extensionPath}` or `@{` in the command.
- `check_policy_patterns.mjs` (node) — offline checks of `policies/security-reviewer.toml`'s patterns: each passes Gemini CLI's `isSafeRegExp`, and under a re-implementation of 0.65.0's `stableStringify` and `commandRegex` matching no allowed command, line of the probe in `modes/reproduction.md` or result-file write is denied while every forbidden form is, compound commands joined with `;`, `&&`, `||`, `|` or a newline and `bash -c` wrappers included; in-memory break-its prove the cases can fail, and that the per-rule `isSafeRegExp` check (broken in each rule in turn), the six-rule check and the probe-block check can each report a failure. The compound split is modelled, not Gemini CLI's own parser, and nothing here is a live run.
- `check_install.sh` (+ PowerShell mirror) — runs the installer with `HOME` (`USERPROFILE` for `install.ps1`) set to a temporary directory and checks that the installed `packs/` and `modes/` match the checkout file for file and that the installed `agents/` holds only the agent, with self-tests whose installer no longer copies `packs/` or `modes/`. Writes only to temporary directories and makes no network call.
- `test-structure.sh` / `test-frontmatter.sh` / `test-all.sh` (+ PowerShell mirrors) — offline structure and frontmatter self-validation; `test-all` also runs the transform golden tests, the agent contract check, the eval invocation check and the install check (`test-all.ps1` runs the transform tests and the eval invocation check through `bash` when `bash` and `jq` are on `PATH`, and reports each skipped otherwise), and both run the policy pattern check when `node` is on `PATH` and report it skipped otherwise.

`fixtures/` holds the framework rule-pack fixtures with paired positive- and negative-controls (including considerations-mode fixtures: a positive and a negative control, a `partial` verdict, a `None —` placeholder, injection text inside a consideration and inside the diff, a noise-class consideration, a gap in pre-existing code, a listed rate-limit consideration, a consideration quoting an obviously fake credential, a probe-tempting diff that reading settles, and a production config change inside a larger diff) and the golden files under `fixtures/golden/`.

### Running the eval

Gemini CLI has no flag that makes a subagent the session agent, so `lib/run_eval.sh` asks the main model to delegate and then checks that it did. Each fixture runs as:

```bash
GEMINI_CLI_HOME=<scratch home> gemini -p '@security-reviewer Delegate the security review of the input above …' \
  -e stride-gemini-security-review --include-directories <scratch home>/.gemini/extensions/stride-gemini-security-review \
  -o stream-json --approval-mode default --skip-trust   # fixture on stdin
```

- The scratch home's `.gemini/extensions/` holds only a copy of this checkout's extension (manifest, `GEMINI.md`, `agents/`, `commands/`, `skills/`, `packs/`, `modes/`), so an edit to `agents/security-reviewer.md` or to a pack is what gets scored. `--include-directories` adds that copy, and nothing wider, to the workspace, so the agent's `read_file` reaches its packs and mode files (see [How rule packs load](#how-rule-packs-load)); it does not reach `fixtures/`, which is never copied. Nothing from your own `~/.gemini` is copied: no credentials, settings or login files.
- The call runs from an empty scratch directory, so the agent cannot read the expected answers in `fixtures/EXPECTED.md`. The fixture prompt goes on stdin, never in `-p`, so shell metacharacters in a diff are never interpreted. It also means the eval never exercises the agent's read scope, and it checks verdicts and whether a finding exists — not redaction, `note` text, or a finding's severity — so those are checked by hand in `logs/` where a row says so.
- `--approval-mode default` keeps Gemini CLI's headless policy: `invoke_agent` is allowed, and the subagent's `run_shell_command` and `write_file` are denied. `--skip-trust` trusts the scratch directory for this process only.
- A fixture is scored only when the `stream-json` output shows an `invoke_agent` call naming `security-reviewer` whose result succeeded. If the main model answers by itself, delegates to another agent, or hits a turn limit (exit `53`), the fixture is `not ok`. Gemini CLI 0.65.0 does not stream the subagent's own result, so the JSON scored is the main model's reply after the call returns; the prompt it delegated is kept in `logs/<stem>.agent_prompt.txt`.
- Auth comes from the environment only, checked in the order Gemini CLI resolves it: a login with Google (`GOOGLE_GENAI_USE_GCA=true`), Vertex AI (`GOOGLE_GENAI_USE_VERTEXAI=true` with `GOOGLE_API_KEY`, or with `GOOGLE_CLOUD_PROJECT` and `GOOGLE_CLOUD_LOCATION`), `GOOGLE_GEMINI_BASE_URL`, `GEMINI_API_KEY`, then compute ADC (`GEMINI_CLI_USE_COMPUTE_ADC=true`, or Cloud Shell). A login with Google needs the OAuth files the eval does not copy, so it is refused. With no usable auth the runner exits `2`; a CLI that still reports itself unauthenticated (exit `41`) or the workspace untrusted (exit `55`) stops the run with `Bail out!` and exit `2`. Only the auth mode's name is printed, never a value.

Every run prints the exact command as `# invocation: …` and the auth mode as `# auth: …` right after the TAP plan line; `--dry-run` prints them without calling Gemini CLI, and `lib/check_eval_invocation.sh` pins them.

```bash
bash lib/run_eval.sh                          # every expectation in EXPECTED.md — check_fixtures.sh prints the current count
bash lib/run_eval.sh --fixture considerations/search_sort_partial.diff
bash lib/run_eval.sh --only considerations/   # only fixtures whose path starts with the prefix
bash lib/run_eval.sh --dry-run                # parser/comparator only; no API calls
```

`EVAL_EXTENSION_DIR` (default: the repo root) and `EVAL_AGENT` (default: `security-reviewer`) override the extension copied and the subagent selected; `GEMINI_CLI`, `FIXTURES_DIR` and `LOG_DIR` work as before. An empty fixture set, or an `--only` prefix that matches nothing, exits `2` rather than passing. Per fixture, `logs/` gets the event stream (`.raw.txt`), the CLI's stderr (`.err.txt`), the delegated prompt (`.agent_prompt.txt`), the reply scored (`.text.txt`) and the parsed document (`.json`).

`fixtures/EXPECTED.md` ends with a **Recorded runs** table: the date, CLI version, auth mode and TAP result of each real run, so a ticked row always traces back to a run rather than to a hand edit. No run of this runner has been recorded yet, so every row is unticked.

## How this relates to `stride-gemini`

[`stride-gemini`](https://github.com/cheezy/stride-gemini) covers the Stride **task lifecycle** (claiming, hook execution, completion). This extension covers **security review** — surfacing the vulnerabilities a change introduces before it merges. A typical loop ships a feature with `stride-gemini`, then reviews it here (and, with `stride-gemini-exploratory-testing`, explores it) before calling it done. `stride-gemini` detects this extension by its sanctioned surface — the `/security-review` command and `security-reviewer` agent appearing in the session's available lists — never by executing extension content.

## Sources & attribution

This extension is the Gemini CLI port of [`cheezy/stride-security-review`](https://github.com/cheezy/stride-security-review), which is loosely based on [`anthropics/claude-code-security-review`](https://github.com/anthropics/claude-code-security-review). The MAESTRO 7-layer classification follows the [Cloud Security Alliance's MAESTRO framework](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro).

## License

MIT — see [LICENSE](LICENSE).
