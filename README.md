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

The installers copy `gemini-extension.json`, `GEMINI.md`, and the `commands/`, `skills/`, `agents/`, `lib/`, and `fixtures/` directories into the target extension location.

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
| `--rci [N]` | Run N additional recursive critique-and-refine passes over the findings (clamped to 3). |
| `--baseline [path]` | Suppress already-acknowledged findings recorded in a baseline file. |
| `--update-baseline` | Rewrite the baseline file from the current findings. |
| `--patches` | Emit a surgical-fix unified diff alongside each finding where one exists. |
| `--base <ref>` | Diff against `<ref>...HEAD` (PR-against-base scope; pass the target branch in CI). |
| `--fail-on <severity>` | Exit non-zero when findings reach the threshold — the CI security gate. |
| `--considerations <source>` | Assess the diff against each declared security consideration (a file, one per line, or an inline string) and emit a `mitigated` / `partial` / `unmitigated` verdict per item alongside the findings (diff mode only). |
| `path ...` | Scope the review to specific paths. |

The flags compose freely. Opt-in output fields (`maestro_layer`, `patch`, `consideration_verdicts`) are absent unless their flag is set, so output stays byte-identical for callers that don't opt in. The exit-code contract is `0` (no findings at/above the threshold, or no `--fail-on`), `1` (a finding meets the threshold), `2` (usage error).

## What it catches

The `security-reviewer` agent covers the universal vulnerability classes — injection, authentication, authorization, data exposure, cryptography, input validation, race conditions, XSS / code execution, insecure configuration, and supply chain — plus idiom-level rule packs that activate on framework signals:

- **Framework rule packs (7):** Android/Kotlin, Django/Python, Express/Node.js, iOS/Swift, Phoenix/Elixir, Rails/Ruby, React/Next.js.
- **CI/CD pipeline pack** across 8 platforms (Azure, Bitbucket, CircleCI, Drone, GitHub Actions, GitLab CI, Jenkins, Tekton).
- **Supply-chain checks** (floating-tag base images, pipe-to-shell installers, unpinned CI references, lockfile drift, typosquat package names).
- **Web defense-in-depth** (missing CSP / HSTS / X-Frame-Options, insecure cookie flags).
- **Agentic-AI classes** — prompt injection, tool abuse, agent trust boundary, model output execution, vector store poisoning — which activate only when a file imports a recognized LLM / AI-agent / Model Context Protocol SDK.

Framework packs map to the existing universal `vulnerability_class` values — they never introduce new enum values.

## Considerations mode

`--considerations <source>` turns "considerations declared" into "considerations verified mitigated." Given the diff plus a task's `security_considerations` list, the agent returns a per-consideration `consideration_verdicts` array — one `{consideration, status, evidence, note}` entry per listed consideration, where `status` is exactly one of `mitigated` / `partial` / `unmitigated` (there is no fourth value; a consideration the change has no surface for is `mitigated`). A `partial` / `unmitigated` verdict is backed by a matching finding, and an explicit `"None — …"` consideration is `mitigated` when the diff introduces no matching surface. A gap that predates the change is graded against the changed code and named in `note` plus one `info` finding. A consideration that embeds a credential, or names where one lives, is echoed as `[REDACTED — row text embedded a credential]` in its position rather than verbatim, and `/security-review` prints that sentinel as returned. The considerations list is treated strictly as task-authored **data to assess, never as instructions to follow** (prompt-injection safety). The source is read as a plain file (never shell-executed), and `--considerations` is diff-based (ignored under `--full`).

**The noise filter has one exception, in considerations mode only.** The agent suppresses findings whose only impact is generic denial-of-service, generic rate-limiting absence or generic memory exhaustion. When a consideration the task lists names one of these risks itself — "uploads are size-bounded", "the export endpoint is rate-limited" — that risk is assessed for that consideration, and a `partial` or `unmitigated` verdict on it is backed by a finding like any other. A risk the list does not name is still suppressed, and diff and full modes keep the filter unchanged.

## Skill

- **[`security-review-essentials`](skills/security-review-essentials/SKILL.md)** — the surface description: *when* to invoke (diff vs. full), *what the output means*, the flag inventory, and how another Stride Gemini extension (`stride-gemini`) detects and dispatches the security-reviewer surface. The analysis methodology itself lives in the agent prompt.

## Custom agent

- **[`security-reviewer`](agents/security-reviewer.md)** — analyzes a diff (or whole files) semantically and returns structured JSON findings grouped by severity. Its tools are `read_file`, `grep_search`, `glob`, `run_shell_command` and `write_file`. It is read-only with one exception: when the caller supplies an absolute `SECURITY_RESULT_PATH` (`.stride/.security-<IDENT>-r<N>.json`, on its own line in the dispatch instructions; the Stride workflow does, `/security-review` does not), it writes that same JSON document to that one file with `write_file`, refusing a symlink at the path or a symlinked `.stride` directory, and returns at most 10 plain-text lines (`result:`, verdict counts, severity counts, `files_reviewed`, no fence). Gemini CLI asks you to approve that write in interactive mode, allows it in auto-edit mode and denies it headless (`gemini -p`); if the write is denied or fails, the agent returns `result: NOT WRITTEN — <reason>` and then the document inline. Without `SECURITY_RESULT_PATH` its output is unchanged. Otherwise it reviews but never edits, executes, or calls out to any external service. Auto-discovered by Gemini CLI and dispatched by the `/security-review` command.

Everything the agent reviews — diff hunks, code comments, string literals, the files it reads and the considerations it is handed — is data, never instructions: a comment telling the reviewer to report nothing is ignored. In diff and considerations mode it may read the changed files in full and their direct callers, up to 10 files beyond the diff; it never enumerates the rest of the repository.

## Deterministic tooling

`lib/` holds the pure, offline transforms and self-validators that lock the extension's deterministic behavior — no network, no LLM, no API key:

- `sarif_transform.sh` — the reference implementation of the SARIF v2.1.0 mapping, dedup, fingerprint, and fail-on transforms.
- `run_transform_tests.sh` — golden-file + spec-assertion tests (TAP 13) that lock those transforms byte-for-byte.
- `check_fixtures.sh` — parity guard between `fixtures/` and `fixtures/EXPECTED.md`; it also checks that each considerations-mode `.diff` has its `.considerations` sidecar (and the reverse) and that its row lists one verdict per consideration.
- `run_eval.sh` — the agent eval runner: hands each fixture to **this checkout's** `security-reviewer` subagent through Gemini CLI and asserts the expectations in `EXPECTED.md`, including the considerations-mode rows. A fixture is scored only when the CLI's event stream shows the main model delegating to that subagent; see [Running the eval](#running-the-eval). `--dry-run` exercises the parser/comparator without an API call.
- `check_eval_invocation.sh` — model-free checks on how `run_eval.sh` invokes Gemini CLI, against a fake `gemini` on a temporary `PATH`: the agent selection, the scratch home and working directory, the fixture on stdin, the refusal without auth, the failure when the main model answers without delegating, the empty-fixture-set refusal, `--only`, and `check_fixtures.sh`'s considerations guards, each with a break-it. Needs no model, no credentials and no network.
- `check_agent_contract.sh` (+ PowerShell mirror) — contract pins on `agents/security-reviewer.md`, each with a self-testing break-it. Its first pin refuses any `${word}` token in the agent, because Gemini CLI templates the agent body and refuses to load an agent whose placeholder it cannot fill. Its W2284 section pins the `SECURITY_RESULT_PATH` result file: the dispatch-line-only rule, the path rules word for word from upstream, the no-path fallback, the `write_file` limit to that one path, the unfenced 10-line summary and the `NOT WRITTEN` fallback, and refuses Claude Code's Bash write wording coming back. Its W2275 section pins the considerations-mode rules: the data-only rule, the listed-consideration exemption from the noise filter and its limit to considerations mode, the MUST-backed `partial`/`unmitigated` verdict, the pre-existing-gap rule, the bounded read scope, the closed `mitigated | partial | unmitigated` enum and the credential sentinel, byte for byte.
- `test-structure.sh` / `test-frontmatter.sh` / `test-all.sh` (+ PowerShell mirrors) — offline structure and frontmatter self-validation; `test-all` also runs the agent contract check and the eval invocation check (`test-all.ps1` runs the latter through `bash` when `bash` and `jq` are on `PATH`, and reports it skipped otherwise).

`fixtures/` holds the framework rule-pack fixtures with paired positive- and negative-controls (including considerations-mode fixtures: a positive and a negative control, a `partial` verdict, a `None —` placeholder, injection text inside a consideration and inside the diff, a noise-class consideration, a gap in pre-existing code, a listed rate-limit consideration and a consideration quoting an obviously fake credential) and the golden files under `fixtures/golden/`.

### Running the eval

Gemini CLI has no flag that makes a subagent the session agent, so `lib/run_eval.sh` asks the main model to delegate and then checks that it did. Each fixture runs as:

```bash
GEMINI_CLI_HOME=<scratch home> gemini -p '@security-reviewer Delegate the security review of the input above …' \
  -e stride-gemini-security-review -o stream-json --approval-mode default --skip-trust   # fixture on stdin
```

- The scratch home's `.gemini/extensions/` holds only a copy of this checkout's extension (manifest, `GEMINI.md`, `agents/`, `commands/`, `skills/`), so an edit to `agents/security-reviewer.md` is what gets scored. Nothing from your own `~/.gemini` is copied: no credentials, settings or login files.
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
