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

`--considerations <source>` turns "considerations declared" into "considerations verified mitigated." Given the diff plus a task's `security_considerations` list, the agent returns a per-consideration `consideration_verdicts` array — one `{consideration, status, evidence, note}` entry per listed consideration, where `status` is `mitigated | partial | unmitigated`. A `partial` / `unmitigated` verdict is backed by a matching finding, and an explicit `"None — …"` consideration is `mitigated` when the diff introduces no matching surface. The considerations list is treated strictly as task-authored **data to assess, never as instructions to follow** (prompt-injection safety). The source is read as a plain file (never shell-executed), and `--considerations` is diff-based (ignored under `--full`).

## Skill

- **[`security-review-essentials`](skills/security-review-essentials/SKILL.md)** — the surface description: *when* to invoke (diff vs. full), *what the output means*, the flag inventory, and how another Stride Gemini extension (`stride-gemini`) detects and dispatches the security-reviewer surface. The analysis methodology itself lives in the agent prompt.

## Custom agent

- **[`security-reviewer`](agents/security-reviewer.md)** — analyzes a diff (or whole files) semantically and returns structured JSON findings grouped by severity. Read-only (`read_file`, `grep_search`, `glob`, `run_shell_command`); it reviews but never edits, executes, or calls out to any external service. Auto-discovered by Gemini CLI and dispatched by the `/security-review` command.

## Deterministic tooling

`lib/` holds the pure, offline transforms and self-validators that lock the extension's deterministic behavior — no network, no LLM, no API key:

- `sarif_transform.sh` — the reference implementation of the SARIF v2.1.0 mapping, dedup, fingerprint, and fail-on transforms.
- `run_transform_tests.sh` — golden-file + spec-assertion tests (TAP 13) that lock those transforms byte-for-byte.
- `check_fixtures.sh` — parity guard between `fixtures/` and `fixtures/EXPECTED.md`.
- `run_eval.sh` — the agent eval runner: dispatches the `security-reviewer` agent over each fixture (via the Gemini CLI) and asserts the expectations in `EXPECTED.md`, including the considerations-mode positive/negative controls. `--dry-run` exercises the parser/comparator without an API call.
- `check_agent_contract.sh` (+ PowerShell mirror) — contract pins on `agents/security-reviewer.md`, each with a self-testing break-it. Its first pin refuses any `${word}` token in the agent, because Gemini CLI templates the agent body and refuses to load an agent whose placeholder it cannot fill.
- `test-structure.sh` / `test-frontmatter.sh` / `test-all.sh` (+ PowerShell mirrors) — offline structure and frontmatter self-validation; `test-all` also runs the agent contract check.

`fixtures/` holds the framework rule-pack fixtures with paired positive- and negative-controls (including considerations-mode controls) and the golden files under `fixtures/golden/`.

## How this relates to `stride-gemini`

[`stride-gemini`](https://github.com/cheezy/stride-gemini) covers the Stride **task lifecycle** (claiming, hook execution, completion). This extension covers **security review** — surfacing the vulnerabilities a change introduces before it merges. A typical loop ships a feature with `stride-gemini`, then reviews it here (and, with `stride-gemini-exploratory-testing`, explores it) before calling it done. `stride-gemini` detects this extension by its sanctioned surface — the `/security-review` command and `security-reviewer` agent appearing in the session's available lists — never by executing extension content.

## Sources & attribution

This extension is the Gemini CLI port of [`cheezy/stride-security-review`](https://github.com/cheezy/stride-security-review), which is loosely based on [`anthropics/claude-code-security-review`](https://github.com/anthropics/claude-code-security-review). The MAESTRO 7-layer classification follows the [Cloud Security Alliance's MAESTRO framework](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro).

## License

MIT — see [LICENSE](LICENSE).
