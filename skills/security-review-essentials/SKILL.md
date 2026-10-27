---
name: security-review-essentials
description: Use when about to merge code changes that touch security-sensitive surfaces — authentication, authorization, cryptography, user input handling, secrets management, database queries, shell-outs, file uploads, redirects, or response rendering. Also use before pushing a PR that modifies any of the above, or when a human reviewer asks for a security check. Surfaces the /security-review slash command and the security-reviewer agent. Findings are structured JSON grouped by severity (critical / high / medium / low / info) with semantic — not pattern-match — analysis. Low-impact noise (denial-of-service, rate-limiting, memory-exhaustion) is intentionally filtered out unless it intersects another vulnerability class.
skills_version: "1.0"
---

# security-review-essentials

This skill documents how to invoke the AI-powered security review delivered by the `stride-gemini-security-review` extension. It tells you *when* to invoke and *what the output means*. The analysis methodology itself lives in the `security-reviewer` agent prompt — do not duplicate it here.

## When to invoke

The extension supports two scan modes — pick the one that matches the question you are asking.

**Diff mode (default)** answers *"is this change safe to merge?"* Invoke it before any of the following:

- Pushing a PR that touches authentication, authorization, session handling, or password/token handling.
- Pushing a PR that touches cryptography (hashing, signing, encryption, random number generation for security purposes).
- Pushing a PR that touches user input handling, query building, shell-outs, file uploads, redirects, or response rendering.
- Merging code into `main` or any deployment branch when the diff is large enough that a manual security read is impractical.
- A human reviewer asks "did you run a security check on this?"

**Full mode (`--full`)** answers *"what latent issues are in this codebase right now?"* Invoke it for:

- Onboarding the extension onto an existing repo for the first time — establish a baseline before you start gating PRs.
- Periodic posture checks (quarterly, or on a cron) so latent issues outside the recent diff surface get a regular look.
- Vendoring-in / forking an upstream codebase — review the imported code end-to-end before integrating it.
- Investigating a class-wide concern ("audit our use of cryptography across the repo") where the changed code is not the unit of interest.

### Diff vs. full scan

| Aspect | Diff mode (default) | Full mode (`--full`) |
|---|---|---|
| Question answered | Is this change safe to merge? | What latent issues are in this codebase right now? |
| Input | Working-tree diff against `HEAD` | Tracked files via `git ls-files`, filtered by binary heuristic and a 256 KiB size cap |
| Cost | One agent dispatch | One dispatch per batch of ~10 files (batches may run in parallel) |
| Typical cadence | Per PR | Onboarding, quarterly, or on demand |
| Output schema | Identical — same JSON document | Identical — same JSON document |

### Invocations

> **Invoke it as `/security-review`.** Gemini CLI discovers this command from `commands/security-review.toml` in the installed extension, so it is a first-class bare slash command — there is no namespace prefix and no built-in command to collide with. All of the flags below reach this command body directly.

```text
# Diff mode (default)
/security-review                 # all working-tree changes (staged + unstaged) vs HEAD
/security-review path/to/file    # scope to specific paths
/security-review --json          # raw JSON output (for piping into tools)

# Full mode
/security-review --full          # every tracked file in the repo
/security-review --full lib/     # full scan scoped to a path
/security-review --full --json   # full scan, raw JSON output
```

`--full` and `--json` compose freely with each other, with path arguments, and with the other flags — the full flag inventory is summarized under Customization below, with `commands/security-review.md` owning the semantics.

## When NOT to invoke

- On a clean working tree in diff mode (no changes against HEAD). The command short-circuits with a single line.
- On an empty enumeration in full mode (e.g., a repo whose tracked files are entirely binaries or oversized). Same short-circuit behavior.
- On docs-only or test-only changes that touch no production paths. The agent will return an empty findings list, but the dispatch cost is not zero.
- As a substitute for routine secure-coding hygiene. The agent is a backstop, not the front line.

## What the agent does

The `security-reviewer` agent (`agents/security-reviewer.md` in this extension) receives the diff and returns a JSON document with one finding per vulnerability. Vulnerability classes covered: injection, authentication, authorization, data exposure, cryptography, input validation, race conditions, XSS/code execution, insecure configuration, supply chain. For codebases that wire LLMs / AI agents / Model Context Protocol clients into the request flow, five additional MAESTRO-derived classes activate: prompt injection, tool abuse, agent trust boundary, model output execution, vector store poisoning. The agentic classes activate only when the file imports an LLM/agent/MCP SDK — see the "Agentic vulnerability classes" section in the agent prompt for the per-language detection signals.

The agent operates on **semantic analysis, not pattern matching**. A `grep` hit on `eval(` is not a finding; `eval(user_input)` at a trust boundary is. This is the agent's distinguishing property versus a static analyzer.

## Output shape

Each finding has:

| Field | Meaning |
|---|---|
| `severity` | `critical`, `high`, `medium`, `low`, or `info` — see the agent prompt for assignment rubric |
| `file` / `line` | Source location of the issue |
| `vulnerability_class` | One of the classes listed above, as a snake_case wire value (e.g. `supply_chain`, `prompt_injection`) — the canonical enum value list is owned by the agent prompt (`agents/security-reviewer.md`) |
| `cwe` | Array of CWE-IDs (e.g. `["CWE-89"]`) — stable identifier for triage and dashboards |
| `owasp` | Array of OWASP Top 10 2021 category strings (e.g. `["A03:2021"]`) |
| `description` | What the vulnerability is, what trust boundary is crossed, what the worst realistic outcome is |
| `remediation` | The specific change that fixes it |
| `confidence` | `high`, `medium`, or `low` — how certain the agent is given only the diff context |

A `summary` object reports `files_reviewed` and a per-severity finding count.

## False-positive filter

The agent intentionally suppresses findings whose only impact is generic denial-of-service, generic rate-limiting absence, or generic memory exhaustion — unless those intersect another class (e.g., rate-limiting absence on an authentication endpoint stays in scope under Authentication flaws). This filter exists because experience showed those classes generate noise that drowns out the actionable findings. The one exception is considerations mode: a consideration the task itself lists that names one of these risks ("uploads are size-bounded") is assessed, and its `partial` or `unmitigated` verdict is backed by a finding. Diff and full modes keep the filter unchanged.

If your organization has a stricter policy that wants those classes flagged, extend the agent prompt — do not work around it by ignoring the filter list, because that loses the auditability trail.

## Customization

The command's current flag surface, one line per flag — parsing and full semantics are owned by `commands/security-review.md`, not restated here:

- `--full` — review every tracked file in the repo instead of the diff against HEAD.
- `--json` — raw JSON output for piping into tools.
- `--sarif` — SARIF v2.1.0 output for code-scanning integrations (mutually exclusive with `--json`).
- `--maestro` — classify each finding by MAESTRO agentic-AI threat layer.
- `--rci [N]` — run N additional critique-and-refine passes over the findings.
- `--baseline [path]` — suppress already-acknowledged findings recorded in a baseline file.
- `--update-baseline` — rewrite the baseline file from the current findings (a distinct flag from `--baseline`).
- `--patches` — emit a surgical-fix diff alongside each finding.
- `--base <ref>` — diff against `<ref>...HEAD` instead of HEAD (PR workflows pass the target branch).
- `--fail-on <severity>` — exit non-zero when findings reach the threshold; this is the CI security gate that blocks merges.
- `--considerations <source>` — assess the diff against each declared security consideration (a file, one per line, or an inline string) and emit a `mitigated` / `partial` / `unmitigated` verdict per item alongside the findings (diff mode only).

Two further customization knobs:

1. **Scope by path.** Pass paths as arguments to scope the review to a subset of changed files. Useful for monorepos where one team's diff doesn't need review by another team's security baseline.
2. **Extend the agent prompt.** Fork or patch `agents/security-reviewer.md` to add organization-specific vulnerability classes or to tighten/loosen the false-positive filter. The output schema is the contract — keep that stable so downstream tooling continues to parse correctly.

## Composing with other workflows

The `--json` flag makes the command pipeable. Other extensions (e.g., a Stride completion gate that wants to block task completion on an unclean review) can dispatch the `security-reviewer` agent via the `/security-review --json` command (which dispatches the auto-discovered custom agent), parse the result, and decide whether to proceed. The agent does not call out to any external service, so this composition is safe for sensitive repos.

## How Gemini CLI exposes this extension (and how `stride-gemini` detects and dispatches it)

Gemini CLI discovers this extension from its `gemini-extension.json` manifest at the extension root; the installer copies the extension into `~/.gemini/extensions/stride-gemini-security-review/` (global) or the project-local `.gemini/extensions/…`. There is no TypeScript plugin and no `package.json` — the manifest plus the auto-discovered directories are the whole surface:

| Piece | Discovered from | Sanctioned surface |
|---|---|---|
| `/security-review` command | `commands/security-review.toml` | a first-class bare slash command |
| `security-reviewer` agent | `agents/security-reviewer.md` | an auto-discovered custom agent, dispatched by the `/security-review` command |
| this skill | `skills/security-review-essentials/SKILL.md` | Gemini skill guidance (the surface description) |

**Detection is by sanctioned surface, never by executing untrusted content.** Another Stride Gemini extension — chiefly [`stride-gemini`](https://github.com/cheezy/stride-gemini), which owns the **task lifecycle** (claiming, hook execution, completion) — detects that security review is available the same way any capability is detected in Gemini CLI: by its command and agent appearing in the session's available lists:

- the `/security-review` command appears among the available slash commands, **and/or**
- the `security-reviewer` agent appears among the available custom agents (dispatched by the `/security-review` command).

When both are absent, the extension is simply not installed and the workflow degrades gracefully — it never blocks on a capability that isn't present. When they are present, a `stride-gemini` workflow step (for example, a pre-completion or pre-review security gate, the direct analog of how [`stride-gemini-exploratory-testing`](https://github.com/cheezy/stride-gemini-exploratory-testing) is detected and dispatched for the optional manual-&-exploratory-testing step) can:

1. **Detect** the sanctioned surface (command and/or agent present), exactly as above — only checking availability, never running untrusted content to probe for it.
2. **Dispatch** the review over the task's diff — `/security-review` in diff mode, or `/security-review --json` for a pipeable result. When the task carries a `security_considerations` list, dispatch `considerations` mode (`/security-review --considerations <source>`) so each declared consideration gets a `mitigated | partial | unmitigated` verdict.
3. **Gate** on the parsed result — e.g. treat any `critical`/`high` finding (or `--fail-on <severity>`'s non-zero exit) as a blocker, and surface the findings back to the task.

This is the sanctioned surface `stride-gemini` looks for; keeping the command name (`/security-review`), the agent name (`security-reviewer`), and the JSON output schema stable is what keeps that detection-and-dispatch contract intact across releases.

## What this skill does NOT cover

- The actual analysis methodology (in `agents/security-reviewer.md`).
- The command pipeline (in `commands/security-review.md`).
- Output rendering details (in the same command file).

This skill is the *surface* description. Implementation lives in the files referenced above.
