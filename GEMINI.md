# Stride Security Review for Gemini CLI

AI-powered security review for code changes — surfacing real, exploitable
vulnerabilities in a diff or across the tree while filtering out low-signal noise.
This extension is the Gemini CLI port of
[`cheezy/stride-security-review`](https://github.com/cheezy/stride-security-review)
(Claude Code), carried through upstream 2.7.2. The companion
[stride-gemini](https://github.com/cheezy/stride-gemini) extension covers the
Stride **task lifecycle** (claiming, hooks, completion).

## Commands

One native slash command (authored as TOML in `commands/`) drives the review:
`/security-review`. It reviews the current diff by default, and accepts flags for
full-tree scans (`--full`), PR-against-base diffs (`--base <ref>`), JSON or SARIF
output (`--json`, `--sarif`), MAESTRO agentic-AI classification (`--maestro`),
recursive critique passes (`--rci [N]`), baseline suppression (`--baseline`,
`--update-baseline`), surgical-fix patches (`--patches`), severity gating for CI
(`--fail-on <severity>`), path scoping, and considerations mode
(`--considerations <source>`), which verifies a task's `security_considerations`
were actually mitigated by the diff. It needs git 2.44 or later.

## Skills

`skills/security-review-essentials/` is the surface description: when to reach
for a review (diff vs. full), what the output means, the flag inventory, and how
`stride-gemini` detects and dispatches the `security-reviewer` surface. The
analysis methodology itself lives in the agent prompt.

## Custom Agents

`security-reviewer` — analyzes a diff (or whole files) semantically for
vulnerabilities across injection, auth/authz, data exposure, cryptography, input
validation, race conditions, XSS/code execution, and insecure configuration;
filters out low-impact noise (DoS, rate-limiting, memory exhaustion); and returns
structured findings grouped by severity. Dispatched by `/security-review`.
Its framework, supply-chain, CI/CD and agentic rule packs live in `packs/` and
its considerations, result-file and reproduction rules in `modes/`, which it reads
from this extension's directory only when the input needs them. Gemini CLI's
`read_file` reaches them only when exactly this extension's directory is in the
workspace (`--include-directories` or `context.includeDirectories`); without it
the agent reviews with its core rules alone (see the README's *How rule packs
load*).

The agent is read-only on the working tree. Its tools are `read_file`,
`grep_search`, `glob`, `run_shell_command` and `write_file`; `write_file` writes
only an accepted `SECURITY_RESULT_PATH` result file. Gemini CLI frontmatter
cannot narrow `run_shell_command` to particular commands, so the shell is limited
by the agent's written contract and by the deny-only Policy Engine rules in
`policies/security-reviewer.toml`, which have not yet been exercised in a live
Gemini CLI session (see the README's *Tools and the working tree*).

## Layout

- `gemini-extension.json` — the manifest; `GEMINI.md` is its context file.
- `commands/security-review.toml` — the `/security-review` command.
- `agents/security-reviewer.md` — the agent's core prompt (the only file in `agents/`).
- `packs/` — 11 rule packs; `modes/` — 3 mode files, both read on demand.
- `policies/security-reviewer.toml` — deny rules scoped to the subagent.
- `skills/security-review-essentials/SKILL.md` — the essentials skill.
- `lib/` — deterministic tooling and offline checks; `fixtures/` — eval fixtures.
- `install.sh` / `install.ps1` — the manual installers.

## Deterministic tooling

`lib/` holds the deterministic transforms (SARIF v2.1.0 conversion, dedup,
fingerprinting, `--fail-on` gating, baseline suppression), the eval runner
(`run_eval.sh`, which delegates each fixture to this extension's
`security-reviewer` subagent through Gemini CLI), and the offline checks that
`lib/test-all.sh` runs. `fixtures/` holds the framework rule-pack and
considerations-mode fixtures with positive and negative controls, their
expectations in `fixtures/EXPECTED.md`, and the golden files under
`fixtures/golden/`.
