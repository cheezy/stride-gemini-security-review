# Stride Security Review for Gemini CLI

> **Scaffold skeleton.** This context file is filled in by later tasks. It will
> orient the Gemini CLI agent on the extension's methodology (semantic security
> analysis, not pattern-matching), its `security-review-essentials` skill, the
> `security-reviewer` custom agent, and the `/security-review` TOML slash command.

AI-powered security review for code changes — surfacing real, exploitable
vulnerabilities in a diff or across the tree while filtering out low-signal noise.
This extension is the Gemini CLI port of
[`cheezy/stride-security-review`](https://github.com/cheezy/stride-security-review)
(Claude Code). The companion [stride-gemini](https://github.com/cheezy/stride-gemini)
extension covers the Stride **task lifecycle** (claiming, hooks, completion).

## Commands

One native slash command (authored as TOML in `commands/`) drives the review:
`/security-review`. It reviews the current diff by default, and accepts flags for
full-tree scans (`--full`), PR-against-base diffs (`--base <ref>`), MAESTRO
agentic-AI classification (`--maestro`), surgical-fix patches (`--patches`),
severity gating for CI (`--fail-on <severity>`), and considerations mode
(`--considerations <source>`), which verifies a task's `security_considerations`
were actually mitigated by the diff.

## Skills

The knowledge core lives under `skills/`: the `security-review-essentials` skill,
which teaches when to reach for a review, the semantic-analysis methodology, the
framework rule packs, the severity model, and the structured-JSON output contract.

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

## Deterministic tooling

`lib/` holds the deterministic transforms (SARIF v2.1.0 conversion, dedup,
fingerprinting, `--fail-on` gating) and the eval/golden test harness; `fixtures/`
holds the framework rule-pack fixtures with positive-and-negative controls. These
are authored by later tasks — this skeleton establishes the directory shape only.
