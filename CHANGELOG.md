# Changelog

All notable changes to the Stride Security Review extension for Gemini CLI are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-07-23

### Fixed

- **The agent-dispatch-failure exit-code contract now matches the procedure (G377: D172).** Ported from the upstream source-of-truth fix (`cheezy/stride-security-review` D170). The Step 6 exit-code table documented exit `2` for an "agent dispatch failure", but the three agent-response-failure branches — Step 4a (diff-mode dispatch), Step 4b (full-mode batch), and Step 4.5 (RCI pass) — only printed a one-line error and "stopped", never running `exit 2`. A `--fail-on` CI gate therefore observed an unspecified exit code (not the documented `2`) when the reviewer returned unparseable JSON. Applying the identical **Option A** resolution: each of the three branches now runs a final `exit 2` via `run_shell_command` after printing its error, mirroring the Step 1 misuse pattern used by every other exit-2 case (`--fail-on`, `--base`, `--considerations`, `--sarif`/`--json` conflict). The exit-code table's `0`/`1`/`2` meanings are unchanged; the exit-code semantics are identical to the corrected CC source, adapted only to Gemini CLI's `run_shell_command` tool vocabulary.

## [0.1.0] - 2026-07-22

Initial release of the Gemini CLI port of [`cheezy/stride-security-review`](https://github.com/cheezy/stride-security-review).

### Added

- **Extension skeleton & install flow** — `gemini-extension.json` manifest (name `stride-gemini-security-review`, version `0.1.0`, `contextFileName` `GEMINI.md`), a `GEMINI.md` context file, the `agents/`, `commands/`, `skills/`, `lib/`, and `fixtures/` directories, `README.md` / `LICENSE` (MIT), and `install.sh` / `install.ps1` that install the extension globally (`~/.gemini/extensions/…`) or project-locally (`--project` / `-Project`). Both recommend `gemini extensions install <repo-url>` as the preferred path.
- **`security-reviewer` custom agent** — a faithful Gemini port of the CC agent (`agents/security-reviewer.md`): the full semantic-analysis methodology; `diff`, `full_file`, and `considerations` input modes; the seven framework rule packs (Android/Kotlin, Django/Python, Express/Node.js, iOS/Swift, Phoenix/Elixir, Rails/Ruby, React/Next.js) plus supply-chain, CI/CD (8 platforms), and Web defense-in-depth packs; the universal and MAESTRO agentic vulnerability classes; the structured findings schema with `cwe`/`owasp` mapping; and the opt-in `maestro_layer`, `patch`, and `consideration_verdicts` (`mitigated | partial | unmitigated`) fields.
- **`/security-review` TOML slash command** — `commands/security-review.toml` with full flag parity: `--full`, `--json`, `--sarif` (mutually exclusive with `--json`), `--maestro`, `--rci [N]`, `--baseline`, `--update-baseline`, `--patches`, `--fail-on <severity>`, `--base <ref>`, `--considerations <source>`, and path arguments. Preserves the mutual-exclusion and `0`/`1`/`2` exit-code contracts, the byte-identical opt-in output discipline, the human-readable / SARIF / JSON rendering, and the per-consideration verdict rendering.
- **`security-review-essentials` skill** — `skills/security-review-essentials/SKILL.md` documenting when to invoke (diff vs. full), the output shape, the false-positive filter, the flag inventory, and how another Stride Gemini extension (`stride-gemini`) detects and dispatches the security-reviewer surface by its sanctioned command/agent availability — never by executing extension content.
- **Deterministic tooling & fixtures** — `lib/sarif_transform.sh` (SARIF/dedup/fingerprint/fail-on reference implementation), `lib/run_transform_tests.sh` (golden-file + spec assertions), `lib/check_fixtures.sh` (fixture↔EXPECTED.md parity), `lib/run_eval.sh` (agent eval runner over the fixtures, with a `--dry-run` parser mode), and `lib/test-structure.sh` / `lib/test-frontmatter.sh` / `lib/test-all.sh` (plus PowerShell mirrors) for offline self-validation. `fixtures/` carries the framework rule-pack fixtures with paired positive/negative controls (including considerations-mode controls) and the golden files under `fixtures/golden/`. The transforms are pure and byte-stable.
- **Marketplace registration** — registered in the `stride-gemini-marketplace` catalog (`extensions.json` + the README extension table), version-synced with the manifest.
