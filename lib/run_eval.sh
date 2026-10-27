#!/usr/bin/env bash
#
# run_eval.sh — eval runner for the security-reviewer agent.
#
# Dispatches the security-reviewer agent (via the Gemini CLI) against every fixture
# in fixtures/ and asserts the findings documented in fixtures/EXPECTED.md.
# Output is TAP version 13; exit 0 only when every fixture produces its expected
# vulnerability_class + severity at the expected count.
#
# Tolerance: the runner asserts (file, vulnerability_class, severity, count).
# CWE/OWASP arrays are advisory — mismatches emit `# warn:` comments but do not
# fail the run. EXPECTED.md is the spec; do not mutate it to match the agent.
#
# Considerations mode: a fixture under considerations/ ending in `.diff` is
# dispatched in the agent's `considerations` input mode — the diff plus the
# resolved list from its sibling `<stem>.considerations` file. Its EXPECTED.md
# row uses the `→ CONSIDERATIONS <s1>,<s2>,… [AND finding|AND clean]` grammar
# (see EXPECTED.md "Considerations mode"); the runner asserts the ordered
# consideration_verdicts[].status list plus the backing-finding (positive) /
# zero-finding (negative) expectation. consideration_verdicts is agent output,
# so there is no golden-file coverage for this mode.
#
# Which agent runs: every fixture is handed to THIS working tree's
# security-reviewer subagent, not answered by Gemini CLI's main model and not by
# an installed copy. Gemini CLI has no flag that makes a subagent the session
# agent, so each call runs with a scratch GEMINI_CLI_HOME whose
# .gemini/extensions/ holds only a copy of this checkout's extension (manifest,
# GEMINI.md, agents/, commands/, skills/, packs/, modes/ — never fixtures/ or
# lib/, and nothing from the user's own ~/.gemini: no credentials, settings or
# login files), with that copy, and nothing wider, added to the workspace by
# --include-directories so the agent's read_file reaches its rule packs and
# mode files (W2482),
# `-e <extension name>` enabling only that copy, from an empty scratch working
# directory. The fixture prompt goes on stdin, never in the -p argument, so shell
# metacharacters in a diff are never interpreted; the -p directive names
# @security-reviewer and asks the main model to delegate the whole input to it.
# `-o stream-json` makes the delegation observable: a fixture is scored only
# when the stream shows an `invoke_agent` tool call naming that agent, and its
# result succeeded. Without one the fixture fails `agent not invoked` — the main
# model answering itself is never scored. Gemini CLI 0.65.0 does not stream a
# subagent's result (its invoke_agent tool_result carries no `output`), so the
# JSON scored is the main model's reply after that call returns; the prompt the
# main model delegated is kept in <stem>.agent_prompt.txt for triage.
# `--approval-mode default` keeps the headless policy, under which invoke_agent
# is allowed and the subagent's run_shell_command and write_file are denied, and
# `--skip-trust` trusts the scratch working directory for this process only
# (nothing is written to the user's trusted-folders list).
#
# Usage:
#   bash lib/run_eval.sh                            # all fixtures
#   bash lib/run_eval.sh --fixture <path>           # one fixture
#   bash lib/run_eval.sh --only <prefix>            # fixtures whose path starts with <prefix>
#                                                   #   e.g. --only considerations/
#   bash lib/run_eval.sh --dry-run                  # parser/comparator only; no API calls
#   bash lib/run_eval.sh --verbose                  # echo prompts and raw agent JSON
#
# Every run prints `# invocation: <argv>` and `# auth: <mode>` after the TAP
# plan line, so the exact gemini command (agent selection included) is on
# record; --dry-run prints it too without calling the CLI.
#
# Auth (not needed for --dry-run) is taken from the environment only, because
# the scratch home deliberately carries none of ~/.gemini: GEMINI_API_KEY;
# GOOGLE_GENAI_USE_VERTEXAI=true with GOOGLE_API_KEY, or with
# GOOGLE_CLOUD_PROJECT and GOOGLE_CLOUD_LOCATION; GOOGLE_GEMINI_BASE_URL; or
# GEMINI_CLI_USE_COMPUTE_ADC=true / CLOUD_SHELL=true. A login with Google
# (GOOGLE_GENAI_USE_GCA) needs the OAuth files under ~/.gemini and is refused.
# Only the mode name is printed, never a value. With no usable auth, exit 2. A
# CLI that still reports itself unauthenticated (exit 41) or the workspace
# untrusted (exit 55) stops the run with `Bail out!` and exit 2; a turn limit
# (exit 53) fails that fixture.
#
# Env:
#   GEMINI_CLI          path to the Gemini CLI (default: gemini)
#   EVAL_EXTENSION_DIR  extension directory to copy (default: this repo's root)
#   EVAL_AGENT          subagent to select (default: security-reviewer)
#   FIXTURES_DIR        default: <lib>/../fixtures
#   LOG_DIR             default: logs
#
# Logs per fixture: <stem>.raw.txt (the stream-json events), <stem>.err.txt
# (the CLI's stderr — auth and extension errors land here), <stem>.agent_prompt.txt
# (the prompt the main model passed to invoke_agent), <stem>.text.txt (the reply
# scored) and <stem>.json (the parsed document).
#
# Exit codes:
#   0  all fixtures pass
#   1  one or more fixtures fail
#   2  setup/usage error (missing dependency, bad args, no auth, an empty
#      fixture set, or a Bail out! on an unauthenticated CLI or untrusted workspace)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Default is CWD-independent (resolved from this script's location); override with
# FIXTURES_DIR to point at a copy elsewhere.
FIXTURES_DIR="${FIXTURES_DIR:-$SCRIPT_DIR/../fixtures}"
EXPECTED_FILE="${FIXTURES_DIR}/EXPECTED.md"
LOG_DIR="${LOG_DIR:-logs}"
GEMINI_CLI="${GEMINI_CLI:-gemini}"

ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
EXT_DIR="${EVAL_EXTENSION_DIR:-$ROOT_DIR}"
AGENT="${EVAL_AGENT:-security-reviewer}"
EXT_NAME=""

VERBOSE=0
DRY_RUN=0
SINGLE_FIXTURE=""
ONLY_PREFIX=""
AUTH_MODE=""
WORK_DIR=""
EVAL_CWD=""
EVAL_HOME=""
EVAL_ENV=()
GEMINI_ARGV=()

usage() {
  # Print the leading comment block (from line 3 to the first non-comment line).
  awk 'NR < 3 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 2
}

require_cmd() {
  command -v jq >/dev/null 2>&1 || die "jq not found on PATH"
  if [ "$DRY_RUN" -eq 0 ]; then
    command -v "$GEMINI_CLI" >/dev/null 2>&1 || die "$GEMINI_CLI not found on PATH (set GEMINI_CLI or pass --dry-run)"
    detect_auth
  else
    AUTH_MODE="dry-run"
  fi
  [ -f "$EXT_DIR/gemini-extension.json" ] || die "gemini-extension.json not found in $EXT_DIR (EVAL_EXTENSION_DIR)"
  EXT_NAME="$(jq -r '.name // empty' "$EXT_DIR/gemini-extension.json" 2>/dev/null || true)"
  [ -n "$EXT_NAME" ] || die "no extension name in $EXT_DIR/gemini-extension.json"
  [ -f "$EXT_DIR/agents/$AGENT.md" ] || die "agent $AGENT not found at $EXT_DIR/agents/$AGENT.md (EVAL_AGENT)"
  [ -f "$EXPECTED_FILE" ] || die "EXPECTED.md not found at $EXPECTED_FILE"
}

# detect_auth
# Sets AUTH_MODE from the environment Gemini CLI reads its auth from
# (@google/gemini-cli-core 0.65.0, core/contentGenerator.js), in the CLI's own
# order, or dies (exit 2). The scratch home carries none of ~/.gemini, so a
# stored login cannot be used. Prints only the mode name, never a value.
detect_auth() {
  if [ "${GOOGLE_GENAI_USE_GCA:-}" = "true" ]; then
    die "login with Google (GOOGLE_GENAI_USE_GCA) needs the OAuth files under ~/.gemini, which the eval deliberately does not copy; use GEMINI_API_KEY or Vertex AI, or pass --dry-run"
  fi
  if [ "${GOOGLE_GENAI_USE_VERTEXAI:-}" = "true" ]; then
    if [ -n "${GOOGLE_API_KEY:-}" ] || { [ -n "${GOOGLE_CLOUD_PROJECT:-}" ] && [ -n "${GOOGLE_CLOUD_LOCATION:-}" ]; }; then
      AUTH_MODE="vertex-ai"
      return 0
    fi
    die "GOOGLE_GENAI_USE_VERTEXAI=true needs GOOGLE_API_KEY, or GOOGLE_CLOUD_PROJECT and GOOGLE_CLOUD_LOCATION"
  fi
  if [ -n "${GOOGLE_GEMINI_BASE_URL:-}" ]; then
    AUTH_MODE="gateway"
    return 0
  fi
  if [ -n "${GEMINI_API_KEY:-}" ]; then
    AUTH_MODE="gemini-api-key"
    return 0
  fi
  if [ "${GEMINI_CLI_USE_COMPUTE_ADC:-}" = "true" ] || [ "${CLOUD_SHELL:-}" = "true" ]; then
    AUTH_MODE="compute-adc"
    return 0
  fi
  die "no Gemini auth: export GEMINI_API_KEY, or set GOOGLE_GENAI_USE_VERTEXAI=true with GOOGLE_API_KEY or GOOGLE_CLOUD_PROJECT+GOOGLE_CLOUD_LOCATION, or pass --dry-run"
}

# setup_scratch
# Creates WORK_DIR with an empty working directory (EVAL_CWD) and a scratch
# home (EVAL_HOME) whose .gemini/extensions/<name>/ holds an allow-listed copy
# of the extension. Runs under --dry-run too, so the invocation printed is the
# one a real run uses. Removed on exit.
setup_scratch() {
  WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/run_eval.XXXXXX")" || die "mktemp could not create a scratch directory"
  [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ] || die "mktemp returned no scratch directory"
  trap '[ -n "$WORK_DIR" ] && rm -rf "$WORK_DIR"' EXIT
  EVAL_CWD="$WORK_DIR/cwd"
  EVAL_HOME="$WORK_DIR/home"
  local dest="$EVAL_HOME/.gemini/extensions/$EXT_NAME"
  EVAL_EXT_DIR="$dest"
  mkdir -p "$EVAL_CWD" "$dest"
  local item
  for item in gemini-extension.json GEMINI.md agents commands skills packs modes; do
    [ -e "$EXT_DIR/$item" ] && cp -R "$EXT_DIR/$item" "$dest/"
  done
  return 0
}

# build_gemini_argv
# Fills EVAL_ENV and GEMINI_ARGV with the exact command each fixture runs: the
# scratch home, the -p directive selecting the subagent (the fixture itself goes
# on stdin), only this extension enabled, the stream-json event stream, the
# default approval mode and a process-only trust of the scratch directory.
# Credentials are inherited from the environment and never placed on argv.
build_gemini_argv() {
  local directive
  directive="@${AGENT} Delegate the security review of the input above to the ${AGENT} subagent: call invoke_agent once with agent_name ${AGENT} and, as its prompt, the entire input above verbatim. Do not review the input yourself and do not call any other tool. When the subagent returns, reply with only the single fenced json document from its result, unchanged."
  EVAL_ENV=(GEMINI_CLI_HOME="$EVAL_HOME")
  GEMINI_ARGV=(
    "$GEMINI_CLI" -p "$directive"
    -e "$EXT_NAME"
    --include-directories "$EVAL_EXT_DIR"
    -o stream-json
    --approval-mode default
    --skip-trust
  )
}

# print_invocation
# Prints `# invocation: env <env> <argv>` (shell-quoted) as a TAP comment line.
print_invocation() {
  printf '# invocation: env'
  printf ' %q' "${EVAL_ENV[@]}" "${GEMINI_ARGV[@]}"
  printf '\n'
}

# stream_events <raw-file>
# Emits the stream-json events in <raw-file> as one JSON array, skipping any
# line that is not a JSON object.
stream_events() {
  jq -Rs '[ split("\n")[] | fromjson? | select(type == "object") ]' "$1"
}

# agent_call_id <raw-file>
# Prints the tool_id of the first invoke_agent tool_use naming $AGENT, or
# nothing when the main model never delegated to it.
agent_call_id() {
  stream_events "$1" | jq -r --arg agent "$AGENT" '
    [ .[] | select(.type == "tool_use" and .tool_name == "invoke_agent"
                   and ((.parameters.agent_name // "") == $agent)) ]
    | first | .tool_id // empty'
}

# require_agent_call <tool-id>
# The guard that keeps a main-model answer from being scored: fails unless the
# stream showed an invoke_agent call to $AGENT.
require_agent_call() {
  [ -n "$1" ]
}

# parse_expected_md
# Reads $EXPECTED_FILE and emits one TAB-delimited record per expected finding:
#   path<TAB>class<TAB>severity<TAB>cwe_json<TAB>owasp_json<TAB>count
# `path` is relative to FIXTURES_DIR. The Bitbucket multi-finding row produces
# count=2; all other rows produce count=1.
parse_expected_md() {
  awk '
    /^- \[[ x]\] `[^`]+`/ {
      line = $0
      # filename: first backtick-fenced token
      match(line, /`[^`]+`/)
      path = substr(line, RSTART+1, RLENGTH-2)
      rest = substr(line, RSTART+RLENGTH)
      # negative-control marker: " → NONE" before any optional prose. Treat as count=0
      # with class/severity placeholders the comparator interprets as "no findings expected".
      if (rest ~ /^ +→ +NONE( |$)/ || rest ~ /^ +→ +NONE +—/) {
        printf "%s\t%s\t%s\t%s\t%s\t%d\n", path, "__NONE__", "__NONE__", "", "", 0
        next
      }
      # considerations-mode marker: " → CONSIDERATIONS <s1>,<s2>,... [AND finding|AND clean]".
      # Emits a record the considerations comparator interprets: class=__CONSIDERATIONS__,
      # severity=verdict CSV, cwe field carries the finding expectation (F=at least one
      # backing finding, C=zero findings, U=unchecked), count=number of verdicts.
      # U is a placeholder, never an empty field: the caller splits records with
      # IFS=TAB, and bash collapses consecutive tabs, which would shift fields.
      if (rest ~ /^ +→ +CONSIDERATIONS +/) {
        head = rest
        sub(/^ +→ +CONSIDERATIONS +/, "", head)
        fexp = "U"
        if (head ~ / AND +finding( |$|—)/) fexp = "F"
        else if (head ~ / AND +clean( |$|—)/) fexp = "C"
        split(head, hp, " ")
        verdicts = hp[1]
        nc = split(verdicts, vv, ",")
        printf "%s\t%s\t%s\t%s\t%s\t%d\n", path, "__CONSIDERATIONS__", verdicts, fexp, "", nc
        next
      }
      # class + severity: after → token, before first comma
      n = match(rest, /→ +[a-z_]+ +\([a-z]+\)/)
      if (n == 0) next
      head = substr(rest, RSTART, RLENGTH)
      gsub(/^→ +/, "", head)
      split(head, parts, " *\\(")
      cls = parts[1]
      sev = parts[2]
      sub(/\)$/, "", sev)
      # multi-finding marker: " AND " before the comma
      count = 1
      tail = substr(rest, RSTART+RLENGTH)
      if (tail ~ /^ +AND +[a-z_]+ +\([a-z]+\)/) {
        count = 2
      }
      # cwe array (first backticked block matching cwe:)
      cwe = ""
      if (match(line, /`cwe: \[[^]]*\]`/)) {
        cwe = substr(line, RSTART+1, RLENGTH-2)
        sub(/^cwe: /, "", cwe)
      }
      # owasp array
      owasp = ""
      if (match(line, /`owasp: \[[^]]*\]`/)) {
        owasp = substr(line, RSTART+1, RLENGTH-2)
        sub(/^owasp: /, "", owasp)
      }
      printf "%s\t%s\t%s\t%s\t%s\t%d\n", path, cls, sev, cwe, owasp, count
    }
  ' "$EXPECTED_FILE"
}

# sanitize_path <relative-path>
# Produces a filesystem-safe stem for log files: slashes and dots → underscores.
sanitize_path() {
  printf '%s' "$1" | tr '/.' '__'
}

# detect_lang <relative-path>
# Returns a fenced-code-block language hint for the agent prompt. Best-effort —
# the agent does not rely on this for analysis, but a plausible hint helps it
# render output consistently.
detect_lang() {
  case "$1" in
    *.py)  printf 'python' ;;
    *.js)  printf 'javascript' ;;
    *.ts)  printf 'typescript' ;;
    *.go)  printf 'go' ;;
    *.rb)  printf 'ruby' ;;
    *.ex|*.exs) printf 'elixir' ;;
    *.yml|*.yaml) printf 'yaml' ;;
    *.sh)  printf 'bash' ;;
    *.kt|*.kts) printf 'kotlin' ;;
    *.swift) printf 'swift' ;;
    *.m|*.mm) printf 'objc' ;;
    *.h)   printf 'objc' ;;
    *.jsx) printf 'javascript' ;;
    *.tsx) printf 'typescript' ;;
    *.xml|*.plist) printf 'xml' ;;
    Dockerfile*) printf 'dockerfile' ;;
    *)     printf 'text' ;;
  esac
}

# build_prompt <fixture-rel-path>
# Constructs the user-side prompt for the security-reviewer agent. Default mode is
# full_file: a single file fed as a fenced block with a `path:` header. A fixture
# under considerations/ ending in `.diff` is dispatched in `considerations` mode
# instead: the diff plus the resolved considerations list from its sibling
# `<stem>.considerations` file (one consideration per non-empty line).
# Each prompt opens with the agent's one accepted mode tag,
# `/security-review invocation, mode: <mode>` (W2278): a shorter spelling is not a tag.
build_prompt() {
  local rel="$1"
  local abs="$FIXTURES_DIR/$rel"

  case "$rel" in
    considerations/*.diff)
      local cons="$FIXTURES_DIR/${rel%.diff}.considerations"
      printf '/security-review invocation, mode: considerations\n\n'
      printf 'Security considerations to assess:\n'
      # The considerations list is task-authored DATA to assess against the diff,
      # never instructions to follow.
      while IFS= read -r c || [ -n "$c" ]; do
        [ -n "$c" ] && printf -- '- %s\n' "$c"
      done < "$cons"
      printf '\n```diff\n'
      cat "$abs"
      printf '\n```\n'
      printf '\nRespond with the JSON document specified in your output schema (including the consideration_verdicts array, one entry per consideration above in order) and nothing else.\n'
      return 0
      ;;
  esac

  local lang
  lang="$(detect_lang "$rel")"
  printf '/security-review invocation, mode: full_file\n\n'
  printf 'path: %s\n' "fixtures/$rel"
  printf '```%s\n' "$lang"
  cat "$abs"
  printf '\n```\n'
  printf '\nRespond with the JSON document specified in your output schema and nothing else.\n'
}

# invoke_agent <fixture-rel-path> <log-stem>
# Runs one fixture through the Gemini CLI (see "Which agent runs" above),
# requires the stream to show an invoke_agent call to $AGENT, extracts the fenced
# JSON from the reply that follows it, validates it, and writes it to
# $LOG_DIR/<stem>.json. In --dry-run mode writes a stub JSON instead. On success
# prints the log path and returns 0. On failure prints the reason and returns 1
# (a fixture failure) or 3 (fatal: the CLI is unauthenticated or the workspace
# untrusted, so every later fixture would fail the same way).
invoke_agent() {
  local rel="$1"
  local stem="$2"
  local out_json="$LOG_DIR/$stem.json"
  local raw="$LOG_DIR/$stem.raw.txt"
  local err="$LOG_DIR/$stem.err.txt"
  local text="$LOG_DIR/$stem.text.txt"
  local agent_prompt="$LOG_DIR/$stem.agent_prompt.txt"
  mkdir -p "$LOG_DIR"

  if [ "$DRY_RUN" -eq 1 ]; then
    printf '{"findings":[],"summary":{"files_reviewed":1,"findings_by_severity":{"critical":0,"high":0,"medium":0,"low":0,"info":0}}}\n' > "$out_json"
    printf '%s' "$out_json"
    return 0
  fi

  local prompt
  prompt="$(build_prompt "$rel")"

  if [ "$VERBOSE" -eq 1 ]; then
    printf '# --- prompt for %s ---\n%s\n# --- end prompt ---\n' "$rel" "$prompt" >&2
  fi

  # Each fixture starts from a clean session store, so fixtures stay independent.
  rm -rf "$EVAL_HOME/.gemini/tmp"

  # The fixture prompt goes on stdin (Gemini CLI prepends stdin to the -p text),
  # never into argv. The call runs from the empty EVAL_CWD; stderr is kept.
  local rc=0
  (cd "$EVAL_CWD" && printf '%s' "$prompt" | env "${EVAL_ENV[@]}" "${GEMINI_ARGV[@]}") > "$raw" 2> "$err" || rc=$?
  case "$rc" in
    0) ;;
    41) printf 'not authenticated (gemini exit 41; see %s)' "$err"; return 3 ;;
    55) printf 'workspace not trusted (gemini exit 55; see %s)' "$err"; return 3 ;;
    53) printf 'turn limit reached (gemini exit 53)'; return 1 ;;
    *)  printf 'agent invocation failed (gemini exit %s)' "$rc"; return 1 ;;
  esac

  local call_id
  call_id="$(agent_call_id "$raw")"
  require_agent_call "$call_id" || { printf 'agent not invoked'; return 1; }

  # The prompt the main model delegated: advisory check that it carried the
  # fixture rather than a paraphrase of it.
  stream_events "$raw" | jq -r --arg id "$call_id" '
    [ .[] | select(.type == "tool_use" and .tool_id == $id) ] | first
    | .parameters.prompt // "" | tostring' > "$agent_prompt"
  local mode_line="${prompt%%$'\n'*}"
  if ! grep -qF -- "$mode_line" "$agent_prompt"; then
    printf '# warn: %s — the delegated prompt does not carry the fixture verbatim (see %s)\n' "$rel" "$agent_prompt" >&2
  fi

  local status
  status="$(stream_events "$raw" | jq -r --arg id "$call_id" '
    [ .[] | select(.type == "tool_result" and .tool_id == $id) ] | first | .status // empty')"
  if [ "$status" != "success" ]; then
    printf 'agent invocation failed: invoke_agent returned %s' "${status:-no result}"
    return 1
  fi

  # The reply: the invoke_agent result's own output when the CLI streams one,
  # otherwise the assistant text that follows the result (Gemini CLI 0.65.0
  # relays the subagent's result through the main model and streams no output).
  stream_events "$raw" | jq -r --arg id "$call_id" '
    . as $ev
    | ([ $ev[] | select(.type == "tool_result" and .tool_id == $id) ] | first) as $res
    | if (($res.output | type) == "string") and ($res.output | length) > 0 then $res.output
      else
        ($ev | map(.type == "tool_result" and .tool_id == $id) | index(true)) as $i
        | [ $ev[($i + 1):][]
            | select(.type == "message" and .role == "assistant")
            | .content // "" | tostring ] | join("")
      end' > "$text"

  # Extract the first fenced ```json block. Fall back to the whole reply if no fence.
  if grep -q '^```json$' "$text"; then
    awk '/^```json$/{flag=1;next} /^```$/{if(flag){exit}} flag' "$text" > "$out_json"
  else
    cp "$text" "$out_json"
  fi

  if ! jq -e . "$out_json" >/dev/null 2>&1; then
    printf 'agent invocation failed: no JSON document in the reply (see %s)' "$text"
    return 1
  fi

  if [ "$VERBOSE" -eq 1 ]; then
    printf '# --- agent JSON for %s ---\n' "$rel" >&2
    jq . "$out_json" >&2
    printf '# --- end JSON ---\n' >&2
  fi

  printf '%s' "$out_json"
}

# compare_finding <path> <class> <sev> <cwe_json> <owasp_json> <count> <json_file>
# Returns 0 if the agent JSON contains at least <count> findings matching
# (file basename or suffix, class, severity). Emits a diff-style block on
# stderr when the comparison fails. CWE/OWASP mismatches are advisory warnings.
compare_finding() {
  local rel="$1" cls="$2" sev="$3" cwe="$4" owasp="$5" count="$6" json="$7"

  # Match findings whose file equals the relative path OR ends with the basename.
  # The agent may report file as "fixtures/sql_injection.py" or just
  # "sql_injection.py" depending on prompt handling.
  local base
  base="$(basename "$rel")"

  # Considerations-mode case (EXPECTED.md row → CONSIDERATIONS; cls="__CONSIDERATIONS__").
  # `sev` carries the expected ordered verdict CSV; `cwe` carries the finding
  # expectation (F=at least one backing finding, C=zero findings, U=unchecked).
  # Assert the agent's consideration_verdicts[].status list matches, in order.
  if [ "$cls" = "__CONSIDERATIONS__" ]; then
    local exp_verdicts="$sev" fexp="$cwe"
    local got_verdicts
    got_verdicts=$(jq -r '[ .consideration_verdicts // [] | .[] | .status ] | join(",")' "$json")
    local n_findings
    n_findings=$(jq '[ .findings // [] | .[] ] | length' "$json")
    local ok=1 detail=""
    if [ "$got_verdicts" != "$exp_verdicts" ]; then
      ok=0
      detail="verdicts expected [$exp_verdicts] got [$got_verdicts]"
    fi
    if [ "$fexp" = "F" ] && [ "$n_findings" -lt 1 ]; then
      ok=0
      detail="${detail:+$detail; }expected at least one backing finding, got 0"
    elif [ "$fexp" = "C" ] && [ "$n_findings" -ne 0 ]; then
      ok=0
      detail="${detail:+$detail; }negative control expected 0 findings, got $n_findings"
    fi
    if [ "$ok" -eq 0 ]; then
      cat >&2 <<EOF
  --- expected ($json)
  - considerations [$exp_verdicts] ($fexp)
  + $detail
EOF
      return 1
    fi
    return 0
  fi

  # Negative-control case (EXPECTED.md row → NONE; cls="__NONE__", count=0):
  # the fixture must produce ZERO findings of any class on this file.
  if [ "$cls" = "__NONE__" ]; then
    local any_count
    any_count=$(jq --arg rel "$rel" --arg base "$base" '
      [ .findings // []
        | .[]
        | select(
            .file == $rel
            or .file == $base
            or (.file | endswith("/" + $rel))
            or (.file | endswith("/" + $base))
          )
      ] | length
    ' "$json")
    if [ "$any_count" -gt 0 ]; then
      local actual
      actual=$(jq --arg rel "$rel" --arg base "$base" '
        [ .findings // []
          | .[]
          | select(
              .file == $rel
              or .file == $base
              or (.file | endswith("/" + $rel))
              or (.file | endswith("/" + $base))
            )
          | "\(.vulnerability_class)/\(.severity)"
        ] | join(", ")
      ' "$json")
      actual=${actual//\"/}
      cat >&2 <<EOF
  --- expected
  +++ actual ($json)
  - (none) — negative control
  + $actual
EOF
      return 1
    fi
    return 0
  fi

  local match_count
  match_count=$(jq --arg rel "$rel" --arg base "$base" --arg cls "$cls" --arg sev "$sev" '
    [ .findings // []
      | .[]
      | select(
          .file == $rel
          or .file == $base
          or (.file | endswith("/" + $rel))
          or (.file | endswith("/" + $base))
        )
      | select(.vulnerability_class == $cls and .severity == $sev)
    ] | length
  ' "$json")

  if [ "$match_count" -lt "$count" ]; then
    # Failure — build a diff-style report on stderr.
    local actual
    actual=$(jq --arg rel "$rel" --arg base "$base" '
      [ .findings // []
        | .[]
        | select(
            .file == $rel
            or .file == $base
            or (.file | endswith("/" + $rel))
            or (.file | endswith("/" + $base))
          )
        | "\(.vulnerability_class)/\(.severity)"
      ] | join(", ")
    ' "$json")
    actual=${actual//\"/}
    [ -n "$actual" ] || actual='(none)'
    cat >&2 <<EOF
  --- expected
  +++ actual ($json)
  - $cls/$sev x$count
  + $actual
EOF
    return 1
  fi

  # Advisory: check CWE / OWASP overlap on any matching finding.
  if [ -n "$cwe" ] && [ "$cwe" != "[]" ]; then
    local cwe_overlap
    cwe_overlap=$(jq --arg rel "$rel" --arg base "$base" --arg cls "$cls" --arg sev "$sev" --argjson exp "$cwe" '
      [ .findings // []
        | .[]
        | select(
            .file == $rel
            or .file == $base
            or (.file | endswith("/" + $rel))
            or (.file | endswith("/" + $base))
          )
        | select(.vulnerability_class == $cls and .severity == $sev)
        | (.cwe // []) - ((.cwe // []) - $exp)
      ] | add // []
    ' "$json")
    if [ "$cwe_overlap" = "[]" ]; then
      printf '# warn: %s — no CWE overlap with expected %s\n' "$rel" "$cwe" >&2
    fi
  fi
  if [ -n "$owasp" ] && [ "$owasp" != "[]" ]; then
    local owasp_overlap
    owasp_overlap=$(jq --arg rel "$rel" --arg base "$base" --arg cls "$cls" --arg sev "$sev" --argjson exp "$owasp" '
      [ .findings // []
        | .[]
        | select(
            .file == $rel
            or .file == $base
            or (.file | endswith("/" + $rel))
            or (.file | endswith("/" + $base))
          )
        | select(.vulnerability_class == $cls and .severity == $sev)
        | (.owasp // []) - ((.owasp // []) - $exp)
      ] | add // []
    ' "$json")
    if [ "$owasp_overlap" = "[]" ]; then
      printf '# warn: %s — no OWASP overlap with expected %s\n' "$rel" "$owasp" >&2
    fi
  fi

  return 0
}

# emit_tap <n> <status> <fixture> <detail>
emit_tap() {
  local n="$1" status="$2" fixture="$3" detail="$4"
  printf '%s %d - %s (%s)\n' "$status" "$n" "$fixture" "$detail"
}

# validate_findings_schema <json_file>
# Asserts every finding in the agent JSON carries the full documented per-finding
# schema (severity, file, line, vulnerability_class, cwe, owasp, description,
# remediation, confidence) AND that cwe/owasp are non-empty arrays for every
# non-info finding (the plugin's contract is that concrete findings always map to
# a CWE and OWASP category). Prints each offending finding to stderr and returns
# 1 on any violation; returns 0 when all findings conform (including the empty
# findings list a clean fixture or the --dry-run stub produces).
validate_findings_schema() {
  local json="$1"
  local required='["severity","file","line","vulnerability_class","cwe","owasp","description","remediation","confidence"]'
  local violations
  violations=$(jq -r --argjson req "$required" '
    [ .findings // []
      | to_entries[]
      | .key as $i | .value as $f
      | ([ $req[] | . as $k | select(($f | has($k)) | not) ]) as $missing
      | (if ($f.severity != "info")
           and ((((($f.cwe) // []) | length) == 0) or (((($f.owasp) // []) | length) == 0))
         then ["cwe/owasp empty for non-info finding"] else [] end) as $cweowasp
      | ($missing + $cweowasp) as $problems
      | select(($problems | length) > 0)
      | "finding[\($i)] \($f.vulnerability_class // "?")@\($f.file // "?"):\($f.line // "?") — \($problems | join("; "))"
    ] | .[]
  ' "$json" 2>/dev/null || true)
  if [ -n "$violations" ]; then
    {
      printf '  --- schema violation (%s)\n' "$json"
      printf '  %s\n' "$violations"
    } >&2
    return 1
  fi
  return 0
}

main() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --verbose) VERBOSE=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      --fixture)
        [ $# -ge 2 ] || die "--fixture requires an argument"
        SINGLE_FIXTURE="$2"
        shift 2
        ;;
      --only)
        [ $# -ge 2 ] || die "--only requires an argument"
        ONLY_PREFIX="$2"
        shift 2
        ;;
      --fixtures-dir)
        [ $# -ge 2 ] || die "--fixtures-dir requires an argument"
        FIXTURES_DIR="$2"
        EXPECTED_FILE="${FIXTURES_DIR}/EXPECTED.md"
        shift 2
        ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown argument: $1" ;;
    esac
  done

  require_cmd

  local records=()
  while IFS= read -r line; do
    [ -n "$line" ] && records+=("$line")
  done < <(parse_expected_md)

  if [ "${#records[@]}" -eq 0 ]; then
    die "no fixture expectations parsed from $EXPECTED_FILE (0 cases) — an empty fixture set is not a pass"
  fi

  # Filter to single fixture if requested.
  if [ -n "$SINGLE_FIXTURE" ]; then
    local needle="$SINGLE_FIXTURE"
    needle="${needle#"$FIXTURES_DIR/"}"
    local filtered=()
    for r in "${records[@]}"; do
      local p="${r%%	*}"
      if [ "$p" = "$needle" ]; then
        filtered+=("$r")
      fi
    done
    if [ "${#filtered[@]}" -eq 0 ]; then
      die "fixture $SINGLE_FIXTURE not found in $EXPECTED_FILE"
    fi
    records=("${filtered[@]}")
  fi

  # Filter to a path prefix if requested (e.g. --only considerations/).
  if [ -n "$ONLY_PREFIX" ]; then
    local prefix="$ONLY_PREFIX"
    prefix="${prefix#"$FIXTURES_DIR/"}"
    local kept=()
    for r in "${records[@]}"; do
      local p="${r%%	*}"
      case "$p" in
        "$prefix"*) kept+=("$r") ;;
      esac
    done
    if [ "${#kept[@]}" -eq 0 ]; then
      die "no fixture in $EXPECTED_FILE matches --only $ONLY_PREFIX (0 cases)"
    fi
    records=("${kept[@]}")
  fi

  # LOG_DIR must be absolute: invoke_agent runs the CLI from inside EVAL_CWD.
  mkdir -p "$LOG_DIR"
  LOG_DIR="$(cd "$LOG_DIR" && pwd)"
  setup_scratch
  build_gemini_argv

  local total="${#records[@]}"
  printf 'TAP version 13\n'
  printf '1..%d\n' "$total"
  print_invocation
  printf '# auth: %s\n' "$AUTH_MODE"

  local n=0 fails=0
  for rec in "${records[@]}"; do
    n=$((n+1))
    IFS=$'\t' read -r path cls sev cwe owasp count <<<"$rec"
    local stem
    stem="$(sanitize_path "$path")"
    local detail
    if [ "$cls" = "__NONE__" ]; then
      detail="negative control"
    elif [ "$cls" = "__CONSIDERATIONS__" ]; then
      detail="considerations: $sev ($cwe)"
    else
      detail="$cls/$sev"
      [ "$count" -gt 1 ] && detail="$detail x$count"
    fi

    local json irc=0
    json="$(invoke_agent "$path" "$stem")" || irc=$?
    if [ "$irc" -ne 0 ]; then
      local reason="${json:-agent invocation failed}"
      emit_tap "$n" "not ok" "$path" "$detail ($reason)"
      fails=$((fails+1))
      if [ "$irc" -eq 3 ]; then
        printf 'Bail out! %s\n' "$reason"
        exit 2
      fi
      continue
    fi

    if ! validate_findings_schema "$json"; then
      emit_tap "$n" "not ok" "$path" "$detail (schema violation)"
      fails=$((fails+1))
      continue
    fi

    if compare_finding "$path" "$cls" "$sev" "$cwe" "$owasp" "$count" "$json"; then
      emit_tap "$n" "ok" "$path" "$detail"
    else
      emit_tap "$n" "not ok" "$path" "$detail"
      fails=$((fails+1))
    fi
  done

  local passed=$((total - fails))
  printf '# %d/%d passed\n' "$passed" "$total"
  if [ "$fails" -gt 0 ]; then
    printf '# logs/ contains raw agent output for each fixture\n'
    exit 1
  fi
  exit 0
}

main "$@"
