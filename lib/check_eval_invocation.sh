#!/usr/bin/env bash
# Model-free checks on how lib/run_eval.sh invokes the agent.
#
# Ported from upstream cheezy/stride-security-review scripts/check_eval_invocation.sh
# (W2274, ea06aeb). The eval is only worth running if it scores THIS checkout's
# security-reviewer subagent rather than Gemini CLI's main model answering in
# its place. That is a property of the gemini argv, its environment and the
# stream-json events the runner accepts, so it can be checked without a model,
# credentials or network. Every case below puts a fake `gemini` first on a
# PATH inside this script's own temporary directory; the fake is removed with
# that directory on exit, a guard refuses to run if `gemini` would resolve
# anywhere else, and the real CLI is never called.
#
#   1. --dry-run prints the invocation: @security-reviewer in the -p directive,
#      `-e stride-gemini-security-review`, `-o stream-json`,
#      `--approval-mode default`, `--skip-trust`, a scratch GEMINI_CLI_HOME
#      outside the repo, and none of the fixture's text in argv.
#   2. A fake CLI records what run_eval.sh actually executed (matrix row 0):
#      the agent selection, an empty cwd outside the repo, a scratch home holding
#      only an allow-listed copy of this extension (no credentials, no fixtures),
#      the user's HOME untouched, the considerations-mode prompt on stdin and not
#      in -p. A canned delegation scores `ok`; the auth value is never printed.
#      Each prompt opens with the agent's one mode tag on its own line,
#      `/security-review invocation, mode: considerations` or `..., mode:
#      full_file` (W2278, upstream a01cb19), never a bare `mode:` line.
#   3. Fixture text with quotes, `$` and a command substitution reaches the CLI
#      on stdin byte for byte and is never interpreted.
#   4. With no usable auth in the environment the run refuses with exit 2 and
#      never dispatches; a Google login and an incomplete Vertex setup refuse too.
#   5. An unauthenticated CLI (exit 41) stops the run non-zero with a clear
#      message (matrix row 2).
#   6. A turn limit (exit 53) fails the fixture.
#   7. The main model answering without delegating, delegating to another
#      agent, or a failed invoke_agent result, each fails the fixture.
#   8. Break-its on a scratch copy of run_eval.sh (matrix row 6): dropping the
#      agent selection from the invocation fails the checks above, and dropping
#      the agent-name filter lets another agent's answer score. Reverting the
#      prompt to the bare `mode: considerations` and `mode: full_file` lines
#      fails the tag checks (W2278).
#   9. An empty fixture set reports zero cases and exits 2 instead of passing
#      (matrix row 3), as does --only with no match.
#  10. --only <prefix> keeps exactly the matching rows.
#  11. A considerations row with no AND clause parses with the explicit `U`
#      marker, and a fixture name containing a space survives the round trip.
#  12. check_fixtures.sh rejects a considerations .diff with no sidecar, a
#      sidecar with no .diff, a verdict-count mismatch, a fixture with no row and
#      a row with no fixture (matrix row 1), against a scratch copy of the tree.
#
# Upstream's fourth check, the CI key gate in .github/workflows/eval.yml, does
# not apply: this extension has no CI workflow, so the eval runs locally only.
#
# Offline and read-only towards the repo. Resolves everything relative to this
# script's own location, so it works from any CWD.
#
# Usage:  bash lib/check_eval_invocation.sh
# Exit code: 0 when every check passes, 1 otherwise.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RUN_EVAL="$SCRIPT_DIR/run_eval.sh"
FIXTURE="considerations/token_logging_unmitigated.diff"
AGENT_ID="security-reviewer"
EXT_NAME="stride-gemini-security-review"
KEY_SENTINEL="FAKE_KEY_SENTINEL_not_a_real_key"

# Stop before anything else when mktemp fails: an empty TMP would put the fake
# CLI in /bin, the records in /rec-* and every scratch copy at the root.
TMP="$(mktemp -d "${TMPDIR:-/tmp}/check_eval_invocation.XXXXXX")" || {
  echo "FAIL: mktemp could not create a scratch directory"
  exit 1
}
if [ -z "$TMP" ] || [ ! -d "$TMP" ]; then
  echo "FAIL: mktemp returned no scratch directory"
  exit 1
fi
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/tmpdir" "$TMP/bin"

fail=0
check() { # $1=label; remaining args = a test command
  local label="$1"
  shift
  if "$@"; then
    echo "ok: $label"
  else
    echo "FAIL: $label"
    fail=1
  fi
}
contains() { grep -qF -- "$2" "$1"; }
lacks() { ! grep -qF -- "$2" "$1"; }
fails() { ! "$@"; }
# W2278: the agent's one accepted mode tag, as upstream a01cb19 spells it.
CONS_TAG='/security-review invocation, mode: considerations'
FF_TAG='/security-review invocation, mode: full_file'
opens_with() { [ "$(head -n 1 "$1" 2>/dev/null)" = "$2" ]; }
outside_repo() { case "$1" in "$ROOT_DIR"|"$ROOT_DIR"/*|'') return 1 ;; *) return 0 ;; esac; }
jq_holds() { jq -e "$2" "$1" >/dev/null 2>&1; }
none_has_sentinel() { ! grep -rqF -- "$KEY_SENTINEL" "$@" 2>/dev/null; }

cd "$ROOT_DIR" || exit 1

# --- the fake CLI ---------------------------------------------------------------
# Records its own path, argv, cwd, environment, scratch home and stdin, then
# prints a stream-json event stream shaped like Gemini CLI 0.65.0's: init, the
# echoed user message, then — when the -p directive selects @security-reviewer —
# an invoke_agent tool_use and its tool_result (with no `output`, as 0.65.0
# streams it), the reply split across two assistant deltas, and a result event.
# Without the selection it answers directly, as a main model that never
# delegated would.
FAKE="$TMP/bin/gemini"
cat > "$FAKE" <<'FAKE_EOF'
#!/usr/bin/env bash
R="${FAKE_REC:?}"
printf '%s\n' "$0" > "$R/self"
printf '%s\n' "$@" > "$R/argv"
pval=""
prev=""
for a in "$@"; do
  [ "$prev" = "-p" ] && pval="$a"
  prev="$a"
done
printf '%s' "$pval" > "$R/pval"
pwd > "$R/pwd"
ls -A | wc -l | tr -d ' ' > "$R/cwd_count"
printf '%s\n' "${GEMINI_CLI_HOME:-}" > "$R/cli_home"
printf '%s\n' "${HOME:-}" > "$R/home"
H="${GEMINI_CLI_HOME:-/nonexistent}"
ls -A "$H" > "$R/home_ls" 2>/dev/null
ls -A "$H/.gemini" > "$R/dotgemini_ls" 2>/dev/null
ls -A "$H/.gemini/extensions" > "$R/extensions_ls" 2>/dev/null
ext="$(head -n 1 "$R/extensions_ls" 2>/dev/null)"
ls -A "$H/.gemini/extensions/$ext" > "$R/ext_ls" 2>/dev/null
cp "$H/.gemini/extensions/$ext/agents/security-reviewer.md" "$R/agent.md" 2>/dev/null
cp "$H/.gemini/extensions/$ext/packs/phoenix.md" "$R/phoenix.md" 2>/dev/null
cp "$H/.gemini/extensions/$ext/modes/considerations.md" "$R/considerations.md" 2>/dev/null
stdin="$(cat)"
printf '%s' "$stdin" > "$R/stdin"
case "${FAKE_EXIT:-0}" in
  41) echo 'Please set an Auth method in your settings.json or specify an environment variable' >&2; exit 41 ;;
  55) echo 'Gemini CLI is not running in a trusted directory' >&2; exit 55 ;;
  53)
    printf '%s\n' '{"type":"init","session_id":"fake","model":"fake-model"}'
    printf '%s\n' '{"type":"result","status":"error","error":{"type":"FatalTurnLimitedError","message":"Reached max session turns"}}'
    exit 53 ;;
esac
reply='```json
{"findings":[{"severity":"critical","file":"app/users.py","line":12,"vulnerability_class":"injection","cwe":["CWE-89"],"owasp":["A03:2021"],"description":"fake","remediation":"fake","confidence":"high"}],
 "consideration_verdicts":[{"consideration":"a","status":"unmitigated"},{"consideration":"b","status":"mitigated"}]}
```'
printf '%s\n' '{"type":"init","session_id":"fake","model":"fake-model"}'
jq -cn --arg t "$stdin

$pval" '{type: "message", role: "user", content: $t}'
case "$pval" in
  *"@security-reviewer"*)
    if [ "${FAKE_NO_DELEGATE:-0}" != "1" ]; then
      jq -cn --arg a "${FAKE_AGENT_NAME:-security-reviewer}" --arg p "$stdin" \
        '{type: "tool_use", tool_name: "invoke_agent", tool_id: "call_1", parameters: {agent_name: $a, prompt: $p}}'
      jq -cn --arg s "${FAKE_TOOL_STATUS:-success}" '{type: "tool_result", tool_id: "call_1", status: $s}'
    fi
    ;;
esac
jq -cn --arg t "${reply:0:20}" '{type: "message", role: "assistant", content: $t, delta: true}'
jq -cn --arg t "${reply:20}" '{type: "message", role: "assistant", content: $t, delta: true}'
printf '%s\n' '{"type":"result","status":"success","stats":{}}'
exit 0
FAKE_EOF
chmod +x "$FAKE"

# Guard: `gemini` must resolve to the fake on the PATH every case uses, so no
# case can ever reach a real CLI.
if [ "$(PATH="$TMP/bin:$PATH" command -v gemini)" != "$FAKE" ]; then
  echo "FAIL: gemini does not resolve to the fake CLI on the test PATH"
  exit 1
fi

# The auth variables Gemini CLI reads, unset in every case so the operator's own
# environment can neither satisfy nor break a check.
AUTH_UNSET=(-u GEMINI_CLI -u GEMINI_API_KEY -u GOOGLE_API_KEY -u GOOGLE_GENAI_USE_GCA
  -u GOOGLE_GENAI_USE_VERTEXAI -u GOOGLE_CLOUD_PROJECT -u GOOGLE_CLOUD_LOCATION
  -u GOOGLE_GEMINI_BASE_URL -u GEMINI_CLI_USE_COMPUTE_ADC -u CLOUD_SHELL)

# run_case <name> [env assignments...] -- [run_eval.sh args...]
# Runs run_eval.sh (or $RUNNER when set) against the fake CLI with a fresh
# record dir, the fake key, and TMPDIR inside $TMP, writing combined output to
# $TMP/<name>.out and the exit code to $TMP/<name>.rc.
run_case() {
  local name="$1"
  shift
  local envs=()
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do envs+=("$1"); shift; done
  [ $# -gt 0 ] && shift
  mkdir -p "$TMP/rec-$name"
  env "${AUTH_UNSET[@]}" PATH="$TMP/bin:$PATH" GEMINI_API_KEY="$KEY_SENTINEL" \
    FAKE_REC="$TMP/rec-$name" TMPDIR="$TMP/tmpdir" LOG_DIR="$TMP/logs-$name" \
    ${envs[@]+"${envs[@]}"} \
    bash "${RUNNER:-$RUN_EVAL}" "$@" > "$TMP/$name.out" 2>&1
  echo "$?" > "$TMP/$name.rc"
}
rc_of() { cat "$TMP/$1.rc"; }
LOGSTEM="considerations_token_logging_unmitigated_diff"

# --- 1. dry-run prints the exact invocation --------------------------------
before_ls="$(ls -A "$ROOT_DIR")"
run_case dry -- --dry-run --fixture "$FIXTURE"
grep '^# invocation:' "$TMP/dry.out" > "$TMP/dry.inv" || true
order="$(grep -nE '^(1\.\.[0-9]+|# invocation:|# auth:)' "$TMP/dry.out" | cut -d: -f1 | tr '\n' ' ')"

check "dry-run prints an invocation line"            test -s "$TMP/dry.inv"
check "the plan, invocation and auth lines are in order" test "$order" = "2 3 4 "
check "the invocation selects @$AGENT_ID"            contains "$TMP/dry.inv" "@$AGENT_ID"
check "the invocation enables only this extension"   contains "$TMP/dry.inv" "-e $EXT_NAME"
check "the invocation asks for the event stream"     contains "$TMP/dry.inv" "-o stream-json"
check "the invocation keeps the default approval mode" contains "$TMP/dry.inv" "--approval-mode default"
check "the invocation trusts only for this process"  contains "$TMP/dry.inv" "--skip-trust"
check "the invocation never runs in yolo mode"       lacks "$TMP/dry.inv" "yolo"
check "the invocation sets a scratch GEMINI_CLI_HOME" contains "$TMP/dry.inv" "GEMINI_CLI_HOME="
check "the scratch home is not in the repo"          lacks "$TMP/dry.inv" "GEMINI_CLI_HOME=$(printf '%q' "$ROOT_DIR")"
check "the invocation is not the old role-play prompt" lacks "$TMP/dry.inv" "Act as the security-reviewer agent"
check "the fixture is not in argv"                   lacks "$TMP/dry.inv" "request.args"
check "dry-run reports its auth mode"                contains "$TMP/dry.out" "# auth: dry-run"
check "dry-run left the repo root unchanged"         test "$before_ls" = "$(ls -A "$ROOT_DIR")"
check "dry-run removed its scratch directory"        test -z "$(ls -A "$TMP/tmpdir")"

run_case badtmp TMPDIR="$TMP/no-such-dir" -- --dry-run --fixture "$FIXTURE"
check "a scratch directory mktemp cannot make exits 2" test "$(rc_of badtmp)" -eq 2
check "the failure names mktemp"                     contains "$TMP/badtmp.out" "mktemp could not create a scratch directory"

# --- 2. a fake CLI records what was really executed -------------------------
run_case fake -- --fixture "$FIXTURE"
R="$TMP/rec-fake"
L="$TMP/logs-fake"
want_ext_ls="$(cd "$ROOT_DIR" && for i in gemini-extension.json GEMINI.md agents commands skills packs modes; do [ -e "$i" ] && echo "$i"; done | LC_ALL=C sort)"

check "a canned delegation scores ok (exit 0)"       test "$(rc_of fake)" -eq 0
check "the TAP line is ok"                           contains "$TMP/fake.out" "ok 1 - $FIXTURE"
check "an API key in the environment is accepted"    contains "$TMP/fake.out" "# auth: gemini-api-key"
check "the fake CLI is what ran"                     test "$(cat "$R/self" 2>/dev/null)" = "$FAKE"
check "the CLI received -e"                          grep -qxF -- "-e" "$R/argv"
check "the CLI received $EXT_NAME"                   grep -qxF -- "$EXT_NAME" "$R/argv"
check "the CLI received stream-json"                 grep -qxF -- "stream-json" "$R/argv"
check "the -p directive starts with @$AGENT_ID"      test "$(head -c $(( ${#AGENT_ID} + 1 )) "$R/pval")" = "@$AGENT_ID"
check "the CLI ran outside the repo"                 outside_repo "$(cat "$R/pwd" 2>/dev/null)"
check "the CLI ran from an empty directory"          test "$(cat "$R/cwd_count" 2>/dev/null)" = "0"
check "GEMINI_CLI_HOME is outside the repo"          outside_repo "$(cat "$R/cli_home" 2>/dev/null)"
check "the scratch home holds only .gemini"          test "$(cat "$R/home_ls" 2>/dev/null)" = ".gemini"
check "its .gemini holds only extensions"            test "$(cat "$R/dotgemini_ls" 2>/dev/null)" = "extensions"
check "extensions holds only this extension"         test "$(cat "$R/extensions_ls" 2>/dev/null)" = "$EXT_NAME"
check "the copy holds exactly the allow-list"        test "$(LC_ALL=C sort "$R/ext_ls" 2>/dev/null)" = "$want_ext_ls"
check "the copy carries this checkout's agent"       cmp -s "$R/agent.md" "$ROOT_DIR/agents/security-reviewer.md"
check "the copy carries this checkout's packs/phoenix.md" cmp -s "$R/phoenix.md" "$ROOT_DIR/packs/phoenix.md"
check "the copy carries this checkout's modes/considerations.md" cmp -s "$R/considerations.md" "$ROOT_DIR/modes/considerations.md"
check "the workspace adds exactly the extension copy" test "$(awk 'p { print; exit } $0 == "--include-directories" { p = 1 }' "$R/argv")" = "$(cat "$R/cli_home" 2>/dev/null)/.gemini/extensions/$EXT_NAME"
check "the CLI received one --include-directories"   test "$(grep -cxF -- "--include-directories" "$R/argv")" = 1
check "the user's HOME is left as it is"             test "$(cat "$R/home" 2>/dev/null)" = "${HOME:-}"
check "the prompt is in considerations mode"         contains "$R/stdin" "$CONS_TAG"
check "the prompt opens with the considerations tag on its own line" opens_with "$R/stdin" "$CONS_TAG"
check "the prompt carries the sidecar's first line"  contains "$R/stdin" "$(head -n 1 "$ROOT_DIR/fixtures/${FIXTURE%.diff}.considerations")"
check "the -p directive carries no fixture text"     lacks "$R/pval" "mode: considerations"
check "the CLI's stderr is kept"                     test -f "$L/$LOGSTEM.err.txt"
check "the event stream is kept"                     contains "$L/$LOGSTEM.raw.txt" '"invoke_agent"'
check "the delegated prompt is kept"                 contains "$L/$LOGSTEM.agent_prompt.txt" "$CONS_TAG"
check "the reply was joined from the assistant deltas" jq_holds "$L/$LOGSTEM.json" '.consideration_verdicts | length == 2'
check "the key never reaches output or logs"         none_has_sentinel "$TMP/fake.out" "$L"
check "the runner removed its scratch directory"     test -z "$(ls -A "$TMP/tmpdir")"

# --- 3. quotes, $ and a command substitution stay data ----------------------
QX="$TMP/qx"
mkdir -p "$QX/considerations"
cat > "$QX/considerations/quotes.diff" <<'QEOF'
diff --git a/app/q.py b/app/q.py
--- a/app/q.py
+++ b/app/q.py
@@ -1,2 +1,4 @@
+msg = "double \"quoted\" text" + 'single quoted'
+cmd = "$HOME and $(touch PWNED_PATH) and `touch PWNED_PATH`"
QEOF
sed "s|PWNED_PATH|$TMP/pwned|g" "$QX/considerations/quotes.diff" > "$QX/q.tmp" && mv "$QX/q.tmp" "$QX/considerations/quotes.diff"
printf '%s\n' 'Input with "quotes" and $VARS is treated as data' 'Nothing runs $(id)' > "$QX/considerations/quotes.considerations"
printf -- '- [ ] `considerations/quotes.diff` → CONSIDERATIONS unmitigated,mitigated AND finding — quoting row\n' > "$QX/EXPECTED.md"
run_case quotes -- --fixtures-dir "$QX"
check "a fixture with quotes and \$ scores ok"        test "$(rc_of quotes)" -eq 0
check "the double-quoted line reaches stdin intact"  contains "$TMP/rec-quotes/stdin" "msg = \"double \\\"quoted\\\" text\" + 'single quoted'"
check "the \$ line reaches stdin intact"             contains "$TMP/rec-quotes/stdin" "cmd = \"\$HOME and \$(touch $TMP/pwned) and \`touch $TMP/pwned\`\""
check "the sidecar's \$ text reaches stdin intact"   contains "$TMP/rec-quotes/stdin" 'Nothing runs $(id)'
check "the fixture text is not in -p"                lacks "$TMP/rec-quotes/pval" "touch"
check "no command in the fixture ran"                test ! -e "$TMP/pwned"

# --- 4. no usable auth refuses -----------------------------------------------
# env -i so a real key exported in this shell cannot make it pass.
mkdir -p "$TMP/rec-noauth" "$TMP/home"
env -i PATH="$TMP/bin:$PATH" HOME="$TMP/home" TMPDIR="$TMP/tmpdir" \
  FAKE_REC="$TMP/rec-noauth" LOG_DIR="$TMP/logs-noauth" \
  bash "$RUN_EVAL" --fixture "$FIXTURE" > "$TMP/noauth.out" 2>&1
echo "$?" > "$TMP/noauth.rc"
check "no auth exits 2"                              test "$(rc_of noauth)" -eq 2
check "the refusal names the auth problem"           contains "$TMP/noauth.out" "no Gemini auth"
check "the refusal happens before any TAP output"    lacks "$TMP/noauth.out" "TAP version"
check "the refusal never dispatches"                 test ! -e "$TMP/rec-noauth/argv"
run_case gca GOOGLE_GENAI_USE_GCA=true -- --fixture "$FIXTURE"
check "a Google login is refused with exit 2"        test "$(rc_of gca)" -eq 2
check "the refusal says why a login cannot be used"  contains "$TMP/gca.out" "deliberately does not copy"
check "the login refusal never dispatches"           test ! -e "$TMP/rec-gca/argv"
run_case vertex GOOGLE_GENAI_USE_VERTEXAI=true -- --fixture "$FIXTURE"
check "an incomplete Vertex setup exits 2"           test "$(rc_of vertex)" -eq 2

# --- 5. an unauthenticated CLI stops the run --------------------------------
run_case unauth FAKE_EXIT=41 -- --fixture "$FIXTURE"
check "an unauthenticated CLI exits non-zero"        test "$(rc_of unauth)" -ne 0
check "it exits 2"                                   test "$(rc_of unauth)" -eq 2
check "the fixture is not ok"                        contains "$TMP/unauth.out" "not ok 1 - $FIXTURE"
check "the message says not authenticated"           contains "$TMP/unauth.out" "not authenticated (gemini exit 41"
check "the run bails out"                            contains "$TMP/unauth.out" "Bail out! not authenticated"
check "the key is never printed"                     none_has_sentinel "$TMP/unauth.out" "$TMP/logs-unauth"

run_case untrusted FAKE_EXIT=55 -- --fixture "$FIXTURE"
check "an untrusted workspace exits 2"               test "$(rc_of untrusted)" -eq 2
check "the fixture is not ok"                        contains "$TMP/untrusted.out" "not ok 1 - $FIXTURE"
check "the message says workspace not trusted"       contains "$TMP/untrusted.out" "workspace not trusted (gemini exit 55"
check "the run bails out"                            contains "$TMP/untrusted.out" "Bail out! workspace not trusted"

# --- 6. a turn limit fails the fixture --------------------------------------
run_case turns FAKE_EXIT=53 -- --fixture "$FIXTURE"
check "a turn limit exits 1"                         test "$(rc_of turns)" -eq 1
check "the turn limit is named"                      contains "$TMP/turns.out" "not ok 1 - $FIXTURE (considerations: unmitigated,mitigated (F) (turn limit reached (gemini exit 53)))"

# --- 7. an answer that did not come from the agent is never scored ----------
run_case nodelegate FAKE_NO_DELEGATE=1 -- --fixture "$FIXTURE"
check "a main-model answer exits 1"                  test "$(rc_of nodelegate)" -eq 1
check "a main-model answer is 'agent not invoked'"   contains "$TMP/nodelegate.out" "not ok 1 - $FIXTURE (considerations: unmitigated,mitigated (F) (agent not invoked))"
run_case otheragent FAKE_AGENT_NAME=generalist -- --fixture "$FIXTURE"
check "delegating to another agent fails"            contains "$TMP/otheragent.out" "(agent not invoked)"
run_case toolerror FAKE_TOOL_STATUS=error -- --fixture "$FIXTURE"
check "a failed invoke_agent result fails"           contains "$TMP/toolerror.out" "invoke_agent returned error"

# --- 8. break-its on a scratch copy of run_eval.sh ---------------------------
EV="$TMP/ev"
mkdir -p "$EV/lib"
sed 's/directive="@${AGENT} /directive="/' "$RUN_EVAL" > "$EV/lib/run_eval.sh"
check "break-it: the agent selection was removed"    lacks "$EV/lib/run_eval.sh" 'directive="@${AGENT} '
RUNNER="$EV/lib/run_eval.sh" run_case brk_dry FIXTURES_DIR="$ROOT_DIR/fixtures" EVAL_EXTENSION_DIR="$ROOT_DIR" -- --dry-run --fixture "$FIXTURE"
check "break-it: the selection pin now fails"        fails contains "$TMP/brk_dry.out" "@$AGENT_ID"
RUNNER="$EV/lib/run_eval.sh" run_case brk_run FIXTURES_DIR="$ROOT_DIR/fixtures" EVAL_EXTENSION_DIR="$ROOT_DIR" -- --fixture "$FIXTURE"
check "break-it: without the selection the fixture fails" test "$(rc_of brk_run)" -eq 1
check "break-it: ... as agent not invoked"           contains "$TMP/brk_run.out" "(agent not invoked)"

sed 's/and ((.parameters.agent_name \/\/ "") == \$agent))/and true)/' "$RUN_EVAL" > "$EV/lib/run_eval.sh"
check "break-it: the agent-name filter was removed"  lacks "$EV/lib/run_eval.sh" '(.parameters.agent_name // "") == $agent'
RUNNER="$EV/lib/run_eval.sh" run_case brk_name FAKE_AGENT_NAME=generalist FIXTURES_DIR="$ROOT_DIR/fixtures" EVAL_EXTENSION_DIR="$ROOT_DIR" -- --fixture "$FIXTURE"
check "break-it: without the filter another agent scores" test "$(rc_of brk_name)" -eq 0

# The fixture-on-stdin pin: put the prompt into -p as well, and the pins that
# say the fixture never reaches argv must fail.
sed 's/"${GEMINI_ARGV\[@\]}") > "$raw"/"${GEMINI_ARGV[@]}" -p "$prompt") > "$raw"/' "$RUN_EVAL" > "$EV/lib/run_eval.sh"
check "break-it: the prompt was added to -p"         contains "$EV/lib/run_eval.sh" '-p "$prompt") > "$raw"'
RUNNER="$EV/lib/run_eval.sh" run_case brk_argv FIXTURES_DIR="$ROOT_DIR/fixtures" EVAL_EXTENSION_DIR="$ROOT_DIR" -- --fixture "$FIXTURE"
check "break-it: the no-fixture-in--p pin now fails" fails lacks "$TMP/rec-brk_argv/pval" "mode: considerations"
RUNNER="$EV/lib/run_eval.sh" run_case brk_argvq FIXTURES_DIR="$QX" EVAL_EXTENSION_DIR="$ROOT_DIR" -- --fixtures-dir "$QX"
check "break-it: the quoting fixture now reaches -p" fails lacks "$TMP/rec-brk_argvq/pval" "touch"

# The key-never-printed pin: echo the key with the auth line, and the
# sentinel scan must find it.
sed "s/  printf '# auth: %s\\\\n' \"\$AUTH_MODE\"/&; printf '# key: %s\\\\n' \"\${GEMINI_API_KEY:-}\"/" "$RUN_EVAL" > "$EV/lib/run_eval.sh"
check "break-it: the key is now echoed"              contains "$EV/lib/run_eval.sh" "printf '# key: %s"
RUNNER="$EV/lib/run_eval.sh" run_case brk_key FIXTURES_DIR="$ROOT_DIR/fixtures" EVAL_EXTENSION_DIR="$ROOT_DIR" -- --fixture "$FIXTURE"
check "break-it: the key-never-printed pin now fails" fails none_has_sentinel "$TMP/brk_key.out" "$TMP/logs-brk_key"

# W2278: the full_file prompt opens with its tag too, and reverting run_eval.sh
# to the bare `mode:` lines it sent before a01cb19 fails both tag checks.
run_case fullfile -- --fixture sql_injection.py
check "a full_file prompt opens with the full_file tag on its own line" opens_with "$TMP/rec-fullfile/stdin" "$FF_TAG"
sed "s|printf '/security-review invocation, mode: |printf 'mode: |" "$RUN_EVAL" > "$EV/lib/run_eval.sh"
check "W2278 break-it: run_eval.sh was reverted to the bare mode lines" lacks "$EV/lib/run_eval.sh" "printf '/security-review invocation, mode: "
RUNNER="$EV/lib/run_eval.sh" run_case brk_tag FIXTURES_DIR="$ROOT_DIR/fixtures" EVAL_EXTENSION_DIR="$ROOT_DIR" -- --fixture "$FIXTURE"
check "W2278 break-it: the reverted copy sends mode: considerations" opens_with "$TMP/rec-brk_tag/stdin" "mode: considerations"
check "W2278 break-it: reverting run_eval.sh to send mode: considerations fails the tag check" fails opens_with "$TMP/rec-brk_tag/stdin" "$CONS_TAG"
check "W2278 break-it: ... and the considerations-mode pin" fails contains "$TMP/rec-brk_tag/stdin" "$CONS_TAG"
check "W2278 break-it: ... and the delegated-prompt pin" fails contains "$TMP/logs-brk_tag/$LOGSTEM.agent_prompt.txt" "$CONS_TAG"
check "W2278 break-it: the reverted copy's delegated prompt is kept" contains "$TMP/logs-brk_tag/$LOGSTEM.agent_prompt.txt" "mode: considerations"
RUNNER="$EV/lib/run_eval.sh" run_case brk_tag_ff FIXTURES_DIR="$ROOT_DIR/fixtures" EVAL_EXTENSION_DIR="$ROOT_DIR" -- --fixture sql_injection.py
check "W2278 break-it: the reverted copy sends mode: full_file" opens_with "$TMP/rec-brk_tag_ff/stdin" "mode: full_file"
check "W2278 break-it: reverting run_eval.sh to send mode: full_file fails the tag check" fails opens_with "$TMP/rec-brk_tag_ff/stdin" "$FF_TAG"

# W2482: the scratch copy carries packs/ and modes/, and the workspace adds
# exactly that copy. Drop each from the copy's allow-list, drop the include, and
# widen it to the scratch home; each pin that says so must fail.
sed 's/for item in gemini-extension.json GEMINI.md agents commands skills packs modes; do/for item in gemini-extension.json GEMINI.md agents commands skills modes; do/' "$RUN_EVAL" > "$EV/lib/run_eval.sh"
check "W2482 break-it: packs/ was dropped from the copy's allow-list" lacks "$EV/lib/run_eval.sh" "skills packs modes; do"
RUNNER="$EV/lib/run_eval.sh" run_case brk_nopacks FIXTURES_DIR="$ROOT_DIR/fixtures" EVAL_EXTENSION_DIR="$ROOT_DIR" -- --fixture "$FIXTURE"
check "W2482 break-it: without packs/ the allow-list pin fails" fails test "$(LC_ALL=C sort "$TMP/rec-brk_nopacks/ext_ls" 2>/dev/null)" = "$want_ext_ls"
check "W2482 break-it: without packs/ the packs/phoenix.md pin fails" fails cmp -s "$TMP/rec-brk_nopacks/phoenix.md" "$ROOT_DIR/packs/phoenix.md"
sed 's/for item in gemini-extension.json GEMINI.md agents commands skills packs modes; do/for item in gemini-extension.json GEMINI.md agents commands skills packs; do/' "$RUN_EVAL" > "$EV/lib/run_eval.sh"
check "W2482 break-it: modes/ was dropped from the copy's allow-list" lacks "$EV/lib/run_eval.sh" "skills packs modes; do"
RUNNER="$EV/lib/run_eval.sh" run_case brk_nomodes FIXTURES_DIR="$ROOT_DIR/fixtures" EVAL_EXTENSION_DIR="$ROOT_DIR" -- --fixture "$FIXTURE"
check "W2482 break-it: without modes/ the modes/considerations.md pin fails" fails cmp -s "$TMP/rec-brk_nomodes/considerations.md" "$ROOT_DIR/modes/considerations.md"
grep -vF -- '--include-directories "$EVAL_EXT_DIR"' "$RUN_EVAL" > "$EV/lib/run_eval.sh"
check "W2482 break-it: the include was removed"       lacks "$EV/lib/run_eval.sh" '--include-directories "$EVAL_EXT_DIR"'
RUNNER="$EV/lib/run_eval.sh" run_case brk_noinc FIXTURES_DIR="$ROOT_DIR/fixtures" EVAL_EXTENSION_DIR="$ROOT_DIR" -- --fixture "$FIXTURE"
check "W2482 break-it: without the include the one-include pin fails" fails test "$(grep -cxF -- "--include-directories" "$TMP/rec-brk_noinc/argv")" = 1
check "W2482 break-it: ... and the exact-copy pin" fails test "$(awk 'p { print; exit } $0 == "--include-directories" { p = 1 }' "$TMP/rec-brk_noinc/argv")" = "$(cat "$TMP/rec-brk_noinc/cli_home" 2>/dev/null)/.gemini/extensions/$EXT_NAME"
sed 's/--include-directories "$EVAL_EXT_DIR"/--include-directories "$EVAL_HOME"/' "$RUN_EVAL" > "$EV/lib/run_eval.sh"
check "W2482 break-it: the include was widened to the scratch home" contains "$EV/lib/run_eval.sh" '--include-directories "$EVAL_HOME"'
RUNNER="$EV/lib/run_eval.sh" run_case brk_wideinc FIXTURES_DIR="$ROOT_DIR/fixtures" EVAL_EXTENSION_DIR="$ROOT_DIR" -- --fixture "$FIXTURE"
check "W2482 break-it: a widened include fails the exact-copy pin" fails test "$(awk 'p { print; exit } $0 == "--include-directories" { p = 1 }' "$TMP/rec-brk_wideinc/argv")" = "$(cat "$TMP/rec-brk_wideinc/cli_home" 2>/dev/null)/.gemini/extensions/$EXT_NAME"
check "W2482 break-it: ... while it still passes one --include-directories" test "$(grep -cxF -- "--include-directories" "$TMP/rec-brk_wideinc/argv")" = 1

# --- 9. an empty fixture set is not a pass ----------------------------------
EMPTY="$TMP/empty"
mkdir -p "$EMPTY"
printf '# Expected\n\nNo fixture rows here.\n' > "$EMPTY/EXPECTED.md"
run_case empty -- --fixtures-dir "$EMPTY"
check "an empty fixture set exits 2"                 test "$(rc_of empty)" -eq 2
check "it reports zero cases"                        contains "$TMP/empty.out" "(0 cases)"
check "it prints no TAP plan"                        lacks "$TMP/empty.out" "1..0"
check "it never dispatches"                          test ! -e "$TMP/rec-empty/argv"
: > "$EMPTY/EXPECTED.md"
run_case empty0 -- --fixtures-dir "$EMPTY"
check "an empty EXPECTED.md exits 2"                 test "$(rc_of empty0)" -eq 2
run_case nomatch -- --only nomatch/
check "--only with no match exits 2"                 test "$(rc_of nomatch)" -eq 2
check "--only with no match reports zero cases"      contains "$TMP/nomatch.out" "(0 cases)"

# --- 10. --only <prefix> -----------------------------------------------------
want_k="$(grep -c '^- \[[ x]\] `considerations/' "$ROOT_DIR/fixtures/EXPECTED.md")"
run_case only -- --only considerations/
check "--only keeps every considerations row"        contains "$TMP/only.out" "1..$want_k"
check "--only keeps nothing else"                    test "$(grep -E '^(not )?ok [0-9]+ - ' "$TMP/only.out" | grep -vc ' - considerations/')" -eq 0
check "--only dispatches each kept row"              test "$(grep -cE '^(not )?ok [0-9]+ - considerations/' "$TMP/only.out")" -eq "$want_k"

# --- 11. the U marker and a fixture name with a space ------------------------
FX="$TMP/fx"
mkdir -p "$FX/considerations"
cp "$ROOT_DIR/fixtures/$FIXTURE" "$FX/considerations/name with space.diff"
cp "$ROOT_DIR/fixtures/${FIXTURE%.diff}.considerations" "$FX/considerations/name with space.considerations"
printf -- '- [ ] `considerations/name with space.diff` → CONSIDERATIONS unmitigated,mitigated — verdict-only row\n' > "$FX/EXPECTED.md"
run_case umarker -- --fixtures-dir "$FX" --fixture "considerations/name with space.diff"
check "a row with no AND clause scores ok"           test "$(rc_of umarker)" -eq 0
check "the row carries the explicit U marker"        contains "$TMP/umarker.out" "ok 1 - considerations/name with space.diff (considerations: unmitigated,mitigated (U))"
check "a name with a space keeps its log file"       test -f "$TMP/logs-umarker/considerations_name with space_diff.json"

# --- 12. check_fixtures.sh guards --------------------------------------------
TREE="$TMP/tree"
fresh_tree() {
  rm -rf "$TREE"
  mkdir -p "$TREE/lib"
  cp "$SCRIPT_DIR/check_fixtures.sh" "$TREE/lib/"
  cp -R "$ROOT_DIR/fixtures" "$TREE/fixtures"
  [ -f "$ROOT_DIR/README.md" ] && cp "$ROOT_DIR/README.md" "$TREE/README.md"
}
cf() { bash "$TREE/lib/check_fixtures.sh" > "$TMP/cf.out" 2>&1; echo "$?" > "$TMP/cf.rc"; }
drop_row() { # $1=fixture path: delete its EXPECTED.md row
  awk -v p="\`$1\`" 'index($0, p) == 0' "$TREE/fixtures/EXPECTED.md" > "$TMP/exp.tmp" && mv "$TMP/exp.tmp" "$TREE/fixtures/EXPECTED.md"
}

fresh_tree; cf
check "check_fixtures passes on an unchanged copy"   test "$(rc_of cf)" -eq 0
check "check_fixtures reports the sidecar check"     contains "$TMP/cf.out" "considerations fixtures, each paired with its sidecar"

fresh_tree; rm "$TREE/fixtures/considerations/search_sort_partial.considerations"; cf
check "break-it: a .diff with no sidecar fails"      test "$(rc_of cf)" -eq 1
check "the failure names the missing sidecar"        contains "$TMP/cf.out" "search_sort_partial.diff has no considerations/search_sort_partial.considerations sidecar"

fresh_tree
rm "$TREE/fixtures/considerations/search_sort_partial.diff"
drop_row considerations/search_sort_partial.diff
cf
check "a sidecar with no .diff fails"                test "$(rc_of cf)" -eq 1
check "the failure names the orphan sidecar"         contains "$TMP/cf.out" "search_sort_partial.considerations has no considerations/search_sort_partial.diff fixture"

fresh_tree
awk '{ if (index($0, "`considerations/search_sort_partial.diff`")) sub(/CONSIDERATIONS partial,mitigated/, "CONSIDERATIONS partial"); print }' "$TREE/fixtures/EXPECTED.md" > "$TMP/exp.tmp" && mv "$TMP/exp.tmp" "$TREE/fixtures/EXPECTED.md"
cf
check "a verdict-count mismatch fails"               test "$(rc_of cf)" -eq 1
check "the failure names both counts"                contains "$TMP/cf.out" "lists 1 verdict(s) but considerations/search_sort_partial.considerations has 2 consideration(s)"

fresh_tree; drop_row considerations/upload_body_size_unmitigated.diff; cf
check "a considerations fixture with no row fails"   test "$(rc_of cf)" -eq 1
check "the failure names the fixture"                contains "$TMP/cf.out" "considerations/upload_body_size_unmitigated.diff"

fresh_tree
printf -- '- [ ] `considerations/ghost.diff` → CONSIDERATIONS mitigated AND clean — no such fixture\n' >> "$TREE/fixtures/EXPECTED.md"
cf
check "a row with no fixture fails"                  test "$(rc_of cf)" -eq 1
check "the failure names the missing fixture"        contains "$TMP/cf.out" "EXPECTED.md rows naming a fixture that does not exist"

if [ "$fail" -ne 0 ]; then
  echo "eval invocation: FAILED"
  exit 1
fi
echo "eval invocation: all checks passed"
