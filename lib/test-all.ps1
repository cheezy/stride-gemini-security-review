# Top-level smoke-test runner for the stride-gemini-security-review extension.
# PowerShell mirror of test-all.sh.
#
# Runs the structure check and the frontmatter check, then the deterministic
# transform golden tests (run_transform_tests.sh) through bash, then the agent
# contract check (check_agent_contract.ps1), then the eval invocation check
# (check_eval_invocation.sh) through bash — each bash suite only when bash and
# jq are on PATH — and exits non-zero if any fails. Offline and read-only (the
# self-tests write only to temporary directories) — suitable for gating a
# release.
#
# Neither bash suite has a PowerShell mirror: the transform tests lock
# lib/sarif_transform.sh, itself a bash script, and the eval invocation check
# pins how the bash runner, lib/run_eval.sh, invokes gemini. Without bash or jq
# each is reported as skipped, not passed. The offline policy pattern check
# (check_policy_patterns.mjs) runs through node when node is on PATH and is
# likewise reported as skipped without it.
#
# Usage:
#   pwsh -NoProfile -File lib\test-all.ps1
#   (or from Windows PowerShell 5.1:  powershell -File lib\test-all.ps1)
#
# Exit code: 0 only if ALL checks pass; 1 if any fails.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Re-invoke the CURRENT interpreter (not a hardcoded `pwsh`) so this runner
# works on Windows PowerShell 5.1-only hosts as well as PowerShell 7 (pwsh).
$Interpreter = (Get-Process -Id $PID).Path

$failed = $false

function Invoke-Check([string]$scriptName) {
    $path = Join-Path $ScriptDir $scriptName
    # Stream the child's output straight to the host with Out-Host so it does
    # NOT leak into this function's return pipeline (which would both hide the
    # per-check lines and corrupt the boolean the caller tests).
    & $Interpreter -NoProfile -File $path | Out-Host
    return ($LASTEXITCODE -eq 0)
}

Write-Host '=== structure ==='
if (-not (Invoke-Check 'test-structure.ps1')) { $failed = $true }

Write-Host ''
Write-Host '=== frontmatter ==='
if (-not (Invoke-Check 'test-frontmatter.ps1')) { $failed = $true }

$bash = Get-Command bash -ErrorAction SilentlyContinue
$jq = Get-Command jq -ErrorAction SilentlyContinue

Write-Host ''
Write-Host '=== transforms (golden) ==='
if ($bash -and $jq) {
    & $bash.Source (Join-Path $ScriptDir 'run_transform_tests.sh') | Out-Host
    if ($LASTEXITCODE -ne 0) { $failed = $true }
} else {
    Write-Host 'skipped: run_transform_tests.sh needs bash and jq on PATH'
}

Write-Host ''
Write-Host '=== agent contract ==='
if (-not (Invoke-Check 'check_agent_contract.ps1')) { $failed = $true }

Write-Host ''
Write-Host '=== eval invocation (fake CLI) ==='
if ($bash -and $jq) {
    & $bash.Source (Join-Path $ScriptDir 'check_eval_invocation.sh') | Out-Host
    if ($LASTEXITCODE -ne 0) { $failed = $true }
} else {
    Write-Host 'skipped: check_eval_invocation.sh needs bash and jq on PATH'
}

Write-Host ''
Write-Host '=== policy patterns (offline, node) ==='
$node = Get-Command node -ErrorAction SilentlyContinue
if ($node) {
    & $node.Source (Join-Path $ScriptDir 'check_policy_patterns.mjs') | Out-Host
    if ($LASTEXITCODE -ne 0) { $failed = $true }
} else {
    Write-Host 'skipped: check_policy_patterns.mjs needs node on PATH'
}

Write-Host ''
Write-Host '=== result ==='
if ($failed) {
    Write-Host 'ONE OR MORE CHECKS FAILED'
    exit 1
} else {
    Write-Host 'ALL CHECKS PASSED'
    exit 0
}
