# Top-level smoke-test runner for the stride-gemini-security-review extension.
# PowerShell mirror of test-all.sh.
#
# Runs the structure check, the frontmatter check and the agent contract check
# (check_agent_contract.ps1) in sequence and exits non-zero if any fails.
# Offline and read-only (the contract check's self-tests write only to a
# temporary directory) — suitable for gating a release.
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

Write-Host ''
Write-Host '=== agent contract ==='
if (-not (Invoke-Check 'check_agent_contract.ps1')) { $failed = $true }

Write-Host ''
Write-Host '=== result ==='
if ($failed) {
    Write-Host 'ONE OR MORE CHECKS FAILED'
    exit 1
} else {
    Write-Host 'ALL CHECKS PASSED'
    exit 0
}
