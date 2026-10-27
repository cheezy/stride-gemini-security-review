# Structure smoke test for the stride-gemini-security-review extension.
# PowerShell mirror of test-structure.sh.
#
# Confirms the extension's required files and directories exist and that the
# gemini-extension.json manifest is valid JSON carrying name/version/
# contextFileName. Offline and read-only — it never executes or evaluates any
# extension file; it only checks existence and parses the manifest as data.
#
# The manifest is gemini-extension.json at the ROOT (Gemini CLI convention).
# This test deliberately does NOT look for a .claude-plugin/plugin.json or a
# package.json — the Gemini extension has neither.
#
# Exit code: 0 if every check passes; 1 if any check fails.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PluginRoot = Split-Path -Parent $ScriptDir

$script:PASS = 0
$script:FAIL = 0

function Pass([string]$message) {
    $script:PASS++
    Write-Host "  [ok]   $message"
}

function Fail([string]$message, [string]$detail = '') {
    $script:FAIL++
    Write-Host "  [nope] $message"
    if ($detail) { Write-Host "         $detail" }
}

function Test-Exists([string]$relative, [string]$label) {
    $path = Join-Path $PluginRoot $relative
    if (Test-Path -LiteralPath $path) {
        Pass "$label exists ($relative)"
    } else {
        Fail "$label missing" $relative
    }
}

Write-Host 'stride-gemini-security-review structure test'
Write-Host "plugin root: $PluginRoot"
Write-Host ''

# --- Manifest ---------------------------------------------------------------

Write-Host 'Manifest'
$manifest = Join-Path $PluginRoot 'gemini-extension.json'
if (-not (Test-Path -LiteralPath $manifest)) {
    Fail 'gemini-extension.json missing at the root' $manifest
} else {
    try {
        $data = Get-Content -Raw -LiteralPath $manifest | ConvertFrom-Json
        $present = @($data.PSObject.Properties.Name)
        $missing = @()
        foreach ($key in @('name', 'version', 'contextFileName')) {
            if ($present -notcontains $key) { $missing += $key }
        }
        if ($missing.Count -gt 0) {
            Fail 'gemini-extension.json missing keys' ($missing -join ', ')
        } else {
            Pass 'gemini-extension.json is valid JSON with name/version/contextFileName'
        }
    } catch {
        Fail 'gemini-extension.json invalid JSON' $_.Exception.Message
    }
}

# Guard: the Gemini extension must NOT rely on Claude Code / npm manifests.
if (Test-Path -LiteralPath (Join-Path $PluginRoot '.claude-plugin/plugin.json')) {
    Fail 'unexpected .claude-plugin/plugin.json present' 'the Gemini extension is declared by gemini-extension.json only'
} else {
    Pass 'no .claude-plugin/plugin.json (correct for a Gemini extension)'
}
if (Test-Path -LiteralPath (Join-Path $PluginRoot 'package.json')) {
    Fail 'unexpected package.json present' 'the Gemini extension does not use npm'
} else {
    Pass 'no package.json (correct for a Gemini extension)'
}

# --- Skills -----------------------------------------------------------------

Write-Host ''
Write-Host 'Skills'
foreach ($skill in @('security-review-essentials')) {
    Test-Exists "skills/$skill/SKILL.md" "skill '$skill' SKILL.md"
}

# --- Agents -----------------------------------------------------------------

Write-Host ''
Write-Host 'Agents'
foreach ($agent in @('security-reviewer')) {
    Test-Exists "agents/$agent.md" "agent '$agent'"
}

# --- Commands ---------------------------------------------------------------

Write-Host ''
Write-Host 'Commands'
foreach ($cmd in @('security-review')) {
    Test-Exists "commands/$cmd.toml" "command /$cmd"
}

# --- lib tooling ------------------------------------------------------------

Write-Host ''
Write-Host 'lib tooling'
foreach ($tool in @('sarif_transform.sh', 'run_eval.sh', 'run_transform_tests.sh', 'check_fixtures.sh', 'check_eval_invocation.sh')) {
    Test-Exists "lib/$tool" "lib helper $tool"
}

# --- Fixtures & golden ------------------------------------------------------

Write-Host ''
Write-Host 'Fixtures'
Test-Exists 'fixtures/EXPECTED.md' 'fixtures EXPECTED.md'
foreach ($g in @('input_findings.json', 'fingerprint.golden', 'dedup.golden.json', 'sarif.golden.json')) {
    Test-Exists "fixtures/golden/$g" "golden $g"
}

# Considerations-mode fixtures: each is a .diff paired with a .considerations
# sidecar. The stems are read from disk rather than listed here, so a new pair
# needs no edit to this file; check_fixtures.sh owns the pairing, row and
# verdict-count rules. This only requires that the directory holds at least one
# .diff and that every .diff found has its sidecar.
Write-Host ''
Write-Host 'Considerations fixtures'
$consDir = Join-Path $PluginRoot 'fixtures/considerations'
$consDiffs = @()
if (Test-Path -LiteralPath $consDir) {
    $consDiffs = @(Get-ChildItem -LiteralPath $consDir -Filter '*.diff' -File | Sort-Object Name)
}
foreach ($d in $consDiffs) {
    $c = [System.IO.Path]::GetFileNameWithoutExtension($d.Name)
    Test-Exists "fixtures/considerations/$c.diff" "considerations fixture $c.diff"
    Test-Exists "fixtures/considerations/$c.considerations" "considerations input $c.considerations"
}
if ($consDiffs.Count -gt 0) {
    Pass "fixtures/considerations/ holds $($consDiffs.Count) .diff fixture(s)"
} else {
    Fail 'no considerations fixtures found' 'fixtures/considerations/*.diff'
}

# --- Install scripts --------------------------------------------------------

Write-Host ''
Write-Host 'Install scripts'
foreach ($inst in @('install.sh', 'install.ps1')) {
    Test-Exists $inst $inst
}

# --- Policies (W2488) ---------------------------------------------------------
# The security-reviewer subagent's Policy Engine deny rules, and both installers
# copying the directory (lib/check_agent_contract.ps1 checks the rules).

Write-Host ''
Write-Host 'Policies'
Test-Exists 'policies/security-reviewer.toml' 'policy security-reviewer.toml'
$instSh = Get-Content -LiteralPath (Join-Path $PluginRoot 'install.sh')
if (@($instSh | Where-Object { $_ -match '^for dir in .* policies(;| )' }).Count -gt 0) { Pass 'install.sh copies policies/' }
else { Fail 'install.sh does not copy policies/' 'install.sh: for dir in ... policies' }
$instPs = Get-Content -LiteralPath (Join-Path $PluginRoot 'install.ps1')
if (@($instPs | Where-Object { $_ -match "^ *foreach \(\`$dir in @\(.*'policies'" }).Count -gt 0) { Pass 'install.ps1 copies policies/' }
else { Fail 'install.ps1 does not copy policies/' 'install.ps1: foreach ($dir in @(... ''policies''))' }

# --- Root docs & license ----------------------------------------------------

Write-Host ''
Write-Host 'Root docs'
foreach ($doc in @('GEMINI.md', 'README.md', 'CHANGELOG.md', 'LICENSE')) {
    Test-Exists $doc $doc
}

# --- Summary ----------------------------------------------------------------

Write-Host ''
Write-Host "$($script:PASS) passed, $($script:FAIL) failed"
if ($script:FAIL -gt 0) { exit 1 }
