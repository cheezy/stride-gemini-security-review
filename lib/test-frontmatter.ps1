# Frontmatter / command-key smoke test for the stride-gemini-security-review
# extension. PowerShell mirror of test-frontmatter.sh.
#
# Confirms:
#   - every agents/*.md has `name:` and `description:` YAML frontmatter,
#     handling the block-scalar `description: |` form;
#   - every commands/*.toml has a `description` key AND a `prompt` key (TOML).
#
# Offline and read-only. It extracts the YAML frontmatter block between the
# first two `---` fences and matches keys at the start of a line; it never
# evaluates or dot-sources any file, so a malicious prompt body cannot execute.
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

# Get-Frontmatter — return the lines of the YAML frontmatter block. The opening
# `---` fence MUST be on line 1 (mirroring the bash awk `NR == 1` guard so both
# runners judge a malformed file identically); the block ends at the next `---`.
# Returns an empty array when line 1 is not an opening fence.
function Get-Frontmatter([string]$path) {
    $lines = @(Get-Content -LiteralPath $path)
    if ($lines.Count -eq 0 -or $lines[0] -notmatch '^---\s*$') { return @() }
    $collected = @()
    for ($i = 1; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^---\s*$') { break }
        $collected += $lines[$i]
    }
    return $collected
}

# Test-HasKey — true if any line starts with `<key>:` (YAML).
function Test-HasKey($frontmatter, [string]$key) {
    foreach ($line in $frontmatter) {
        if ($line -match "^$([regex]::Escape($key)):") { return $true }
    }
    return $false
}

# Test-MdFrontmatter <file> <label>
function Test-MdFrontmatter([string]$file, [string]$label) {
    if (-not (Test-Path -LiteralPath $file)) {
        Fail "$label missing" $file
        return
    }
    $fm = Get-Frontmatter $file
    if ($fm.Count -eq 0) {
        Fail "$label has no YAML frontmatter block" $file
        return
    }
    if (Test-HasKey $fm 'name') { Pass "$label has name:" }
    else { Fail "$label missing name:" $file }
    if (Test-HasKey $fm 'description') { Pass "$label has description: (inline or block-scalar)" }
    else { Fail "$label missing description:" $file }
}

Write-Host 'stride-gemini-security-review frontmatter test'
Write-Host "plugin root: $PluginRoot"
Write-Host ''

# --- Skills -----------------------------------------------------------------

Write-Host 'Skill frontmatter'
foreach ($skill in @('security-review-essentials')) {
    Test-MdFrontmatter (Join-Path $PluginRoot "skills/$skill/SKILL.md") "skill '$skill'"
}

# --- Agents -----------------------------------------------------------------

Write-Host ''
Write-Host 'Agent frontmatter'
foreach ($agent in @('security-reviewer')) {
    Test-MdFrontmatter (Join-Path $PluginRoot "agents/$agent.md") "agent '$agent'"
}

# --- Commands ---------------------------------------------------------------

Write-Host ''
Write-Host 'Command TOML keys'
foreach ($cmd in @('security-review')) {
    $file = Join-Path $PluginRoot "commands/$cmd.toml"
    if (-not (Test-Path -LiteralPath $file)) {
        Fail "command /$cmd missing" $file
        continue
    }
    $content = Get-Content -LiteralPath $file
    $hasDescription = $false
    $hasPrompt = $false
    foreach ($line in $content) {
        if ($line -match '^description(\s|=)') { $hasDescription = $true }
        if ($line -match '^prompt(\s|=)')      { $hasPrompt = $true }
    }
    if ($hasDescription) { Pass "command /$cmd has a description key" }
    else { Fail "command /$cmd missing a description key" $file }
    if ($hasPrompt) { Pass "command /$cmd has a prompt key" }
    else { Fail "command /$cmd missing a prompt key" $file }
}

# --- Summary ----------------------------------------------------------------

Write-Host ''
Write-Host "$($script:PASS) passed, $($script:FAIL) failed"
if ($script:FAIL -gt 0) { exit 1 }
