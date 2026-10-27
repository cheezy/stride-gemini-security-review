# Frontmatter / command-key smoke test for the stride-gemini-security-review
# extension. PowerShell mirror of test-frontmatter.sh.
#
# Confirms:
#   - every agents/*.md has `name:` and `description:` YAML frontmatter,
#     handling the block-scalar `description: |` form;
#   - the agent's frontmatter uses only the keys Gemini CLI's strict agent
#     schema accepts (W2484): kind, name, description, display_name, tools,
#     mcp_servers, model, temperature, max_turns and timeout_mins
#     (@google/gemini-cli-core 0.65.0, dist/src/agents/agentLoader.js:68-87).
#     `model` is allowed but not required: this port inherits the session model;
#   - every description, the agent's and the skill's, is non-empty (W2484);
#   - every commands/*.toml has a `description` key AND a `prompt` key (TOML).
#
# Offline and read-only. It extracts the YAML frontmatter block between the
# first two `---` fences and matches keys at the start of a line; it never
# evaluates or dot-sources any file, so a malicious prompt body cannot execute.
#
# Self-tests (W2484): run with no arguments, it then writes broken copies of
# the agent and the skill to a temporary directory and runs itself on each as
# a child, which must fail, as test-frontmatter.sh does.
# This file is kept ASCII-only so Windows PowerShell 5.1 reads it correctly.
#
# Usage:  pwsh -NoProfile -File lib/test-frontmatter.ps1 [-Agent <file>] [-Skill <file>]
#         (a child run checks only the files it is given)
# Exit code: 0 if every check passes; 1 if any check fails.

param([string]$Agent = '', [string]$Skill = '')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PluginRoot = Split-Path -Parent $ScriptDir
$Self = $MyInvocation.MyCommand.Path

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

# Gemini CLI's agent frontmatter keys (agentLoader.js:68-87).
$GeminiAgentKeys = @('kind', 'name', 'description', 'display_name', 'tools', 'mcp_servers', 'model', 'temperature', 'max_turns', 'timeout_mins')

# Get-Frontmatter -- return the lines of the YAML frontmatter block, CR
# stripped. The opening `---` fence MUST be on line 1 (mirroring the bash awk
# `NR == 1` guard so both runners judge a malformed file identically); the
# block ends at the next `---`. Returns an empty array when line 1 is not an
# opening fence.
function Get-Frontmatter([string]$path) {
    $lines = @(Get-Content -LiteralPath $path | ForEach-Object { $_ -replace "`r", '' })
    if ($lines.Count -eq 0 -or $lines[0] -notmatch '^---\s*$') { return @() }
    $collected = @()
    for ($i = 1; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^---\s*$') { break }
        $collected += $lines[$i]
    }
    return $collected
}

# Test-HasKey -- true if any line starts with `<key>:` (YAML).
function Test-HasKey($frontmatter, [string]$key) {
    foreach ($line in $frontmatter) {
        if ($line -match "^$([regex]::Escape($key)):") { return $true }
    }
    return $false
}

# Get-TopKeys -- every top-level key: a line that starts with a key character
# and holds a colon. Indented lines (a block scalar's text, a list item under
# `tools:`) are not keys.
function Get-TopKeys($frontmatter) {
    $keys = @()
    foreach ($line in $frontmatter) {
        if ($line -match '^([^\s#\-][^:]*):') { $keys += $Matches[1] }
    }
    return $keys
}

# Get-DescriptionText -- the description's value: an inline value with one
# pair of surrounding quotes removed, or the lines of a `|` / `>` block.
function Get-DescriptionText($frontmatter) {
    $out = @(); $block = $false
    foreach ($line in $frontmatter) {
        if ($block) {
            if ($line -match '^\s' -or $line -eq '') { $out += $line; continue }
            break
        }
        if ($line -match '^description:\s*[|>][-+0-9]*\s*$') { $block = $true; continue }
        if ($line -match '^description:\s*(.*?)\s*$') {
            $v = $Matches[1]
            if ($v -match '^"(.*)"$' -or $v -match "^'(.*)'$") { $v = $Matches[1] }
            return $v
        }
    }
    return ($out -join "`n")
}

# Test-MdFrontmatter <file> <label> <kind: agent|skill>
function Test-MdFrontmatter([string]$file, [string]$label, [string]$kind) {
    if (-not (Test-Path -LiteralPath $file)) {
        Fail "$label missing" $file
        return
    }
    $fm = @(Get-Frontmatter $file)
    if ($fm.Count -eq 0) {
        Fail "$label has no YAML frontmatter block" $file
        return
    }
    if (Test-HasKey $fm 'name') { Pass "$label has name:" }
    else { Fail "$label missing name:" $file }
    if (Test-HasKey $fm 'description') {
        Pass "$label has description: (inline or block-scalar)"
        if ((Get-DescriptionText $fm) -match '\S') { Pass "$label has a non-empty description" }
        else { Fail "$label has an empty description" $file }
    } else {
        Fail "$label missing description:" $file
    }
    if ($kind -eq 'agent') {
        $unknown = @(Get-TopKeys $fm | Where-Object { $GeminiAgentKeys -cnotcontains $_ })
        if ($unknown.Count -eq 0) { Pass "$label uses only Gemini CLI's agent frontmatter keys" }
        else { Fail "$label has a frontmatter key Gemini CLI rejects: $($unknown -join ' ')" $file }
    }
}

function Test-Command([string]$cmd) {
    $file = Join-Path $PluginRoot "commands/$cmd.toml"
    if (-not (Test-Path -LiteralPath $file)) {
        Fail "command /$cmd missing" $file
        return
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

function Exit-Summary {
    Write-Host ''
    Write-Host "$($script:PASS) passed, $($script:FAIL) failed"
    if ($script:FAIL -gt 0) { exit 1 }
    exit 0
}

if ($Agent -ne '' -or $Skill -ne '') {
    if ($Skill -ne '') { Test-MdFrontmatter $Skill "skill '$(Split-Path -Leaf $Skill)'" 'skill' }
    if ($Agent -ne '') { Test-MdFrontmatter $Agent "agent '$(Split-Path -Leaf $Agent)'" 'agent' }
    Exit-Summary
}

Write-Host 'stride-gemini-security-review frontmatter test'
Write-Host "plugin root: $PluginRoot"
Write-Host ''

# --- Skills -----------------------------------------------------------------

Write-Host 'Skill frontmatter'
foreach ($skill in @('security-review-essentials')) {
    Test-MdFrontmatter (Join-Path $PluginRoot "skills/$skill/SKILL.md") "skill '$skill'" 'skill'
}

# --- Agents -----------------------------------------------------------------

Write-Host ''
Write-Host 'Agent frontmatter'
foreach ($agentName in @('security-reviewer')) {
    Test-MdFrontmatter (Join-Path $PluginRoot "agents/$agentName.md") "agent '$agentName'" 'agent'
}

# --- Commands ---------------------------------------------------------------

Write-Host ''
Write-Host 'Command TOML keys'
foreach ($cmd in @('security-review')) {
    Test-Command $cmd
}

# --- Self-tests (W2484) -------------------------------------------------------
# Each case writes a broken copy of the shipped agent or skill to a temporary
# directory and runs this script on it as a child; the child must fail with the
# named line. The shipped copies, and copies that only add keys Gemini CLI
# accepts, must pass.

Write-Host ''
Write-Host 'Self-tests'
$Interpreter = (Get-Process -Id $PID).Path
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false
$Tmp = Join-Path ([IO.Path]::GetTempPath()) ('test-frontmatter.' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
    function Write-Variant([string]$name, [string]$text) {
        $path = Join-Path $Tmp $name
        [IO.File]::WriteAllText($path, $text, $Utf8NoBom)
        return $path
    }
    # Self-Test <label> <want-exit> <needle> <kind> <path> -- a child run.
    function Self-Test([string]$label, [int]$want, [string]$needle, [string]$kind, [string]$path) {
        $o = (& $Interpreter -NoProfile -File $Self "-$kind" $path *>&1 | Out-String)
        $rc = $LASTEXITCODE
        if ($rc -ne $want) { Fail "self-test: $label" "exit $rc, wanted $want" }
        elseif ($needle -ne '' -and -not $o.Contains($needle)) { Fail "self-test: $label" "output lacks: $needle" }
        else { Pass "self-test: $label" }
    }
    # Add-Key <text> <line> -- <line> added as the frontmatter's last line.
    function Add-Key([string]$text, [string]$line) {
        $ls = $text -split "`n"; $o = @(); $done = $false
        for ($k = 0; $k -lt $ls.Count; $k++) {
            if ($k -gt 0 -and -not $done -and $ls[$k] -match '^---\s*$') { $o += $line; $done = $true }
            $o += $ls[$k]
        }
        return ($o -join "`n")
    }
    # Set-Description <text> <lines> -- the frontmatter's description key, and
    # any block lines under it, replaced by <lines>.
    function Set-Description([string]$text, [string]$lines) {
        $ls = $text -split "`n"; $o = @(); $skip = $false; $fmDone = $false
        for ($k = 0; $k -lt $ls.Count; $k++) {
            $l = $ls[$k]
            if ($k -gt 0 -and $l -match '^---\s*$') { $fmDone = $true }
            if (-not $fmDone -and $l.StartsWith('description:', [StringComparison]::Ordinal)) { $o += $lines; $skip = $true; continue }
            if ($skip -and $l -match '^\s') { continue }
            $skip = $false; $o += $l
        }
        return ($o -join "`n")
    }

    $agentText = [IO.File]::ReadAllText((Join-Path $PluginRoot 'agents/security-reviewer.md'), [Text.Encoding]::UTF8) -replace "`r`n", "`n"
    $skillText = [IO.File]::ReadAllText((Join-Path $PluginRoot 'skills/security-review-essentials/SKILL.md'), [Text.Encoding]::UTF8) -replace "`r`n", "`n"
    $agentBase = Write-Variant 'security-reviewer.md' $agentText
    $skillBase = Write-Variant 'SKILL.md' $skillText

    Self-Test 'the shipped agent passes' 0 "uses only Gemini CLI's agent frontmatter keys" 'Agent' $agentBase
    Self-Test 'the shipped skill passes' 0 'has a non-empty description' 'Skill' $skillBase

    Self-Test 'an unknown agent frontmatter key fails the check' 1 'has a frontmatter key Gemini CLI rejects: color' 'Agent' (Write-Variant 'unknown-key.md' (Add-Key $agentText 'color: red'))
    Self-Test 'a skill-only key in the agent frontmatter fails the check' 1 'has a frontmatter key Gemini CLI rejects: skills_version' 'Agent' (Write-Variant 'claude-key.md' (Add-Key $agentText 'skills_version: 1.0'))
    Self-Test "kind and display_name, both in Gemini CLI's schema, pass" 0 "uses only Gemini CLI's agent frontmatter keys" 'Agent' (Write-Variant 'gemini-keys.md' (Add-Key (Add-Key $agentText 'kind: local') 'display_name: Security reviewer'))
    Self-Test 'the agent with CRLF line endings passes' 0 'has a non-empty description' 'Agent' (Write-Variant 'crlf.md' ($agentText -replace "`n", "`r`n"))

    Self-Test 'an empty description fails the check' 1 'has an empty description' 'Agent' (Write-Variant 'empty-inline.md' (Set-Description $agentText 'description:'))
    Self-Test 'an empty quoted description fails the check' 1 'has an empty description' 'Agent' (Write-Variant 'empty-quoted.md' (Set-Description $agentText 'description: ""'))
    Self-Test 'an empty block description fails the check' 1 'has an empty description' 'Agent' (Write-Variant 'empty-block.md' (Set-Description $agentText 'description: |'))
    Self-Test 'a whitespace-only block description fails the check' 1 'has an empty description' 'Agent' (Write-Variant 'blank-block.md' (Set-Description $agentText "description: |`n   "))
    Self-Test 'an empty skill description fails the check' 1 'has an empty description' 'Skill' (Write-Variant 'empty-skill.md' (Set-Description $skillText 'description:'))
    Self-Test 'an empty quoted skill description fails the check' 1 'has an empty description' 'Skill' (Write-Variant 'empty-skill-quoted.md' (Set-Description $skillText "description: ''"))
    Self-Test 'an empty block skill description fails the check' 1 'has an empty description' 'Skill' (Write-Variant 'empty-skill-block.md' (Set-Description $skillText 'description: >'))
    Self-Test 'a whitespace-only block skill description fails the check' 1 'has an empty description' 'Skill' (Write-Variant 'blank-skill-block.md' (Set-Description $skillText "description: |`n   "))
} finally {
    Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# --- Summary ----------------------------------------------------------------

Exit-Summary
