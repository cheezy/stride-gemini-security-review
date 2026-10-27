# check_install.ps1 -- runs install.ps1 into a scratch profile directory and
# checks what it installed (W2482). PowerShell mirror of check_install.sh: same
# checks, for install.ps1.
#
# Since W2482 the security-reviewer agent reads its rule packs and mode files
# from the installed extension's packs/ and modes/, so an install that leaves
# either out leaves the agent with its core rules alone. This check sets
# USERPROFILE to a new temporary directory, runs install.ps1 in its default
# (global) mode in a child PowerShell, and checks that packs/ and modes/ under
# $env:USERPROFILE\.gemini\extensions\stride-gemini-security-review\ match this
# checkout file for file (by SHA-256), and that the installed agents/ holds only
# security-reviewer.md. The installer copies from the directory it lives in when
# that directory holds gemini-extension.json, so this run makes no network call.
# A self-test runs a copy of the checkout whose install.ps1 no longer copies
# packs/, then one that no longer copies modes/, and requires each to fail.
#
# This file is kept ASCII-only so Windows PowerShell 5.1 reads it correctly.
#
# Usage:
#   pwsh -NoProfile -File lib\check_install.ps1
# Exit code: 0 when the install matches and the self-tests hold; 1 otherwise.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = (Resolve-Path (Join-Path $ScriptDir '..')).Path
$ExtName = 'stride-gemini-security-review'
$Interpreter = (Get-Process -Id $PID).Path
$script:fail = $false
$Tmp = Join-Path ([IO.Path]::GetTempPath()) ('check-install.' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Tmp | Out-Null

# Get-Tree <dir> -- relative path and SHA-256 of every file below <dir>, sorted.
function Get-Tree([string]$dir) {
    $base = (Resolve-Path -LiteralPath $dir).Path
    $rows = foreach ($f in @(Get-ChildItem -LiteralPath $base -Recurse -File)) {
        $rel = $f.FullName.Substring($base.Length + 1) -replace '\\', '/'
        $rel + ' ' + (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
    }
    return (@($rows | Sort-Object) -join "`n")
}

# Get-InstallProblems <root> -- install from <root> into a fresh profile
# directory; return one string per problem, none when the install matches.
function Get-InstallProblems([string]$src) {
    $profileDir = Join-Path $Tmp ('profile.' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $profileDir | Out-Null
    $out = @()
    $saved = $env:USERPROFILE
    $env:USERPROFILE = $profileDir
    try {
        & $Interpreter -NoProfile -File (Join-Path $src 'install.ps1') *> (Join-Path $Tmp 'install.log')
        if ($LASTEXITCODE -ne 0) { $out += 'install.ps1 exited non-zero' }
    } finally {
        $env:USERPROFILE = $saved
    }
    $dest = Join-Path (Join-Path (Join-Path $profileDir '.gemini') 'extensions') $ExtName
    foreach ($d in @('packs', 'modes')) {
        $got = Join-Path $dest $d
        if (-not (Test-Path -LiteralPath $got -PathType Container)) { $out += "$d/ was not installed" }
        elseif ((Get-Tree $got) -ne (Get-Tree (Join-Path $src $d))) { $out += "$d/ differs from the checkout" }
    }
    $agentsDir = Join-Path $dest 'agents'
    $agents = @()
    if (Test-Path -LiteralPath $agentsDir) {
        $agents = @(Get-ChildItem -LiteralPath $agentsDir -Recurse -File -Filter '*.md' | ForEach-Object { $_.FullName.Substring($agentsDir.Length + 1) -replace '\\', '/' } | Sort-Object)
    }
    if (-not ($agents.Count -eq 1 -and $agents[0] -eq 'security-reviewer.md')) {
        $list = $agents -join ' '; if ($list -eq '') { $list = 'nothing' }
        $out += "agents/ holds: $list"
    }
    return ,$out
}

try {
    $problems = Get-InstallProblems $Root
    if ($problems.Count -eq 0) {
        Write-Output 'ok: install.ps1 installs packs/ and modes/ as in the checkout, and agents/ holds only the agent'
    } else {
        foreach ($p in $problems) { Write-Output "FAIL: install.ps1 installs packs/ and modes/ as in the checkout -- $p" }
        $script:fail = $true
    }

    # Self-tests: a copy of the checkout whose installer drops one directory.
    $git = Get-Command git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    foreach ($d in @('packs', 'modes')) {
        $label = "self-test: an install.ps1 that does not copy $d/ fails"
        if (-not $git) { Write-Output "skipped: $label (git not on PATH)"; continue }
        $copy = Join-Path $Tmp "no-$d"
        New-Item -ItemType Directory -Path $copy | Out-Null
        $files = @(& $git.Source -C $Root --no-pager --no-lazy-fetch -c core.fsmonitor=false ls-files --cached --others --exclude-standard)
        foreach ($rel in $files) {
            $to = Join-Path $copy $rel
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $to) | Out-Null
            Copy-Item -LiteralPath (Join-Path $Root $rel) -Destination $to
        }
        $inst = Join-Path $copy 'install.ps1'
        $text = [IO.File]::ReadAllText($inst)
        $broken = $text.Replace(", '$d'", '')
        if ($broken -eq $text) { Write-Output "FAIL: $label -- the edit did not apply"; $script:fail = $true; continue }
        [IO.File]::WriteAllText($inst, $broken)
        $problems = Get-InstallProblems $copy
        if ($problems -contains "$d/ was not installed") { Write-Output "ok: $label" }
        else { Write-Output "FAIL: $label -- got: $($problems -join '; ')"; $script:fail = $true }
    }
} finally {
    Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
}

if ($script:fail) {
    Write-Output 'install check: FAILED'
    exit 1
}
Write-Output 'install check: all checks passed'
exit 0
