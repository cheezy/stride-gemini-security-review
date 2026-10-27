# Contract pins on agents/security-reviewer.md for the Gemini CLI port.
# PowerShell mirror of check_agent_contract.sh: same labels, same exit codes.
# Change both together.
#
# W2480 -- the template-token pin. Gemini CLI runs templateString() over a
# subagent's system prompt (the agent body) and throws for any ${word}
# placeholder that is not one of its inputs. The pin uses the CLI's own regex,
# /\$\{(\w+)\}/g, with \w spelled as ASCII [A-Za-z0-9_] because .NET's \w also
# matches non-ASCII letters, which JavaScript's \w does not. It scans the whole
# file, frontmatter included. See check_agent_contract.sh for the full rationale.
#
# Offline. Reads the agent; the self-tests write only to a temporary directory.
# This file is kept ASCII-only so Windows PowerShell 5.1 reads it correctly.
#
# Usage:
#   pwsh -NoProfile -File lib\check_agent_contract.ps1 [agent-file]
#   (or from Windows PowerShell 5.1:  powershell -File lib\check_agent_contract.ps1)
# Exit code: 0 when every pin and self-test holds; 1 when any fails, or when
#            the agent file is missing or empty.

param([string]$AgentPath = '')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Self = $MyInvocation.MyCommand.Path
$CustomPath = $AgentPath -ne ''
if (-not $CustomPath) {
    $AgentPath = Join-Path (Join-Path (Join-Path $ScriptDir '..') 'agents') 'security-reviewer.md'
}
$script:fail = $false

if (-not (Test-Path -LiteralPath $AgentPath -PathType Leaf)) {
    Write-Output "FAIL: agent file not found: $AgentPath"
    exit 1
}
if ((Get-Item -LiteralPath $AgentPath).Length -eq 0) {
    Write-Output "FAIL: agent file is empty: $AgentPath"
    exit 1
}
try {
    [IO.File]::OpenRead($AgentPath).Dispose()
} catch {
    Write-Output "FAIL: agent file is not readable: $AgentPath"
    exit 1
}

# --- W2480: no Gemini CLI template token -------------------------------------

$TemplateTokenRe = '\$\{[A-Za-z0-9_]+\}'

# Get-TemplateTokens <file> -- `line:token` for every ${word} placeholder.
function Get-TemplateTokens([string]$path) {
    $text = [IO.File]::ReadAllText($path, [Text.Encoding]::UTF8)
    $lines = $text -split "`n"
    $found = @()
    for ($i = 0; $i -lt $lines.Count; $i++) {
        foreach ($m in [regex]::Matches($lines[$i], $TemplateTokenRe)) {
            $found += ('{0}:{1}' -f ($i + 1), $m.Value)
        }
    }
    return ,$found
}

$tokens = Get-TemplateTokens $AgentPath
if ($tokens.Count -eq 0) {
    Write-Output 'ok: no Gemini CLI template token in the agent'
} else {
    Write-Output ('FAIL: no Gemini CLI template token in the agent -- found: ' + ($tokens -join ' ') + ' ')
    $script:fail = $true
}

# --- Self-tests: a break-it per pin ------------------------------------------
# Each case writes a variant of the agent to a temporary directory and runs this
# script on it as a child. CHECK_AGENT_CONTRACT_CHILD stops the child running the
# self-tests again. Skipped when a custom agent path is given.

if (-not $env:CHECK_AGENT_CONTRACT_CHILD -and -not $CustomPath) {
    $Interpreter = (Get-Process -Id $PID).Path
    $Utf8NoBom = New-Object System.Text.UTF8Encoding $false
    $Tmp = Join-Path ([IO.Path]::GetTempPath()) ('check-agent-contract.' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $Tmp | Out-Null
    # Built rather than written: inside a double-quoted PowerShell string a
    # dollar-brace form is variable syntax, so the planted tokens are assembled
    # from $D instead.
    $D = '$'

    function Expect([string]$label, [int]$want, [string]$needle, [string]$file) {
        $env:CHECK_AGENT_CONTRACT_CHILD = '1'
        try {
            $out = (& $Interpreter -NoProfile -File $Self $file 2>&1 | Out-String)
            $rc = $LASTEXITCODE
        } finally {
            Remove-Item Env:\CHECK_AGENT_CONTRACT_CHILD -ErrorAction SilentlyContinue
        }
        if ($rc -ne $want) {
            Write-Output "FAIL: self-test: $label -- exit $rc, wanted $want"; $script:fail = $true
        } elseif ($needle -ne '' -and -not $out.Contains($needle)) {
            Write-Output "FAIL: self-test: $label -- output lacks: $needle"; $script:fail = $true
        } else {
            Write-Output "ok: self-test: $label"
        }
    }

    function Write-Variant([string]$name, [string]$text) {
        $path = Join-Path $Tmp $name
        [IO.File]::WriteAllText($path, $text, $Utf8NoBom)
        return $path
    }

    try {
        $baseText = [IO.File]::ReadAllText($AgentPath, [Text.Encoding]::UTF8) -replace "`r`n", "`n"
        if (-not $baseText.EndsWith("`n")) { $baseText += "`n" }
        $base = Write-Variant 'agent.md' $baseText
        Expect 'the shipped agent passes the template-token pin' 0 'ok: no Gemini CLI template token' $base

        $plantedBody = $baseText + "Planted: <a href={``/redirect?to=$D{url}``}>`n"
        $p = Write-Variant 'planted-body.md' $plantedBody
        Expect "a planted $D{url} in the body fails the pin" 1 'found: ' $p

        $fmLines = $baseText -split "`n"
        $fmText = (($fmLines[0..2] + "  Planted $D{id} in the description." + $fmLines[3..($fmLines.Count - 1)]) -join "`n")
        $p = Write-Variant 'planted-fm.md' $fmText
        Expect "a $D{word} token in the frontmatter description fails the pin" 1 "found: 4:$D{id}" $p

        $p = Write-Variant 'planted-digit.md' ($baseText + "Digit key: $D{1}`n")
        Expect "a digit-only $D{1} (the CLI's \w) fails the pin" 1 'found: ' $p

        $p = Write-Variant 'planted-escaped.md' ($baseText + "Escaped: \$D{url}`n")
        Expect "a backslash-escaped \$D{url} still fails the pin" 1 'found: ' $p

        $dollars = $baseText +
            "Price: $($D)5, a bare $D and $D$D and $($D)VAR and $($D)(cmd)`n" +
            "Open brace with no word: $D{ and $D{} and $D{ url } and $D{-x}`n" +
            "Dotted and doubled: $D{req.body.path} and $D{{ github.event.issue.title }}`n"
        $p = Write-Variant 'dollars.md' $dollars
        Expect "a bare $D, $D$D or $D{ with no word does not trip the pin" 0 'ok: no Gemini CLI template token' $p

        $p = Write-Variant 'crlf.md' ($baseText -replace "`n", "`r`n")
        Expect 'the agent with CRLF line endings passes the pin' 0 'ok: no Gemini CLI template token' $p

        $p = Write-Variant 'crlf-planted.md' ($plantedBody -replace "`n", "`r`n")
        Expect "a planted $D{url} under CRLF line endings fails the pin" 1 'found: ' $p

        Expect 'a missing agent file exits non-zero with a message' 1 'FAIL: agent file not found' (Join-Path $Tmp 'missing.md')

        $p = Write-Variant 'empty.md' ''
        Expect 'an empty agent file exits non-zero with a message' 1 'FAIL: agent file is empty' $p

        # Needs chmod (macOS/Linux); on Windows the case is reported as skipped.
        $p = Write-Variant 'unreadable.md' $baseText
        $chmod = Get-Command chmod -CommandType Application -ErrorAction SilentlyContinue
        $unreadable = $false
        if ($chmod) {
            & $chmod.Source 000 $p
            try { [IO.File]::OpenRead($p).Dispose() } catch { $unreadable = $true }
        }
        if ($unreadable) {
            Expect 'an unreadable agent file exits non-zero with a message' 1 'FAIL: agent file is not readable' $p
        } else {
            Write-Output 'ok: self-test: an unreadable agent file exits non-zero with a message -- skipped (permissions not enforced for this user)'
        }
        if ($chmod) { & $chmod.Source 600 $p }
    } finally {
        Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($script:fail) {
    Write-Output 'agent contract: FAILED'
    exit 1
}
Write-Output 'agent contract: all pins present'
exit 0
