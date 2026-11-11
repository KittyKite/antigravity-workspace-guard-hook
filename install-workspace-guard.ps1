# Self-contained installer for the Antigravity Global Workspace Guard Hook (Hardened + Live CMD Alert Popup)
# Run this script in PowerShell on any Windows computer to install the hook globally.

$configDir  = Join-Path $env:USERPROFILE ".gemini\config"
$scriptsDir = Join-Path $configDir "scripts"
$hooksFile  = Join-Path $configDir "hooks.json"
$guardFile  = Join-Path $scriptsDir "workspace-guard.ps1"

New-Item -ItemType Directory -Force -Path $scriptsDir | Out-Null

$hooksJson = @'
{
  "global-workspace-jail-9f8a2b": {
    "enabled": true,
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "powershell -NoProfile -ExecutionPolicy Bypass -File scripts/workspace-guard.ps1",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
'@

$guardScript = @'
$ErrorActionPreference = "Stop"

try {
    $rawInput = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($rawInput)) {
        @{ decision = "allow" } | ConvertTo-Json -Compress
        exit 0
    }
    $payload = $rawInput | ConvertFrom-Json
} catch {
    @{ decision = "allow" } | ConvertTo-Json -Compress
    exit 0
}

$tool = "$($payload.toolCall.name)".ToLowerInvariant()
$args = $payload.toolCall.args

$geminiRoot = Join-Path $env:USERPROFILE ".gemini"

$readWritePaths = @()
if ($payload.workspacePaths) {
    $readWritePaths += @($payload.workspacePaths)
}
if ($payload.artifactDirectoryPath) {
    $readWritePaths += "$($payload.artifactDirectoryPath)"
}
$readWritePaths += (Join-Path $geminiRoot "antigravity\scratch")

$readOnlyPaths = @(
    (Join-Path $geminiRoot "antigravity\builtin"),
    (Join-Path $geminiRoot "antigravity\plugins"),
    (Join-Path $geminiRoot "config")
)
if ($payload.transcriptPath) {
    $readOnlyPaths += "$($payload.transcriptPath)"
}

function Send-SecurityAlert {
    param(
        [string]$Decision,
        [string]$RuleName,
        [string]$TargetInfo,
        [string]$Reason
    )
    try {
        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $activeWs  = if ($payload.workspacePaths -and $payload.workspacePaths.Count -gt 0) { ($payload.workspacePaths -join ", ") } else { "(No Active Workspace - Scratch Only)" }
        $convId    = "$($payload.conversationId)"
        $colorCode = if ($Decision -eq "deny") { "4F" } else { "6F" } # 4F = Red bg/White text, 6F = Yellow-Brown bg/White text

        $alertLines = @(
            "=========================================================================="
            "               ANTIGRAVITY SECURITY GUARD - RULE TRIPPED                  "
            "=========================================================================="
            " Time           : $timestamp"
            " Action Taken   : $($Decision.ToUpperInvariant())"
            " Rule Tripped   : $RuleName"
            " Tool Called    : $tool"
            " Active Project : $activeWs"
            " Conversation   : $convId"
            "--------------------------------------------------------------------------"
            " Target / Command:"
            " $TargetInfo"
            ""
            " Reason:"
            " $Reason"
            "=========================================================================="
            ""
        )
        $alertText = $alertLines -join "`r`n"

        # 1. Write to temp alert file (used by CMD window to prevent any command injection)
        $tempAlertFile = Join-Path $env:TEMP "agy-security-alert.txt"
        Set-Content -Path $tempAlertFile -Value $alertText -Encoding UTF8 -Force

        # 2. Append to persistent security log in ~/.gemini/security-alerts.log
        $logFile = Join-Path $geminiRoot "security-alerts.log"
        Add-Content -Path $logFile -Value $alertText -Encoding UTF8 -Force

        # 3. Pop up a visible CMD console window asynchronously via conhost.exe
        $cmdArgs = 'cmd.exe /c "color ' + $colorCode + ' & mode con: cols=80 lines=25 & title [ANTIGRAVITY SECURITY ALERT: ' + $RuleName + '] & type ""' + $tempAlertFile + '"" & pause"'
        Start-Process -FilePath "conhost.exe" -ArgumentList $cmdArgs -ErrorAction SilentlyContinue
    } catch {
        # Never let alert UI failure prevent blocking the tool call
    }
}

function Stop-WithAlert {
    param(
        [string]$Decision,
        [string]$RuleName,
        [string]$TargetInfo,
        [string]$Reason
    )
    Send-SecurityAlert -Decision $Decision -RuleName $RuleName -TargetInfo $TargetInfo -Reason $Reason
    @{ decision = $Decision; reason = "[$RuleName] $Reason" } | ConvertTo-Json -Compress
    exit 0
}

function Test-PathUnder([string]$targetPath, [string[]]$allowedRoots) {
    if ([string]::IsNullOrWhiteSpace($targetPath)) { return $false }
    try {
        $cleanTarget = $targetPath.Trim('"', "'", ' ')
        $resolved = [System.IO.Path]::GetFullPath($cleanTarget).TrimEnd('\', '/')
        foreach ($root in $allowedRoots) {
            if ([string]::IsNullOrWhiteSpace($root)) { continue }
            $cleanRoot = "$root".Trim('"', "'", ' ')
            $rootFull = [System.IO.Path]::GetFullPath($cleanRoot).TrimEnd('\', '/')
            if ($resolved.Equals($rootFull, [System.StringComparison]::OrdinalIgnoreCase) -or
                $resolved.StartsWith("$rootFull\", [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
    } catch {
        return $false
    }
    return $false
}

function Test-SecretFile([string]$pathStr) {
    if ([string]::IsNullOrWhiteSpace($pathStr)) { return $false }
    $leaf = [System.IO.Path]::GetFileName($pathStr.Trim('"', "'", ' '))
    if ($leaf -match '^(\.env(\..+)?|.*\.(pem|key|pfx|p12)|id_rsa.*|id_ed25519.*|\.npmrc|\.pypirc|credentials\.json)$') {
        if ($leaf -match '^\.env\.(example|sample|template|defaults)$') { return $false }
        return $true
    }
    return $false
}

function Test-TrojanWriteTarget([string]$pathStr) {
    if ([string]::IsNullOrWhiteSpace($pathStr)) { return $false }
    $norm = $pathStr.Trim('"', "'", ' ').Replace('/', '\')
    if ($norm -match '(^|\\)(\.agents|\.agent|_agents|_agent|\.git\\hooks|\.git\\config|\.vscode\\tasks\.json|\.vscode\\launch\.json|GEMINI\.md|AGENTS\.md|CLAUDE\.md|\.cursorrules)(\\|$)') {
        return $true
    }
    return $false
}

# Extract target file/directory path from tool args if present
$targetPath = $null
foreach ($prop in @("Path", "TargetFile", "DirectoryPath", "SearchPath")) {
    if ($args.PSObject.Properties[$prop] -and -not [string]::IsNullOrWhiteSpace("$($args.$prop)")) {
        $targetPath = "$($args.$prop)".Trim('"', "'", ' ')
        break
    }
}

# 1. File Read / Search tools
if ($tool -in @("read_file", "view_file", "list_dir", "find_by_name", "grep_search") -and $targetPath) {
    if (-not (Test-PathUnder $targetPath $readWritePaths) -and -not (Test-PathUnder $targetPath $readOnlyPaths)) {
        Stop-WithAlert -Decision "deny" -RuleName "Outside-Workspace-Read" -TargetInfo $targetPath -Reason "Read access blocked outside project workspace: $targetPath"
    }

    if (Test-SecretFile $targetPath) {
        Stop-WithAlert -Decision "force_ask" -RuleName "Secret-File-Read" -TargetInfo $targetPath -Reason "Agent is attempting to read a sensitive secret/credential file: $targetPath"
    }

    # Pre-read prompt injection scan on text files (skip internal brain/transcript files)
    $brainRoot = Join-Path $geminiRoot "antigravity\brain"
    if ($tool -in @("read_file", "view_file") -and -not (Test-PathUnder $targetPath @($brainRoot)) -and (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
        try {
            $fileInfo = Get-Item -LiteralPath $targetPath -ErrorAction SilentlyContinue
            if ($fileInfo -and $fileInfo.Length -gt 0 -and $fileInfo.Length -lt 5MB) {
                $rawText = [System.IO.File]::ReadAllText($fileInfo.FullName)
                # Detect invisible Unicode bidi overrides or Plane 14 tag characters
                if ($rawText -match '[\u202A-\u202E\u2066-\u2069]|\uDB40[\uDC00-\uDC7F]') {
                    Stop-WithAlert -Decision "force_ask" -RuleName "Unicode-Prompt-Injection" -TargetInfo $targetPath -Reason "Suspicious invisible Unicode tag/override characters detected in file: $targetPath"
                }
                # Detect fake system/user prompt boundary injection tags
                if ($rawText -match '(</USER_REQUEST>|<SYSTEM_MESSAGE>|IGNORE ALL PREVIOUS INSTRUCTIONS|DISREGARD ALL PREVIOUS INSTRUCTIONS)') {
                    Stop-WithAlert -Decision "force_ask" -RuleName "Prompt-Injection-Signature" -TargetInfo $targetPath -Reason "Suspicious prompt injection boundary markers detected in file: $targetPath"
                }
            }
        } catch {
            # Ignore binary/locked file read errors during pre-scan
        }
    }

    @{ decision = "allow" } | ConvertTo-Json -Compress
    exit 0
}

# 2. File Write / Edit tools
if ($tool -in @("write_file", "write_to_file", "edit_file", "replace_file_content", "multi_replace_file_content", "code_action") -and $targetPath) {
    if (-not (Test-PathUnder $targetPath $readWritePaths)) {
        if (Test-PathUnder $targetPath @($geminiRoot)) {
            Stop-WithAlert -Decision "force_ask" -RuleName "Gemini-Config-Write" -TargetInfo $targetPath -Reason "Agent is attempting to modify .gemini configuration: $targetPath"
        }
        Stop-WithAlert -Decision "deny" -RuleName "Outside-Workspace-Write" -TargetInfo $targetPath -Reason "Write access blocked outside project workspace: $targetPath"
    }

    if (Test-SecretFile $targetPath) {
        Stop-WithAlert -Decision "force_ask" -RuleName "Secret-File-Write" -TargetInfo $targetPath -Reason "Agent is attempting to modify a secret/credential file: $targetPath"
    }

    if (Test-TrojanWriteTarget $targetPath) {
        Stop-WithAlert -Decision "force_ask" -RuleName "Agent-Config-Or-Hook-Write" -TargetInfo $targetPath -Reason "Agent is attempting to modify project hooks, agent rules, or IDE auto-run tasks: $targetPath"
    }

    @{ decision = "allow" } | ConvertTo-Json -Compress
    exit 0
}

# 3. Terminal commands (run_command)
if ($tool -eq "run_command" -and $args.PSObject.Properties["CommandLine"]) {
    $cmd = "$($args.CommandLine)".Trim('"', "'")

    # 3a. Check any explicit drive paths referenced in the command line (skip http:// or https://)
    $driveMatches = [regex]::Matches($cmd, '(?<![A-Za-z0-9_])([A-Za-z]:[/\\][^\s"''`;|&><)*?]*)')
    foreach ($m in $driveMatches) {
        $refPath = $m.Groups[1].Value
        if (-not (Test-PathUnder $refPath $readWritePaths) -and -not (Test-PathUnder $refPath $readOnlyPaths)) {
            Stop-WithAlert -Decision "deny" -RuleName "Outside-Workspace-Command" -TargetInfo $cmd -Reason "Command blocked: references path outside project workspace ($refPath)"
        }
        if (Test-PathUnder $refPath @((Join-Path $geminiRoot "config"))) {
            Stop-WithAlert -Decision "force_ask" -RuleName "Gemini-Config-Command" -TargetInfo $cmd -Reason "Command references .gemini/config ($refPath)"
        }
    }

    # 3b. Block relative parent traversal or home directory shortcuts
    if ($cmd -match '(^|[\s"''=/\\])\.\.[/\\]|(^|[\s"''=])~[/\\]|\$HOME\b|\$env:USERPROFILE\b|%USERPROFILE%') {
        Stop-WithAlert -Decision "deny" -RuleName "Directory-Traversal-Command" -TargetInfo $cmd -Reason "Command blocked: references parent (../) or user home directory outside project workspace."
    }

    # 3c. Block obfuscated PowerShell / Base64 / Invoke-Expression / Environment dumping
    if ($cmd -match '(?i)(-[eE]ncodedCommand\b|-[eE]nc\b|FromBase64String|Invoke-Expression\b|\biex\b|Get-ChildItem\s+Env:|\bgci\s+env:|\bdir\s+env:|\bls\s+env:|GetEnvironmentVariables)') {
        Stop-WithAlert -Decision "deny" -RuleName "Obfuscation-Or-Env-Dump" -TargetInfo $cmd -Reason "Command blocked: uses Base64 obfuscation, Invoke-Expression, or dumps environment variables."
    }

    # 3d. Block reading/writing .env or secret files via shell
    if ($cmd -match '(?i)(^|[\s"''/\\])(\.env(\.local|\.prod|\.production|\.dev)?|id_rsa|id_ed25519|\.npmrc|\.pypirc)\b') {
        Stop-WithAlert -Decision "force_ask" -RuleName "Secret-File-Shell-Access" -TargetInfo $cmd -Reason "Command references a sensitive credential file (.env, SSH key, or token rc)."
    }

    # 3e. Allow normal curl/iwr GET lookups, but prompt if uploading local files
    if ($cmd -match '(?i)\b(curl|curl\.exe|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b' -and
        $cmd -match '(?i)(--data-binary\s+@|-d\s*@|-F\s+|--upload-file\b|-InFile\b)') {
        Stop-WithAlert -Decision "force_ask" -RuleName "Network-File-Upload" -TargetInfo $cmd -Reason "Network command is attempting to upload a local file."
    }

    # 3f. Prompt if shell command modifies .agents or .git/hooks
    if ($cmd -match '(?i)(^|[\s"''/\\])(\.agents|\.agent|\.git[/\\]hooks|GEMINI\.md|AGENTS\.md)\b') {
        Stop-WithAlert -Decision "force_ask" -RuleName "Agent-Config-Shell-Touch" -TargetInfo $cmd -Reason "Command references project agent configuration or git hooks."
    }
}

# Auto-approve permitted workspace operations
@{ decision = "allow" } | ConvertTo-Json -Compress
'@

Set-Content -Path $hooksFile -Value $hooksJson -Encoding UTF8
Set-Content -Path $guardFile -Value $guardScript -Encoding UTF8

Write-Host "Installed Hardened Antigravity Workspace Guard Hook (with CMD Alert Popup) to: $configDir" -ForegroundColor Green
