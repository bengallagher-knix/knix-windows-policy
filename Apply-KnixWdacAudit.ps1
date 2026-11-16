<#
.SYNOPSIS
  Deploy Windows Defender Application Control (WDAC, "App Control for Business") in AUDIT mode and collect what
  WOULD be blocked, so the real policy can be designed from data.

.DESCRIPTION
  Audit mode blocks NOTHING. Windows logs an event (CodeIntegrity 3076) whenever a file loads that the policy
  would have blocked. The audit policy is built from Microsoft's own template, so the baseline is: Windows
  components, Microsoft Store apps and WHCP-signed drivers are allowed, and everything else (Chrome, Office,
  Slack, anything in AppData/Downloads/Temp...) is reported.

  Install  Build the audit policy from the template, deploy it (no restart on Windows 11 22H2 or later),
           enlarge the CodeIntegrity event log. Safe to re-run: it does nothing if the policy is already there.
  Collect  Read new "would have been blocked" events, de-duplicate them, write a CSV (+ a suggested allow policy
           generated from the audit events) to C:\ProgramData\Knix\WdacAudit and post a summary (and files) to Slack.
  Remove   Remove the audit policy. Only touches the policy this script created (fixed policy ID).

  SECRETS: none are stored here or on the device. For Collect/Install the Atera bootstrap supplies
  KNIX_SLACK_TOKEN / KNIX_SLACK_CHANNEL as environment variables for that one run. Without them the script
  still writes the local CSV and just skips Slack.

  NOTE: other WDAC policies already on the device are left alone. Two base policies are both applied, so if one
  of yours is ENFORCED it keeps blocking; this audit policy only adds logging.

.PARAMETER Base
  DefaultWindows (default): allow Windows + Store + WHCP drivers, report everything else. Most informative.
  AllowMicrosoft: also allow anything Microsoft-signed (less noise from Office, Teams, Edge).

.PARAMETER Force
  Install: remove and redeploy the audit policy even if it is already present.

.PARAMETER PostEmpty
  Collect: post to Slack even when nothing new was found.

.NOTES
  Requirements: Windows 11 (CiTool needs 22H2+; older builds fall back to a file copy and need a restart), and the
  ConfigCI PowerShell cmdlets. Log: C:\ProgramData\Knix\WdacAudit\audit.log. Exit 0 = ok, 1 = a step failed.
#>
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Collect', 'Remove')][string]$Mode = 'Install',
    [ValidateSet('DefaultWindows', 'AllowMicrosoft')][string]$Base = 'DefaultWindows',
    [switch]$Force,
    [switch]$PostEmpty
)

$ErrorActionPreference = 'Stop'
$Root       = Join-Path $env:ProgramData 'Knix\WdacAudit'
$LogFile    = Join-Path $Root 'audit.log'
$StatePath  = Join-Path $Root 'state.json'
$PolicyId   = '4B1D0C6E-8F3A-4E8B-9A57-0C5D2E7F1A39'    # fixed, so a re-install replaces instead of stacking policies
$PolicyName = 'Knix WDAC Audit'
$ExampleDir = Join-Path $env:WINDIR 'schemas\CodeIntegrity\ExamplePolicies'
$ActiveDir  = Join-Path $env:WINDIR 'System32\CodeIntegrity\CiPolicies\Active'
$CiTool     = Join-Path $env:WINDIR 'System32\CiTool.exe'
$CiLog      = 'Microsoft-Windows-CodeIntegrity/Operational'
$MaxEvents  = 30000
$script:Failures = 0

# ----------------------------------------------------------------------------- helpers
function Write-Log([string]$Msg, [string]$Level = 'INFO') {
    $line = '{0} [{1}] [{2}] {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Mode, $Level, $Msg
    Write-Host $line
    try {
        if (-not (Test-Path $Root)) { New-Item -ItemType Directory -Path $Root -Force | Out-Null }
        if ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt 1MB) { Move-Item $LogFile "$LogFile.old" -Force }
        Add-Content -LiteralPath $LogFile -Value $line
    } catch { }
}

function Test-IsAdmin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ----------------------------------------------------------------------------- Slack (token comes from environment only)
function Get-SlackAuth {
    $t = "$($env:KNIX_SLACK_TOKEN)".Trim(); $c = "$($env:KNIX_SLACK_CHANNEL)".Trim()
    if ($t -and $c) { return @{ Token = $t; Channel = $c } }
    return $null
}

function Send-SlackMessage([string]$Text) {
    $a = Get-SlackAuth
    if (-not $a) { Write-Log 'No Slack token/channel in environment, not posted'; return $false }
    $bytes = [Text.Encoding]::UTF8.GetBytes((@{ channel = $a.Channel; text = $Text; unfurl_links = $false } | ConvertTo-Json -Compress))
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $r = Invoke-RestMethod -Uri 'https://slack.com/api/chat.postMessage' -Method Post -Headers @{ Authorization = "Bearer $($a.Token)" } `
             -ContentType 'application/json; charset=utf-8' -Body $bytes -UseBasicParsing -TimeoutSec 30
        if ($r.ok) { Write-Log 'Slack message posted'; return $true }
        Write-Log "Slack refused the message: $($r.error)" 'WARN'
    } catch { Write-Log "Slack post failed: $($_.Exception.Message)" 'WARN' }
    return $false
}

# Uploads files then posts them with a comment. Needs the bot's files:write scope; caller falls back to a plain message.
function Send-SlackFiles([string[]]$Paths, [string]$Comment) {
    $a = Get-SlackAuth
    if (-not $a) { return $false }
    $hdr = @{ Authorization = "Bearer $($a.Token)" }
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $ids = @()
        foreach ($p in $Paths) {
            $bytes = [IO.File]::ReadAllBytes($p)
            $name  = [IO.Path]::GetFileName($p)
            $u = Invoke-RestMethod -Uri 'https://slack.com/api/files.getUploadURLExternal' -Method Post -Headers $hdr `
                 -Body @{ filename = $name; length = $bytes.Length } -UseBasicParsing -TimeoutSec 30
            if (-not $u.ok) { Write-Log "Slack file upload refused ($($u.error))" 'WARN'; return $false }
            Invoke-WebRequest -Uri $u.upload_url -Method Post -Body $bytes -ContentType 'application/octet-stream' -UseBasicParsing -TimeoutSec 120 | Out-Null
            $ids += @{ id = $u.file_id; title = $name }
        }
        $body = [Text.Encoding]::UTF8.GetBytes((@{ files = $ids; channel_id = $a.Channel; initial_comment = $Comment } | ConvertTo-Json -Compress -Depth 4))
        $c = Invoke-RestMethod -Uri 'https://slack.com/api/files.completeUploadExternal' -Method Post -Headers $hdr `
             -ContentType 'application/json; charset=utf-8' -Body $body -UseBasicParsing -TimeoutSec 30
        if ($c.ok) { Write-Log 'Slack report + files posted'; return $true }
        Write-Log "Slack file post refused ($($c.error))" 'WARN'
    } catch { Write-Log "Slack file upload failed: $($_.Exception.Message)" 'WARN' }
    return $false
}

# ----------------------------------------------------------------------------- policy deploy
# Runs a native tool without a stderr line turning into a terminating error (Windows PowerShell 5.1 behaviour).
function Invoke-Native([string]$Exe, [string[]]$CmdArgs) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = (& $Exe @CmdArgs 2>&1 | Out-String)
        return [pscustomobject]@{ Code = $LASTEXITCODE; Out = $out }
    }
    finally { $ErrorActionPreference = $old }
}

function Test-PolicyDeployed {
    if (Test-Path $CiTool) {
        $r = Invoke-Native $CiTool @('--list-policies', '-json')
        return ($r.Out -match [regex]::Escape($PolicyId))
    }
    return (Test-Path (Join-Path $ActiveDir "{$PolicyId}.cip"))
}

function Set-AuditLog {
    # WDAC audit events can be plentiful: 50 MB so they survive between collections.
    [void](Invoke-Native 'wevtutil.exe' @('sl', $CiLog, '/e:true', '/ms:52428800'))
}

function Install-Audit {
    foreach ($c in 'ConvertFrom-CIPolicy', 'Set-RuleOption', 'Set-CIPolicyIdInfo') {
        if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { throw "$c is not available (ConfigCI cmdlets are missing on this Windows edition/build)." }
    }
    Set-AuditLog
    if ((Test-PolicyDeployed) -and -not $Force) {
        Write-Log 'WDAC audit policy is already deployed. Nothing to do (use -Force to redeploy).'
        return
    }

    $template = if ($Base -eq 'AllowMicrosoft') { 'AllowMicrosoft.xml' } else { 'DefaultWindows_Audit.xml' }
    $src = Join-Path $ExampleDir $template
    if (-not (Test-Path $src)) { throw "Template policy not found: $src" }

    $xmlPath = Join-Path $Root 'knix-wdac-audit.xml'
    $cip     = Join-Path $Root "{$PolicyId}.cip"
    Copy-Item -LiteralPath $src -Destination $xmlPath -Force
    Set-CIPolicyIdInfo -FilePath $xmlPath -PolicyName $PolicyName -ResetPolicyID | Out-Null
    Set-RuleOption -FilePath $xmlPath -Option 3      # Enabled: Audit Mode (log, never block)
    Set-RuleOption -FilePath $xmlPath -Option 16     # Enabled: Update Policy No Reboot

    # Pin the policy ID so running Install again replaces this policy instead of adding a second one.
    $x = New-Object System.Xml.XmlDocument
    $x.Load($xmlPath)
    $x.SiPolicy.PolicyID = "{$PolicyId}"
    $x.SiPolicy.BasePolicyID = "{$PolicyId}"
    $x.Save($xmlPath)

    # Safety: refuse to deploy unless audit mode is really in the policy.
    if ((Get-Content -LiteralPath $xmlPath -Raw) -notmatch 'Enabled:Audit Mode') { throw 'Audit Mode option is missing from the policy XML. Not deployed.' }
    ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $cip | Out-Null

    $restart = ''
    if (Test-Path $CiTool) {
        if (Test-PolicyDeployed) { [void](Invoke-Native $CiTool @('--remove-policy', "{$PolicyId}")) }
        $r = Invoke-Native $CiTool @('--update-policy', $cip)
        if ($r.Code -ne 0) { throw "CiTool could not apply the policy: $($r.Out.Trim())" }
        if (-not (Test-PolicyDeployed)) { throw "CiTool reported success but the policy is not listed: $($r.Out.Trim())" }
    } else {
        if (-not (Test-Path $ActiveDir)) { New-Item -ItemType Directory -Path $ActiveDir -Force | Out-Null }
        Copy-Item -LiteralPath $cip -Destination (Join-Path $ActiveDir "{$PolicyId}.cip") -Force
        $restart = ' A restart is needed before it takes effect (this Windows build has no CiTool).'
    }
    Write-Log "WDAC audit policy deployed (base: $Base). Nothing is blocked.$restart"
    [void](Send-SlackMessage ":mag: *WDAC AUDIT deployed on $($env:COMPUTERNAME)* (base: $Base). Nothing is blocked; findings come with the next Collect.$restart")
}

function Remove-Audit {
    if (Test-Path $CiTool) {
        if (Test-PolicyDeployed) { [void](Invoke-Native $CiTool @('--remove-policy', "{$PolicyId}")); Write-Log 'WDAC audit policy removed.' }
        else { Write-Log 'WDAC audit policy was not deployed.' }
    } else {
        $f = Join-Path $ActiveDir "{$PolicyId}.cip"
        if (Test-Path $f) { Remove-Item -LiteralPath $f -Force; Write-Log 'WDAC audit policy file removed (restart needed to stop auditing).' }
    }
    Remove-Item $StatePath -Force -ErrorAction SilentlyContinue
}

# ----------------------------------------------------------------------------- collect
$script:SidCache = @{}
function Resolve-Sid([string]$Sid) {
    if (-not $Sid) { return '' }
    if ($script:SidCache.ContainsKey($Sid)) { return $script:SidCache[$Sid] }
    $n = try { (New-Object Security.Principal.SecurityIdentifier($Sid)).Translate([Security.Principal.NTAccount]).Value } catch { $Sid }
    $script:SidCache[$Sid] = $n
    return $n
}

# Events carry NT device paths (\Device\HarddiskVolume3\...). Convert them to drive letters.
function Get-DriveMap {
    if (-not ('KnixDos' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class KnixDos {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern uint QueryDosDevice(string deviceName, StringBuilder target, int max);
}
'@
    }
    $map = @{}
    foreach ($l in [char[]]'CDEFGHIJKLMNOPQRSTUVWXYZ') {
        $sb = New-Object Text.StringBuilder 1024
        if ([KnixDos]::QueryDosDevice("${l}:", $sb, 1024) -gt 0) { $map[$sb.ToString()] = "${l}:" }
    }
    return $map
}

function ConvertTo-DosPath([string]$p) {
    if ($p -match '^(\\Device\\HarddiskVolume\d+)(\\.*)?$' -and $script:DriveMap.ContainsKey($Matches[1])) {
        return $script:DriveMap[$Matches[1]] + $Matches[2]
    }
    return $p
}

function Get-Field($Xml, [string[]]$Names) {
    foreach ($d in $Xml.Event.EventData.Data) {
        $n = ($d.GetAttribute('Name') -replace '\s', '')
        foreach ($want in $Names) { if ($n -ieq $want) { return "$($d.InnerText)" } }
    }
    return ''
}

function Get-PathLocation([string]$Path) {
    $p = $Path.ToUpper()
    if ($p -match '\\APPDATA\\LOCAL\\TEMP\\|\\WINDOWS\\TEMP\\|\\TEMP\\') { return 'Temp' }
    if ($p -match '\\USERS\\[^\\]+\\(DOWNLOADS|DESKTOP|DOCUMENTS)\\') { return 'User folders (Downloads/Desktop/Docs)' }
    if ($p -match '\\USERS\\[^\\]+\\APPDATA\\') { return 'User AppData' }
    if ($p -match '\\USERS\\') { return 'Other user profile' }
    if ($p -match '\\PROGRAMDATA\\') { return 'ProgramData' }
    if ($p -match '^\\\\') { return 'Network share' }
    if ($p -match '\\PROGRAM FILES') { return 'Program Files' }
    if ($p -match '^[A-Z]:\\' -and $p -notmatch '^[A-Z]:\\WINDOWS\\') { return 'Other folder / drive' }
    return 'Other'
}

function Get-Category([string]$Path) {
    $ext = ''
    if ($Path -match '\.([A-Za-z0-9]+)$') { $ext = $Matches[1].ToLower() }
    switch -Regex ($ext) {
        '^(exe|com|scr)$'         { return 'EXE' }
        '^(dll|ocx|cpl|mui)$'     { return 'DLL' }
        '^sys$'                   { return 'Driver' }
        '^(msi|msp|mst)$'         { return 'MSI' }
        '^(ps1|bat|cmd|vbs|js)$'  { return 'Script' }
    }
    return 'Other'
}

function Get-AuditRows([datetime]$Since) {
    $script:DriveMap = Get-DriveMap

    $f = @{ LogName = $CiLog; Id = 3076 }
    if ($Since) { $f.StartTime = $Since }
    $events = @(Get-WinEvent -FilterHashtable $f -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)
    Write-Log "$CiLog 3076: $($events.Count) audit event(s)$(if ($events.Count -ge $MaxEvents) { ' (capped, the rest will come next run)' })"
    if ($events.Count -eq 0) { return @() }

    # Event 3089 carries the signer of the same file load (same activity id). Use it to name the publisher.
    $pubByActivity = @{}
    $f2 = @{ LogName = $CiLog; Id = 3089 }
    if ($Since) { $f2.StartTime = $Since }
    foreach ($e in @(Get-WinEvent -FilterHashtable $f2 -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)) {
        if (-not $e.ActivityId) { continue }
        $pn = Get-Field ([xml]$e.ToXml()) @('PublisherName')
        if ($pn) { $pubByActivity["$($e.ActivityId)"] = $pn }
    }

    $agg = @{}
    foreach ($ev in $events) {
        $x = [xml]$ev.ToXml()
        $raw = Get-Field $x @('FileName')
        if (-not $raw) { continue }
        $path = ConvertTo-DosPath $raw
        $cat = Get-Category $path
        $key = "$cat|$($path.ToLower())"
        if (-not $agg.ContainsKey($key)) {
            $lvl = Get-Field $x @('ValidatedSigningLevel')
            $agg[$key] = [pscustomobject]@{
                Host = $env:COMPUTERNAME; Category = $cat; Location = (Get-PathLocation $path); Path = $path
                Process = (ConvertTo-DosPath (Get-Field $x @('ProcessName')))
                Publisher = ''; SigningLevel = $lvl; Signed = ([int]($lvl -replace '\D', '0') -gt 1)
                UserWriteable = (Get-Field $x @('UserWriteable')); SHA256 = (Get-Field $x @('SHA256Hash'))
                Count = 0; Users = (New-Object System.Collections.Generic.HashSet[string])
                FirstSeen = $ev.TimeCreated; LastSeen = $ev.TimeCreated
            }
        }
        $row = $agg[$key]
        $row.Count++
        if (-not $row.Publisher -and $ev.ActivityId -and $pubByActivity.ContainsKey("$($ev.ActivityId)")) { $row.Publisher = $pubByActivity["$($ev.ActivityId)"] }
        if ($ev.UserId) { [void]$row.Users.Add((Resolve-Sid $ev.UserId.Value)) }
        if ($ev.TimeCreated -lt $row.FirstSeen) { $row.FirstSeen = $ev.TimeCreated }
        if ($ev.TimeCreated -gt $row.LastSeen)  { $row.LastSeen  = $ev.TimeCreated }
    }
    return @($agg.Values | ForEach-Object { $_.Users = (($_.Users | Sort-Object) -join '; '); $_ })
}

function New-SuggestedPolicy([string]$OutPath) {
    # Microsoft's generator: builds allow rules (publisher + file name/version, hash as fallback) from the audit events.
    if (-not (Get-Command New-CIPolicy -ErrorAction SilentlyContinue)) { return $false }
    New-CIPolicy -Audit -Level FilePublisher -Fallback Hash -UserPEs -MultiplePolicyFormat -FilePath $OutPath | Out-Null
    return (Test-Path $OutPath)
}

function Get-PublisherName([string]$Pub) { if ($Pub -match 'O=([^,]+)') { return $Matches[1].Trim('"') } if ($Pub -match 'CN=([^,]+)') { return $Matches[1].Trim('"') } return $Pub }

function Collect-Audit {
    if (-not (Test-PolicyDeployed)) { Write-Log 'The WDAC audit policy is not deployed on this device; run Install first.' 'WARN' }
    $since = $null
    if (Test-Path $StatePath) { try { $since = [datetime]((Get-Content $StatePath -Raw | ConvertFrom-Json).LastCollect) } catch { } }
    $started = Get-Date
    $rows = @(Get-AuditRows $since)
    Write-Log "$($rows.Count) unique would-be-blocked item(s) since $(if ($since) { $since } else { 'the beginning of the log' })"

    if ($rows.Count -eq 0) {
        if ($PostEmpty) { [void](Send-SlackMessage ":white_check_mark: *WDAC audit on $($env:COMPUTERNAME):* nothing new would have been blocked.") }
        @{ LastCollect = $started.ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath $StatePath -Encoding UTF8
        return
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmm'
    $csv = Join-Path $Root "audit-$($env:COMPUTERNAME)-$stamp.csv"
    $rows | Sort-Object Count -Descending |
        Select-Object Host, Category, Location, Path, Process, Publisher, Signed, SigningLevel, UserWriteable, SHA256, Count, Users, FirstSeen, LastSeen |
        Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    $files = @($csv)

    $pol = Join-Path $Root "suggested-policy-$($env:COMPUTERNAME)-$stamp.xml"
    try { if (New-SuggestedPolicy $pol) { $files += $pol } } catch { Write-Log "Suggested-policy step skipped: $($_.Exception.Message)" 'WARN' }

    # ---- Slack summary
    $users = @($rows | ForEach-Object { $_.Users -split '; ' } | Where-Object { $_ } | Sort-Object -Unique)
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add(":mag: *WDAC AUDIT $($env:COMPUTERNAME):* $($rows.Count) unique files would have been blocked | users: $($users -join ', ')")
    $cat = ($rows | Group-Object Category | Sort-Object Count -Descending | ForEach-Object { "$($_.Name) $($_.Count)" }) -join ' | '
    $loc = ($rows | Group-Object Location | Sort-Object Count -Descending | ForEach-Object { "$($_.Name) $($_.Count)" }) -join ' | '
    [void]$lines.Add("*By type:* $cat")
    [void]$lines.Add("*By location:* $loc")
    $pubs = @($rows | Where-Object Publisher | Group-Object { Get-PublisherName $_.Publisher } | Sort-Object Count -Descending | Select-Object -First 8)
    if ($pubs.Count) {
        [void]$lines.Add('*Signed - allow by PUBLISHER:*')
        foreach ($p in $pubs) { [void]$lines.Add("  - $($p.Name) ($($p.Count) files)") }
    }
    $uns = @($rows | Where-Object { -not $_.Publisher } | Sort-Object Count -Descending | Select-Object -First 8)
    if ($uns.Count) {
        [void]$lines.Add('*No publisher found - needs a PATH or HASH rule, or removal:*')
        foreach ($u in $uns) { [void]$lines.Add("  - $($u.Path) (x$($u.Count))") }
    }
    $text = $lines -join "`n"
    if ($text.Length -gt 3500) { $text = $text.Substring(0, 3500) + "`n..." }

    $sent = $false
    if (Get-SlackAuth) {
        $sent = Send-SlackFiles $files $text
        if (-not $sent) { $sent = Send-SlackMessage ($text + "`n_(files not uploaded; add files:write to the bot. CSV is on the device: $csv)_") }
    } else {
        Write-Log "No Slack token: report left on device at $csv"
        $sent = $true     # local-only run; still advance so the next run is incremental
    }
    # Only move the watermark forward once the findings reached Slack (or this was a local-only run).
    if ($sent) { @{ LastCollect = $started.ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath $StatePath -Encoding UTF8 }
    else { $script:Failures++; Write-Log 'Findings NOT delivered to Slack; next Collect will re-send them.' 'ERROR' }

    # Keep the device tidy
    Get-ChildItem $Root -Include 'audit-*.csv', 'suggested-policy-*.xml' -Recurse -ErrorAction SilentlyContinue |
        Where-Object LastWriteTime -lt (Get-Date).AddDays(-14) | Remove-Item -Force -ErrorAction SilentlyContinue
}

# ============================================================================= main
if (-not (Test-IsAdmin)) { Write-Log 'Must run elevated/SYSTEM' 'ERROR'; exit 1 }
if (-not (Test-Path $Root)) { New-Item -ItemType Directory -Path $Root -Force | Out-Null }

try {
    switch ($Mode) {
        'Install' { Install-Audit }
        'Collect' { Collect-Audit }
        'Remove'  { Remove-Audit }
    }
} catch {
    $script:Failures++
    Write-Log "$Mode FAILED: $($_.Exception.Message)" 'ERROR'
    if ($Mode -ne 'Remove') { [void](Send-SlackMessage ":x: *WDAC audit $Mode FAILED on $($env:COMPUTERNAME):* $($_.Exception.Message)") }
}

if ($script:Failures -gt 0) { Write-Log "Completed with $($script:Failures) failure(s)" 'ERROR'; exit 1 }
Write-Log 'Completed OK'
exit 0
