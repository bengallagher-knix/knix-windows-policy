<#
.SYNOPSIS
  Deploy AppLocker in AUDIT-ONLY mode and collect what WOULD be blocked, so the real policy can be designed from data.

.DESCRIPTION
  Audit mode blocks NOTHING. Windows logs an event whenever something runs that a realistic allow-list policy
  would have blocked (the Microsoft "default rules" shape: Program Files + Windows allowed, everything else
  such as AppData, Downloads, Temp and ProgramData is flagged).

  Install  Apply the audit-only policy, start the Application Identity service, enlarge the AppLocker event logs.
  Collect  Read new "would have been blocked" events, de-duplicate them, write a CSV (+ AppLocker's own suggested
           rules XML) to C:\ProgramData\Knix\AppLockerAudit and post a summary (and files) to Slack.
  Remove   Put AppLocker back to Not Configured. Only touches rules this script created.

  SECRETS: none are stored here or on the device. For Collect, the Atera bootstrap supplies
  KNIX_SLACK_TOKEN / KNIX_SLACK_CHANNEL as environment variables for that one run. Without them the script
  still writes the local CSV and just skips Slack.

  NOTE: this replaces the LOCAL AppLocker policy. It refuses to run if rules that are not its own exist
  (rules named KNIXAUDIT-* are treated as its own and replaced).

.PARAMETER IncludeDll
  Also audit DLL loads. Very noisy and slower. Leave off for the first round.

.PARAMETER AdminsExempt
  Add an "Administrators may run everything" rule, like the Microsoft defaults. Leave OFF while auditing so apps
  run by users who happen to be local admins are still reported. Turn ON to see what standard users would hit.

.PARAMETER PostEmpty
  Collect: post to Slack even when nothing new was found.

.NOTES
  Log: C:\ProgramData\Knix\AppLockerAudit\audit.log. Exit 0 = ok, 1 = a step failed.
#>
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Collect', 'Remove')][string]$Mode = 'Install',
    [switch]$IncludeDll,
    [switch]$AdminsExempt,
    [switch]$PostEmpty
)

$ErrorActionPreference = 'Stop'
$Root      = Join-Path $env:ProgramData 'Knix\AppLockerAudit'
$LogFile   = Join-Path $Root 'audit.log'
$StatePath = Join-Path $Root 'state.json'
$Prefix    = 'KNIXAUDIT-'
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

function New-StableGuid([string]$Seed) {
    $md5 = [Security.Cryptography.MD5]::Create()
    ([guid]::new($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($Seed)))).ToString()
}

function Get-ForeignRuleCount {
    $count = 0
    $pol = Get-AppLockerPolicy -Local -ErrorAction SilentlyContinue
    if ($pol) { foreach ($c in $pol.RuleCollections) { foreach ($r in $c) { if ($r.Name -notlike "$Prefix*") { $count++ } } } }
    return $count
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

# ----------------------------------------------------------------------------- policy
function PathRule([string]$Name, [string]$Sid, [string]$Path) {
    $id = New-StableGuid "$Prefix$Name"
    "    <FilePathRule Id=`"$id`" Name=`"$Prefix$Name`" Description=`"Audit baseline`" UserOrGroupSid=`"$Sid`" Action=`"Allow`"><Conditions><FilePathCondition Path=`"$Path`" /></Conditions></FilePathRule>"
}

function SignedRule([string]$Name) {
    $id = New-StableGuid "$Prefix$Name"
    "    <FilePublisherRule Id=`"$id`" Name=`"$Prefix$Name`" Description=`"Audit baseline: any signed file`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`"><Conditions><FilePublisherCondition PublisherName=`"*`" ProductName=`"*`" BinaryName=`"*`"><BinaryVersionRange LowSection=`"*`" HighSection=`"*`" /></FilePublisherCondition></Conditions></FilePublisherRule>"
}

function Build-AuditXml {
    $sb = New-Object Text.StringBuilder
    [void]$sb.AppendLine('<AppLockerPolicy Version="1">')
    foreach ($type in @('Exe', 'Script', 'Dll')) {
        if ($type -eq 'Dll' -and -not $IncludeDll) { continue }
        [void]$sb.AppendLine("  <RuleCollection Type=`"$type`" EnforcementMode=`"AuditOnly`">")
        [void]$sb.AppendLine((PathRule "$type-ProgramFiles" 'S-1-1-0' '%PROGRAMFILES%\*'))
        [void]$sb.AppendLine((PathRule "$type-Windows" 'S-1-1-0' '%WINDIR%\*'))
        if ($AdminsExempt) { [void]$sb.AppendLine((PathRule "$type-Admins" 'S-1-5-32-544' '*')) }
        [void]$sb.AppendLine('  </RuleCollection>')
    }
    [void]$sb.AppendLine('  <RuleCollection Type="Msi" EnforcementMode="AuditOnly">')
    [void]$sb.AppendLine((SignedRule 'Msi-Signed'))
    [void]$sb.AppendLine((PathRule 'Msi-Installer' 'S-1-1-0' '%WINDIR%\Installer\*'))
    if ($AdminsExempt) { [void]$sb.AppendLine((PathRule 'Msi-Admins' 'S-1-5-32-544' '*')) }
    [void]$sb.AppendLine('  </RuleCollection>')
    [void]$sb.AppendLine('  <RuleCollection Type="Appx" EnforcementMode="AuditOnly">')
    [void]$sb.AppendLine((SignedRule 'Appx-Signed'))
    [void]$sb.AppendLine('  </RuleCollection>')
    [void]$sb.AppendLine('</AppLockerPolicy>')
    return $sb.ToString()
}

function Enable-AppIdService {
    try { Set-Service -Name AppIDSvc -StartupType Automatic -ErrorAction Stop }
    catch { & sc.exe config appidsvc start= auto | Out-Null }
    if ((Get-Service -Name AppIDSvc).Status -ne 'Running') { Start-Service -Name AppIDSvc -ErrorAction Stop; Write-Log 'Started Application Identity service' }
}

function Set-AuditLogs {
    foreach ($l in @('Microsoft-Windows-AppLocker/EXE and DLL', 'Microsoft-Windows-AppLocker/MSI and Script',
                     'Microsoft-Windows-AppLocker/Packaged app-Execution', 'Microsoft-Windows-AppLocker/Packaged app-Deployment')) {
        & wevtutil.exe sl $l /e:true /ms:20971520 2>&1 | Out-Null      # enabled, 20 MB so events survive between collections
    }
}

function Install-Audit {
    if ((Get-ForeignRuleCount) -gt 0) {
        throw 'Existing AppLocker rules that this script did not create were found. Not overwriting them.'
    }
    $xml = Build-AuditXml
    $tmp = Join-Path $env:TEMP 'knix-applocker-audit.xml'
    Set-Content -LiteralPath $tmp -Value $xml -Encoding UTF8
    try { Set-AppLockerPolicy -XmlPolicy $tmp } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    Enable-AppIdService
    Set-AuditLogs

    # Read back and confirm: every collection must say AuditOnly, never Enabled.
    $live = Get-AppLockerPolicy -Local -Xml
    if ($live -match 'EnforcementMode="Enabled"') { throw 'Read-back shows an ENFORCED collection. Aborting; run -Mode Remove.' }
    $mode = ([regex]::Matches($live, 'EnforcementMode="AuditOnly"')).Count
    Write-Log "Audit-only AppLocker policy active ($mode collections). Nothing is blocked."
    $dll = if ($IncludeDll) { 'EXE, DLL, scripts, MSI, packaged apps' } else { 'EXE, scripts, MSI, packaged apps' }
    $adm = if ($AdminsExempt) { 'admins exempt' } else { 'admins audited too' }
    [void](Send-SlackMessage ":mag: *AppLocker AUDIT deployed on $($env:COMPUTERNAME)* - $dll ($adm). Nothing is blocked; findings come with the next Collect.")
}

function Remove-Audit {
    if ((Get-ForeignRuleCount) -gt 0) { throw 'Existing non-audit AppLocker rules present, left untouched.' }
    $tmp = Join-Path $env:TEMP 'knix-applocker-empty.xml'
    $parts = foreach ($t in 'Exe', 'Script', 'Msi', 'Dll', 'Appx') { "<RuleCollection Type=`"$t`" EnforcementMode=`"NotConfigured`" />" }
    Set-Content -LiteralPath $tmp -Value ('<AppLockerPolicy Version="1">' + ($parts -join '') + '</AppLockerPolicy>') -Encoding UTF8
    try { Set-AppLockerPolicy -XmlPolicy $tmp } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    Remove-Item $StatePath -Force -ErrorAction SilentlyContinue
    Write-Log 'AppLocker audit policy removed (Not Configured).'
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

function Get-PathLocation([string]$Path) {
    $p = $Path.ToUpper()
    if ($p -match '\\APPDATA\\LOCAL\\TEMP\\|\\WINDOWS\\TEMP\\|\\TEMP\\') { return 'Temp' }
    if ($p -match '\\USERS\\[^\\]+\\(DOWNLOADS|DESKTOP|DOCUMENTS)\\') { return 'User folders (Downloads/Desktop/Docs)' }
    if ($p -match '\\USERS\\[^\\]+\\APPDATA\\') { return 'User AppData' }
    if ($p -match '\\USERS\\') { return 'Other user profile' }
    if ($p -match '\\PROGRAMDATA\\') { return 'ProgramData' }
    if ($p -match '^\\\\|^[A-Z]:\\' -and $p -notmatch '^%OSDRIVE%') { return 'Other drive / network' }
    return 'Other'
}

function Get-Category([string]$Path, [string]$Kind) {
    $ext = ''
    if ($Path -match '\.([A-Za-z0-9]+)$') { $ext = $Matches[1].ToLower() }
    if ($Kind -like 'Packaged*') { return 'Packaged app' }
    switch -Regex ($ext) {
        '^(exe|com)$'         { return 'EXE' }
        '^(dll|ocx)$'         { return 'DLL' }
        '^(msi|msp|mst)$'     { return 'MSI' }
        '^(ps1|bat|cmd|vbs|js)$' { return 'Script' }
    }
    return $Kind
}

function Get-AuditRows([datetime]$Since) {
    $defs = @(
        @{ Log = 'Microsoft-Windows-AppLocker/EXE and DLL';                 Id = 8003; Kind = 'EXE/DLL' },
        @{ Log = 'Microsoft-Windows-AppLocker/MSI and Script';              Id = 8006; Kind = 'MSI/Script' },
        @{ Log = 'Microsoft-Windows-AppLocker/Packaged app-Execution';      Id = 8021; Kind = 'Packaged app' },
        @{ Log = 'Microsoft-Windows-AppLocker/Packaged app-Deployment';     Id = 8024; Kind = 'Packaged app' }
    )
    $agg = @{}
    foreach ($d in $defs) {
        $f = @{ LogName = $d.Log; Id = $d.Id }
        if ($Since) { $f.StartTime = $Since }
        $events = @(Get-WinEvent -FilterHashtable $f -MaxEvents 50000 -ErrorAction SilentlyContinue)
        Write-Log "$($d.Log): $($events.Count) audit event(s)"
        foreach ($ev in $events) {
            $x = [xml]$ev.ToXml()
            $get = {
                param($names)
                foreach ($n in $names) {
                    $e = $x.GetElementsByTagName($n)
                    if ($e.Count -gt 0 -and $e[0].InnerText) { return $e[0].InnerText }
                }
                return ''
            }
            $path = & $get @('FilePathBuffer', 'FilePath', 'FullFilePath', 'PackageFullName')
            if (-not $path -and $ev.Message -match '^(.+?) was allowed to run') { $path = $Matches[1] }
            if (-not $path) { continue }
            $fqbn = & $get @('FqbnBuffer', 'Fqbn')
            $hash = & $get @('FileHash')
            $sid  = & $get @('TargetUser')

            $cat = Get-Category $path $d.Kind
            $key = "$cat|$($path.ToLower())"
            if (-not $agg.ContainsKey($key)) {
                $pub = ''; $prod = ''; $bin = ''; $ver = ''; $signed = $false
                if ($fqbn -and $fqbn -ne '-') {
                    $parts = $fqbn -split '\\'
                    $signed = $true
                    $pub = $parts[0]; if ($parts.Count -gt 1) { $prod = $parts[1] }; if ($parts.Count -gt 2) { $bin = $parts[2] }; if ($parts.Count -gt 3) { $ver = $parts[3] }
                }
                $agg[$key] = [pscustomobject]@{
                    Host = $env:COMPUTERNAME; Category = $cat; Location = (Get-PathLocation $path); Path = $path
                    Publisher = $pub; Product = $prod; Binary = $bin; Version = $ver; Signed = $signed
                    SHA256 = $hash; Count = 0; Users = (New-Object System.Collections.Generic.HashSet[string])
                    FirstSeen = $ev.TimeCreated; LastSeen = $ev.TimeCreated
                }
            }
            $row = $agg[$key]
            $row.Count++
            [void]$row.Users.Add((Resolve-Sid $sid))
            if ($ev.TimeCreated -lt $row.FirstSeen) { $row.FirstSeen = $ev.TimeCreated }
            if ($ev.TimeCreated -gt $row.LastSeen)  { $row.LastSeen  = $ev.TimeCreated }
        }
    }
    return @($agg.Values | ForEach-Object { $_.Users = (($_.Users | Sort-Object) -join '; '); $_ })
}

function New-SuggestedRules([string]$OutPath) {
    # AppLocker's own generator: turns the audited files into publisher/hash allow rules.
    $info = @()
    foreach ($log in 'Microsoft-Windows-AppLocker/EXE and DLL', 'Microsoft-Windows-AppLocker/MSI and Script') {
        $info += @(Get-AppLockerFileInformation -EventLog -LogPath $log -EventType Audited -ErrorAction SilentlyContinue)
    }
    if ($info.Count -eq 0) { return $false }
    $xml = $info | New-AppLockerPolicy -RuleType Publisher, Hash -User Everyone -Optimize -Xml
    Set-Content -LiteralPath $OutPath -Value $xml -Encoding UTF8
    return $true
}

function Get-PublisherName([string]$Pub) { if ($Pub -match 'O=([^,]+)') { return $Matches[1].Trim('"') } if ($Pub -match 'CN=([^,]+)') { return $Matches[1].Trim('"') } return $Pub }

function Collect-Audit {
    $since = $null
    if (Test-Path $StatePath) { try { $since = [datetime]((Get-Content $StatePath -Raw | ConvertFrom-Json).LastCollect) } catch { } }
    $started = Get-Date
    $rows = @(Get-AuditRows $since)
    Write-Log "$($rows.Count) unique would-be-blocked item(s) since $(if ($since) { $since } else { 'the beginning of the log' })"

    if ($rows.Count -eq 0) {
        if ($PostEmpty) { [void](Send-SlackMessage ":white_check_mark: *AppLocker audit on $($env:COMPUTERNAME):* nothing new would have been blocked.") }
        @{ LastCollect = $started.ToString('o') } | ConvertTo-Json | Set-Content -LiteralPath $StatePath -Encoding UTF8
        return
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmm'
    $csv = Join-Path $Root "audit-$($env:COMPUTERNAME)-$stamp.csv"
    $rows | Sort-Object Count -Descending |
        Select-Object Host, Category, Location, Path, Publisher, Product, Binary, Version, Signed, SHA256, Count, Users, FirstSeen, LastSeen |
        Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
    $files = @($csv)

    $rules = Join-Path $Root "suggested-rules-$($env:COMPUTERNAME)-$stamp.xml"
    try { if (New-SuggestedRules $rules) { $files += $rules } } catch { Write-Log "Suggested-rules step skipped: $($_.Exception.Message)" 'WARN' }

    # ---- Slack summary
    $users = @($rows | ForEach-Object { $_.Users -split '; ' } | Where-Object { $_ } | Sort-Object -Unique)
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add(":mag: *AppLocker AUDIT $($env:COMPUTERNAME):* $($rows.Count) unique items would have been blocked | users: $($users -join ', ')")
    $cat = ($rows | Group-Object Category | Sort-Object Count -Descending | ForEach-Object { "$($_.Name) $($_.Count)" }) -join ' | '
    $loc = ($rows | Group-Object Location | Sort-Object Count -Descending | ForEach-Object { "$($_.Name) $($_.Count)" }) -join ' | '
    [void]$lines.Add("*By type:* $cat")
    [void]$lines.Add("*By location:* $loc")
    $pubs = @($rows | Where-Object Signed | Group-Object { Get-PublisherName $_.Publisher } | Sort-Object Count -Descending | Select-Object -First 8)
    if ($pubs.Count) {
        [void]$lines.Add('*Signed - allow by PUBLISHER:*')
        foreach ($p in $pubs) { [void]$lines.Add("  - $($p.Name) ($($p.Count) files)") }
    }
    $uns = @($rows | Where-Object { -not $_.Signed } | Sort-Object Count -Descending | Select-Object -First 8)
    if ($uns.Count) {
        [void]$lines.Add('*Unsigned - needs a PATH or HASH rule, or removal:*')
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
    Get-ChildItem $Root -Include 'audit-*.csv', 'suggested-rules-*.xml' -Recurse -ErrorAction SilentlyContinue |
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
    if ($Mode -ne 'Remove') { [void](Send-SlackMessage ":x: *AppLocker audit $Mode FAILED on $($env:COMPUTERNAME):* $($_.Exception.Message)") }
}

if ($script:Failures -gt 0) { Write-Log "Completed with $($script:Failures) failure(s)" 'ERROR'; exit 1 }
Write-Log 'Completed OK'
exit 0
