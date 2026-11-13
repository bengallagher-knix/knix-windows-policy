<#
.SYNOPSIS
  Knix Windows policy baseline for RMM-managed (non-MDM) devices.

.DESCRIPTION
  Enforces a baseline using the same mechanism Group Policy uses: policy registry keys under
  HKLM\SOFTWARE\Policies (standard users cannot write HKLM, and Windows greys out the matching
  Settings toggles as "managed by your organization"), plus AppLocker for the browser block.

  Self-heals: Install mode copies this script to C:\ProgramData\Knix\Policy (admin-only write) and
  registers two scheduled tasks that re-apply the baseline, so drift is corrected even if RMM is offline.
    \Knix\Knix Policy - Machine   SYSTEM, at startup + hourly   (HKLM policy, app removal, AppLocker, Default User hive)
    \Knix\Knix Policy - User      Users group, at logon + hourly (taskbar prefs, unpin Store/Copilot, WhatsApp Win32)

  REQUIREMENTS: users must be standard users (not local admins). Windows 11, Windows PowerShell 5.1.

.PARAMETER Mode
  Install  (default, use this in RMM) Copy script, register tasks, apply machine baseline now.
  Machine  Apply machine-wide settings (run as SYSTEM/admin).
  User     Apply per-user settings for the signed-in user (run as that user).
  Remove   Remove tasks and revert every policy this script sets. Removed apps are NOT reinstalled.

.PARAMETER OneDrive
  Block | Allow. Persists to config.json and applies. Use "Allow" to re-enable OneDrive.
    .\Apply-KnixPolicy.ps1 -Mode Machine -OneDrive Allow

.NOTES
  Config: C:\ProgramData\Knix\Policy\config.json (lock timeout, app list, browser list, OneDrive switch).
  Logs:   C:\ProgramData\Knix\Policy\policy.log (machine)  |  %LOCALAPPDATA%\Knix\policy-user.log (user)
  Exit code 0 = all steps succeeded, 1 = one or more steps failed (see log).
#>
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Machine', 'User', 'Remove')][string]$Mode = 'Install',
    [ValidateSet('Block', 'Allow')][string]$OneDrive
)

$ErrorActionPreference = 'Stop'
$Root       = Join-Path $env:ProgramData 'Knix\Policy'
$ScriptPath = Join-Path $Root 'Apply-KnixPolicy.ps1'
$ConfigPath = Join-Path $Root 'config.json'
$StatePath  = Join-Path $Root 'applocker.state'
$TaskPath   = '\Knix\'
$script:Failures = 0
$script:Report = New-Object System.Collections.ArrayList   # one row per policy area, posted to Slack at the end

if ($Mode -eq 'User') {
    $LogDir = Join-Path $env:LOCALAPPDATA 'Knix'
    $LogFile = Join-Path $LogDir 'policy-user.log'
} else {
    $LogDir = $Root
    $LogFile = Join-Path $Root 'policy.log'
}

# ----------------------------------------------------------------------------- helpers
function Write-Log([string]$Msg, [string]$Level = 'INFO') {
    $line = '{0} [{1}] [{2}] {3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Mode, $Level, $Msg
    Write-Host $line
    try {
        if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
        if ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt 1MB) { Move-Item $LogFile "$LogFile.old" -Force }
        Add-Content -LiteralPath $LogFile -Value $line
    } catch { }
}

# Status: OK (already compliant), APPLIED (changed this run), FAILED
function Add-Result([string]$Area, [string]$Status, [string]$Detail = '') {
    [void]$script:Report.Add([pscustomobject]@{ Area = $Area; Status = $Status; Detail = $Detail })
}

function Invoke-Step([string]$Name, [scriptblock]$Body) {
    try { & $Body }
    catch {
        $script:Failures++
        Write-Log "$Name FAILED: $($_.Exception.Message)" 'ERROR'
        Add-Result $Name 'FAILED' $_.Exception.Message
    }
}

function Test-IsAdmin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Set-RegValue([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord') {
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
    $cur = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    if ($null -ne $cur -and $cur -eq $Value) { return $false }
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    Write-Log "SET $Path\$Name = $Value"
    return $true
}

function Remove-RegValue([string]$Path, [string]$Name) {
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    if ($null -eq (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue)) { return $false }
    Remove-ItemProperty -LiteralPath $Path -Name $Name -Force
    Write-Log "REMOVED $Path\$Name"
    return $true
}

# ----------------------------------------------------------------------------- config
function Get-DefaultConfig {
    [ordered]@{
        # Set true (or run with -OneDrive Allow) to re-enable OneDrive. Nothing is uninstalled, so this is instant.
        AllowOneDrive          = $false
        # Screen lock after inactivity. 300 = 5 minutes.
        LockTimeoutSeconds     = 300
        # AppX package names (wildcards allowed). Removed for all users + deprovisioned.
        RemoveApps             = @(
            'Microsoft.XboxApp', 'Microsoft.GamingApp', 'Microsoft.XboxGamingOverlay', 'Microsoft.XboxGameOverlay',
            'Microsoft.XboxIdentityProvider', 'Microsoft.XboxSpeechToTextOverlay', 'Microsoft.Xbox.TCUI',
            '5319275A.WhatsAppDesktop'
        )
        # Taskbar items to unpin at each user logon (display names, wildcards allowed).
        UnpinFromTaskbar       = @('Microsoft Store', 'Copilot')
        # Original executable names blocked by AppLocker. Chrome and Edge are never blocked.
        BlockedBrowserBinaries = @(
            'firefox.exe', 'brave.exe', 'opera.exe', 'vivaldi.exe', 'iexplore.exe', 'chromium.exe',
            'waterfox.exe', 'librewolf.exe', 'palemoon.exe', 'seamonkey.exe', 'maxthon.exe', 'arc.exe',
            'duckduckgo.exe', 'comet.exe', 'avastbrowser.exe', 'torch.exe', 'ucbrowser.exe'
        )
    }
}

function Import-Config {
    $cfg = Get-DefaultConfig
    if (Test-Path $ConfigPath) {
        $j = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
        foreach ($k in @($cfg.Keys)) {
            if ($j.PSObject.Properties.Name -contains $k) { $cfg[$k] = $j.$k }
        }
    }
    $script:Cfg = $cfg
}

function Save-Config {
    if (-not (Test-Path $Root)) { New-Item -ItemType Directory -Path $Root -Force | Out-Null }
    $script:Cfg | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $ConfigPath -Encoding UTF8
}

# ----------------------------------------------------------------------------- machine policy table
function Get-MachinePolicies {
    $od  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
    $od2 = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'
    # A = area name shown in the Slack report
    @(
        # 1. Fast Startup off (policy + live setting)
        @{ G = 'Base'; A = 'Fast Startup disabled'; P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; N = 'HiberbootEnabled'; V = 0 }
        @{ G = 'Base'; A = 'Fast Startup disabled'; P = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'; N = 'HiberbootEnabled'; V = 0 }
        # 2. Lock after inactivity (Security Policy: "Interactive logon: Machine inactivity limit")
        @{ G = 'Base'; A = "Screen lock after $([int]$script:Cfg.LockTimeoutSeconds / 60) min"; P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; N = 'InactivityTimeoutSecs'; V = [int]$script:Cfg.LockTimeoutSeconds }
        # 3. Taskbar search hidden, Widgets off, Copilot button off
        @{ G = 'Base'; A = 'Taskbar search hidden'; P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; N = 'SearchOnTaskbarMode'; V = 0 }
        @{ G = 'Base'; A = 'Widgets disabled'; P = 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh'; N = 'AllowNewsAndInterests'; V = 0 }
        @{ G = 'Base'; A = 'Copilot button disabled'; P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'; N = 'TurnOffWindowsCopilot'; V = 1 }
        # 5. Game Bar off (stops the "get an app for ms-gamingoverlay" popup once Xbox apps are removed)
        @{ G = 'Base'; A = 'Game Bar disabled'; P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'; N = 'AllowGameDVR'; V = 0 }
        # 4. OneDrive off. Group 'OneDrive' is removed (not set) when AllowOneDrive = true.
        @{ G = 'OneDrive'; A = 'OneDrive'; P = $od;  N = 'DisableFileSyncNGSC'; V = 1 }
        @{ G = 'OneDrive'; A = 'OneDrive'; P = $od;  N = 'DisableFileSync'; V = 1 }
        @{ G = 'OneDrive'; A = 'OneDrive'; P = $od;  N = 'DisableLibrariesDefaultSaveToOneDrive'; V = 1 }
        @{ G = 'OneDrive'; A = 'OneDrive'; P = $od;  N = 'PreventNetworkTrafficPreUserSignIn'; V = 1 }
        @{ G = 'OneDrive'; A = 'OneDrive'; P = $od2; N = 'KFMBlockOptIn'; V = 1 }
        @{ G = 'OneDrive'; A = 'OneDrive'; P = $od2; N = 'DisablePersonalSync'; V = 1 }
    )
}

# Policy-backed values removed on Remove (live settings such as the Power key are left alone).
$script:RevertSkip = @('HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power')

function Set-MachinePolicies {
    $changed = 0
    $perArea = [ordered]@{}
    foreach ($e in (Get-MachinePolicies)) {
        if (-not $perArea.Contains($e.A)) { $perArea[$e.A] = 0 }
        $didChange = $false
        try {
            if ($e.G -eq 'OneDrive' -and $script:Cfg.AllowOneDrive) { $didChange = Remove-RegValue $e.P $e.N }
            else { $didChange = Set-RegValue $e.P $e.N $e.V }
        } catch {
            $script:Failures++
            Write-Log "Policy $($e.A) ($($e.N)) FAILED: $($_.Exception.Message)" 'ERROR'
            Add-Result $e.A 'FAILED' $_.Exception.Message
            $perArea[$e.A] = -1000
            continue
        }
        if ($didChange) { $changed++; $perArea[$e.A]++ }
    }
    foreach ($a in $perArea.Keys) {
        if ($perArea[$a] -lt 0) { continue }   # failure already recorded
        $detail = ''
        if ($a -eq 'OneDrive') { $detail = if ($script:Cfg.AllowOneDrive) { 'ALLOWED (block policies removed)' } else { 'blocked (sync, auto-save, KFM, personal accounts)' } }
        Add-Result $a $(if ($perArea[$a] -gt 0) { 'APPLIED' } else { 'OK' }) $detail
    }
    Write-Log "Machine policy: $changed value(s) corrected" $(if ($changed) { 'DRIFT' } else { 'INFO' })
    if ($changed -and -not $script:Cfg.AllowOneDrive) {
        Get-Process -Name OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

function Undo-MachinePolicies {
    foreach ($e in (Get-MachinePolicies)) {
        if ($script:RevertSkip -contains $e.P) { continue }
        [void](Remove-RegValue $e.P $e.N)
    }
}

# ----------------------------------------------------------------------------- per-user settings
function Get-UserSettings {
    $adv = 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    @(
        @{ S = $adv; N = 'TaskbarAl'; V = 0 }                 # Start button on the left
        @{ S = $adv; N = 'ShowTaskViewButton'; V = 0 }        # Task View button off
        @{ S = $adv; N = 'ShowCopilotButton'; V = 0 }         # Copilot button off
        @{ S = 'Software\Microsoft\Windows\CurrentVersion\Search'; N = 'SearchboxTaskbarMode'; V = 0 }  # Search hidden
    )
}

function Set-UserSettings([string]$Hive) {
    $changed = $false
    foreach ($s in (Get-UserSettings)) {
        try {
            if (Set-RegValue "$Hive\$($s.S)" $s.N $s.V) { $changed = $true }
        } catch { Write-Log "Could not set $($s.N): $($_.Exception.Message)" 'WARN' }
    }
    return $changed
}

# Seed the Default User profile so new accounts start compliant.
function Set-DefaultUserHive {
    $ntuser = Join-Path $env:SystemDrive 'Users\Default\NTUSER.DAT'
    if (-not (Test-Path $ntuser)) { Write-Log 'Default User hive not found, skipped' 'WARN'; return }
    & reg.exe load 'HKU\KnixDefault' $ntuser *> $null
    if ($LASTEXITCODE -ne 0) { Write-Log 'Could not load Default User hive, skipped' 'WARN'; return }
    try {
        $chg = Set-UserSettings 'Registry::HKEY_USERS\KnixDefault'
        # Per-user prefs on existing profiles are applied by the logon task, so SYSTEM can only report the template.
        Add-Result 'Taskbar: Start left, no Task View/Search (new profiles)' $(if ($chg) { 'APPLIED' } else { 'OK' }) 'existing users enforced at logon'
    }
    finally {
        [gc]::Collect(); [gc]::WaitForPendingFinalizers()
        for ($i = 0; $i -lt 5; $i++) {
            & reg.exe unload 'HKU\KnixDefault' *> $null
            if ($LASTEXITCODE -eq 0) { break }
            Start-Sleep -Milliseconds 500
        }
    }
}

# ----------------------------------------------------------------------------- apps
function Remove-UnwantedApps {
    $provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue)
    $removed = New-Object System.Collections.ArrayList
    $errors  = New-Object System.Collections.ArrayList
    foreach ($pattern in @($script:Cfg.RemoveApps)) {
        foreach ($pkg in @(Get-AppxPackage -AllUsers -Name $pattern -ErrorAction SilentlyContinue)) {
            Write-Log "Removing app $($pkg.PackageFullName)" 'DRIFT'
            try { Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop; [void]$removed.Add($pkg.Name) }
            catch { $script:Failures++; [void]$errors.Add($pkg.Name); Write-Log "Remove failed for $($pkg.Name): $($_.Exception.Message)" 'ERROR' }
        }
        foreach ($prov in ($provisioned | Where-Object { $_.DisplayName -like $pattern })) {
            Write-Log "Deprovisioning $($prov.DisplayName)" 'DRIFT'
            try { Remove-AppxProvisionedPackage -Online -PackageName $prov.PackageName -ErrorAction Stop | Out-Null; [void]$removed.Add($prov.DisplayName) }
            catch { $script:Failures++; [void]$errors.Add($prov.DisplayName); Write-Log "Deprovision failed for $($prov.DisplayName): $($_.Exception.Message)" 'ERROR' }
        }
    }
    if ($errors.Count -gt 0) { Add-Result 'Xbox / WhatsApp removal' 'FAILED' ("could not remove: " + (($errors | Sort-Object -Unique) -join ', ')) }
    elseif ($removed.Count -gt 0) { Add-Result 'Xbox / WhatsApp removal' 'APPLIED' ("removed: " + (($removed | Sort-Object -Unique) -join ', ')) }
    else { Add-Result 'Xbox / WhatsApp removal' 'OK' 'not installed' }
}

# ----------------------------------------------------------------------------- AppLocker browser block
function New-StableGuid([string]$Seed) {
    $md5 = [Security.Cryptography.MD5]::Create()
    ([guid]::new($md5.ComputeHash([Text.Encoding]::UTF8.GetBytes($Seed)))).ToString()
}

function Get-ForeignAppLockerRuleCount {
    $count = 0
    $pol = Get-AppLockerPolicy -Local -ErrorAction SilentlyContinue
    if ($pol) {
        foreach ($c in $pol.RuleCollections) { foreach ($r in $c) { if ($r.Name -notlike 'KNIX-*') { $count++ } } }
    }
    return $count
}

function Build-BrowserBlockXml {
    $keep = @('chrome.exe', 'msedge.exe')
    $bins = @($script:Cfg.BlockedBrowserBinaries | Where-Object { $_ -and ($keep -notcontains $_.ToLower()) } | Sort-Object -Unique)
    $sb = New-Object Text.StringBuilder
    [void]$sb.AppendLine('<AppLockerPolicy Version="1">')
    [void]$sb.AppendLine('  <RuleCollection Type="Exe" EnforcementMode="Enabled">')
    $id = New-StableGuid 'KNIX-Allow-all'
    [void]$sb.AppendLine("    <FilePathRule Id=`"$id`" Name=`"KNIX-Allow-all`" Description=`"Allow everything; browser deny rules below take precedence`" UserOrGroupSid=`"S-1-1-0`" Action=`"Allow`"><Conditions><FilePathCondition Path=`"*`" /></Conditions></FilePathRule>")
    foreach ($b in $bins) {
        $idPub  = New-StableGuid "KNIX-Deny-$b-signed"
        $idPath = New-StableGuid "KNIX-Deny-$b-path"
        # Signed binary matched on its embedded original file name, so renamed copies are still caught.
        [void]$sb.AppendLine("    <FilePublisherRule Id=`"$idPub`" Name=`"KNIX-Deny-$b-signed`" Description=`"Blocked browser`" UserOrGroupSid=`"S-1-1-0`" Action=`"Deny`"><Conditions><FilePublisherCondition PublisherName=`"*`" ProductName=`"*`" BinaryName=`"$b`"><BinaryVersionRange LowSection=`"*`" HighSection=`"*`" /></FilePublisherCondition></Conditions></FilePublisherRule>")
        # Path rule as a second layer (unsigned or oddly signed copies).
        [void]$sb.AppendLine("    <FilePathRule Id=`"$idPath`" Name=`"KNIX-Deny-$b-path`" Description=`"Blocked browser`" UserOrGroupSid=`"S-1-1-0`" Action=`"Deny`"><Conditions><FilePathCondition Path=`"*\$b`" /></Conditions></FilePathRule>")
    }
    [void]$sb.AppendLine('  </RuleCollection>')
    [void]$sb.AppendLine('</AppLockerPolicy>')
    return $sb.ToString()
}

function Enable-AppIdService {
    try { Set-Service -Name AppIDSvc -StartupType Automatic -ErrorAction Stop }
    catch { & sc.exe config appidsvc start= auto | Out-Null }
    $svc = Get-Service -Name AppIDSvc
    if ($svc.Status -ne 'Running') { Start-Service -Name AppIDSvc -ErrorAction Stop; Write-Log 'Started Application Identity service' 'DRIFT' }
}

function Set-BrowserBlock {
    if ((Get-ForeignAppLockerRuleCount) -gt 0) {
        $script:Failures++
        Write-Log 'Existing non-Knix AppLocker rules found. Browser block NOT applied (would overwrite them). Merge manually.' 'ERROR'
        Add-Result 'Browser block' 'FAILED' 'existing non-Knix AppLocker rules, not overwritten'
        return
    }
    $xml = Build-BrowserBlockXml
    $hash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($xml)))
    $expected = ([regex]::Matches($xml, 'Name="KNIX-')).Count
    $pol = Get-AppLockerPolicy -Local -ErrorAction SilentlyContinue
    $have = 0
    if ($pol) { foreach ($c in $pol.RuleCollections) { foreach ($r in $c) { $have++ } } }
    $stored = if (Test-Path $StatePath) { (Get-Content $StatePath -Raw).Trim() } else { '' }
    $applied = $false
    if ($stored -ne $hash -or $have -ne $expected) {
        $tmp = Join-Path $env:TEMP 'knix-applocker.xml'
        Set-Content -LiteralPath $tmp -Value $xml -Encoding UTF8
        try { Set-AppLockerPolicy -XmlPolicy $tmp } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
        Set-Content -LiteralPath $StatePath -Value $hash
        Write-Log "AppLocker browser block applied ($expected rules)" 'DRIFT'
        $applied = $true
    }
    Enable-AppIdService
    $n = [int](($expected - 1) / 2)
    Add-Result 'Browser block (only Chrome + Edge)' $(if ($applied) { 'APPLIED' } else { 'OK' }) "$n browsers denied via AppLocker"
}

function Remove-BrowserBlock {
    if ((Get-ForeignAppLockerRuleCount) -gt 0) { Write-Log 'Foreign AppLocker rules present, left untouched' 'WARN'; return }
    $tmp = Join-Path $env:TEMP 'knix-applocker-empty.xml'
    Set-Content -LiteralPath $tmp -Value '<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="NotConfigured" /></AppLockerPolicy>' -Encoding UTF8
    try { Set-AppLockerPolicy -XmlPolicy $tmp } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    Remove-Item $StatePath -Force -ErrorAction SilentlyContinue
    Write-Log 'AppLocker browser block removed'
}

# ----------------------------------------------------------------------------- install / tasks
function Install-Self {
    if (-not (Test-Path $Root)) { New-Item -ItemType Directory -Path $Root -Force | Out-Null }
    if (-not $PSCommandPath) { throw 'Run this as a .ps1 file (not pasted inline) so it can copy itself.' }
    if ((Resolve-Path $PSCommandPath).Path -ne $ScriptPath) { Copy-Item -LiteralPath $PSCommandPath -Destination $ScriptPath -Force }
    if (-not (Test-Path $ConfigPath)) { Save-Config }
    # Admin/SYSTEM full control, Users read+execute only, so users cannot edit the script or config.
    & icacls.exe $Root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
}

function Register-PolicyTasks {
    $ps = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $argBase = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`""
    $hourly = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Hours 1)
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

    # Machine task: SYSTEM
    Register-ScheduledTask -TaskName 'Knix Policy - Machine' -TaskPath $TaskPath -Force `
        -Action (New-ScheduledTaskAction -Execute $ps -Argument "$argBase -Mode Machine") `
        -Trigger @((New-ScheduledTaskTrigger -AtStartup), $hourly) `
        -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) `
        -Settings $settings | Out-Null

    # User task: runs as whichever standard user signs in (no elevation)
    $logon = New-ScheduledTaskTrigger -AtLogOn
    try { $logon.Repetition = $hourly.Repetition } catch { Write-Log 'Could not add hourly repetition to logon trigger' 'WARN' }
    Register-ScheduledTask -TaskName 'Knix Policy - User' -TaskPath $TaskPath -Force `
        -Action (New-ScheduledTaskAction -Execute $ps -Argument "$argBase -Mode User") `
        -Trigger $logon `
        -Principal (New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited) `
        -Settings $settings | Out-Null
    Write-Log 'Scheduled tasks registered'
}

# ----------------------------------------------------------------------------- user-mode actions
function Remove-TaskbarPins {
    $apps = (New-Object -ComObject Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}')
    $unpinned = $false
    foreach ($item in $apps.Items()) {
        foreach ($pat in @($script:Cfg.UnpinFromTaskbar)) {
            if ($item.Name -like $pat) {
                $verb = $item.Verbs() | Where-Object { $_.Name.Replace('&', '') -match 'Unpin from taskbar' } | Select-Object -First 1
                if ($verb) { $verb.DoIt(); $unpinned = $true; Write-Log "Unpinned '$($item.Name)' from taskbar" 'DRIFT' }
            }
        }
    }
    return $unpinned
}

function Remove-WhatsAppWin32 {
    # Non-Store (Squirrel) WhatsApp installs per user under %LOCALAPPDATA%\WhatsApp
    $upd = Join-Path $env:LOCALAPPDATA 'WhatsApp\Update.exe'
    if (Test-Path $upd) {
        Get-Process -Name WhatsApp -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Log 'Uninstalling WhatsApp (Win32)' 'DRIFT'
        Start-Process -FilePath $upd -ArgumentList '--uninstall', '-s' -Wait
    }
}

# ----------------------------------------------------------------------------- reporting (Slack)
# The Slack token and channel are NOT stored in this repo. The Atera bootstrap (which holds the secrets)
# passes them in as environment variables KNIX_SLACK_TOKEN / KNIX_SLACK_CHANNEL for that single run.
# Scheduled self-heal runs have no token, so they stay silent.
function Save-Report {
    $obj = [ordered]@{
        Computer = $env:COMPUTERNAME
        Time     = (Get-Date).ToString('s')
        Failures = $script:Failures
        Results  = @($script:Report)
    }
    $obj | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $Root 'last-run.json') -Encoding UTF8
}

function Send-SlackReport {
    $token   = "$($env:KNIX_SLACK_TOKEN)".Trim()
    $channel = "$($env:KNIX_SLACK_CHANNEL)".Trim()
    if (-not $token -or -not $channel) { Write-Log 'No Slack token/channel in environment, report not posted'; return }

    $icon = @{ OK = ':white_check_mark:'; APPLIED = ':hammer_and_wrench:'; FAILED = ':x:' }
    $applied = @($script:Report | Where-Object Status -eq 'APPLIED').Count
    $failed  = @($script:Report | Where-Object Status -eq 'FAILED').Count
    $head = if ($failed) { ":warning: *Windows policy run on $($env:COMPUTERNAME): $failed FAILED*" }
            elseif ($applied) { ":lock: *Windows policy applied on $($env:COMPUTERNAME)* ($applied changed)" }
            else { ":white_check_mark: *Windows policy check on $($env:COMPUTERNAME): already compliant*" }

    $os = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue)
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add($head)
    foreach ($r in $script:Report) {
        $d = if ($r.Detail) { " _($($r.Detail))_" } else { '' }
        [void]$lines.Add("$($icon[$r.Status]) $($r.Area)$d")
    }
    if ($os) { [void]$lines.Add("_$($os.Caption) build $($os.BuildNumber) | $(Get-Date -Format 'yyyy-MM-dd HH:mm')_") }

    $body  = @{ channel = $channel; text = ($lines -join "`n"); unfurl_links = $false } | ConvertTo-Json -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($body)
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $resp = Invoke-RestMethod -Uri 'https://slack.com/api/chat.postMessage' -Method Post -Headers @{ Authorization = "Bearer $token" } `
                 -ContentType 'application/json; charset=utf-8' -Body $bytes -UseBasicParsing -TimeoutSec 20
        if ($resp.ok) { Write-Log 'Slack report posted' } else { Write-Log "Slack refused the report: $($resp.error)" 'WARN' }
    } catch { Write-Log "Slack post failed: $($_.Exception.Message)" 'WARN' }   # never log the token
}

# ============================================================================= main
Import-Config
if ($PSBoundParameters.ContainsKey('OneDrive')) {
    $script:Cfg.AllowOneDrive = ($OneDrive -eq 'Allow')
    if ($Mode -ne 'User') { Save-Config; Write-Log "OneDrive set to $OneDrive" }
}

switch ($Mode) {
    'Install' {
        if (-not (Test-IsAdmin)) { Write-Log 'Must run elevated/SYSTEM' 'ERROR'; exit 1 }
        Invoke-Step 'Install files'    { Install-Self }
        Invoke-Step 'Register tasks'   { Register-PolicyTasks }
        Invoke-Step 'Machine policy'   { Set-MachinePolicies }
        Invoke-Step 'Default profile'  { Set-DefaultUserHive }
        Invoke-Step 'Remove apps'      { Remove-UnwantedApps }
        Invoke-Step 'Browser block'    { Set-BrowserBlock }
        Invoke-Step 'Run user task'    { Start-ScheduledTask -TaskPath $TaskPath -TaskName 'Knix Policy - User' }
    }
    'Machine' {
        if (-not (Test-IsAdmin)) { Write-Log 'Must run elevated/SYSTEM' 'ERROR'; exit 1 }
        Invoke-Step 'Machine policy'   { Set-MachinePolicies }
        Invoke-Step 'Default profile'  { Set-DefaultUserHive }
        Invoke-Step 'Remove apps'      { Remove-UnwantedApps }
        Invoke-Step 'Browser block'    { Set-BrowserBlock }
    }
    'User' {
        $script:restartExplorer = $false
        Invoke-Step 'User settings' { if (Set-UserSettings 'HKCU:') { $script:restartExplorer = $true } }
        Invoke-Step 'Unpin apps'    { if (Remove-TaskbarPins) { $script:restartExplorer = $true } }
        Invoke-Step 'WhatsApp'      { Remove-WhatsAppWin32 }
        if (-not $script:Cfg.AllowOneDrive) {
            Get-Process -Name OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        }
        # Taskbar prefs are read at shell start; restart Explorer once, only when something changed.
        if ($script:restartExplorer) { Write-Log 'Restarting Explorer to apply taskbar changes'; Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue }
    }
    'Remove' {
        if (-not (Test-IsAdmin)) { Write-Log 'Must run elevated/SYSTEM' 'ERROR'; exit 1 }
        Invoke-Step 'Remove tasks'   { foreach ($t in 'Knix Policy - Machine', 'Knix Policy - User') { Unregister-ScheduledTask -TaskName $t -TaskPath $TaskPath -Confirm:$false -ErrorAction SilentlyContinue } }
        Invoke-Step 'Revert policy'  { Undo-MachinePolicies }
        Invoke-Step 'Revert AppLocker' { Remove-BrowserBlock }
        Write-Log 'Reverted. Per-user taskbar prefs and removed apps are not restored.'
    }
}

if ($Mode -in @('Install', 'Machine')) {
    try { Save-Report } catch { Write-Log "Could not save report: $($_.Exception.Message)" 'WARN' }
    if ($Mode -eq 'Install') { Send-SlackReport }
}

if ($script:Failures -gt 0) { Write-Log "Completed with $($script:Failures) failure(s)" 'ERROR'; exit 1 }
Write-Log 'Completed OK'
exit 0
