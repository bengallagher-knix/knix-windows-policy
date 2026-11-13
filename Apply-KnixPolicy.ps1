<#
.SYNOPSIS
  Knix Windows policy baseline for RMM-managed (non-MDM) devices.

.DESCRIPTION
  Enforces a baseline using the same mechanism Group Policy uses: policy registry keys under
  HKLM\SOFTWARE\Policies (standard users cannot write HKLM, and Windows greys out the matching
  Settings toggles as "managed by your organization"). AppLocker is NOT handled here.

  Self-heals: Install mode copies this script to C:\ProgramData\Knix\Policy (admin-only write) and
  registers two scheduled tasks that re-apply the baseline, so drift is corrected even if RMM is offline.
    \Knix\Knix Policy - Machine   SYSTEM, at startup + hourly   (HKLM policy, app removal, Default User hive)
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

.PARAMETER TargetVersion
  e.g. 25H2. Pins the Windows 11 feature update version (devices stay on it and keep getting its security patches).
  None clears the pin. CAUTION: a pinned version that reaches end of servicing stops receiving security patches,
  so raise the pin before then. Not pinned by default.
    .\Apply-KnixPolicy.ps1 -Mode Machine -TargetVersion 25H2

.PARAMETER UsbWriteBlock
  Enable | Disable. OFF by default. Enable blocks writing to USB/removable disks (reading still works).

.PARAMETER PowerShellLogging
  Enable | Disable. OFF by default. Script-block logging writes script text to the local event log, which would
  capture any secret pasted into an RMM script (e.g. the Slack token). Enable only if no scripts carry secrets.

.NOTES
  Also enforced (see Get-MachinePolicies and the account functions): password length + lockout, Guest and
  built-in Administrator disabled, firewall, Windows Update deadlines, SMBv1/LLMNR off, RDP NLA,
  AutoRun off, UAC, and audit/log settings. Remove mode does NOT undo account policy or disabled accounts.
  Microsoft Defender is deliberately not managed. BitLocker is only CHECKED and reported, never changed.
  Config: C:\ProgramData\Knix\Policy\config.json (lock timeout, app list, taskbar unpin list, OneDrive switch, options above).
  Logs:   C:\ProgramData\Knix\Policy\policy.log (machine)  |  %LOCALAPPDATA%\Knix\policy-user.log (user)
  Exit code 0 = all steps succeeded, 1 = one or more steps failed (see log).
#>
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Machine', 'User', 'Remove')][string]$Mode = 'Install',
    [ValidateSet('Block', 'Allow')][string]$OneDrive,
    [ValidatePattern('^(\d{2}H[12]|None)$')][string]$TargetVersion,
    [ValidateSet('Enable', 'Disable')][string]$UsbWriteBlock,
    [ValidateSet('Enable', 'Disable')][string]$PowerShellLogging
)

$ErrorActionPreference = 'Stop'
$Root       = Join-Path $env:ProgramData 'Knix\Policy'
$ScriptPath = Join-Path $Root 'Apply-KnixPolicy.ps1'
$ConfigPath = Join-Path $Root 'config.json'
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
        # Windows Update install deadlines (days after an update is offered before it is forced).
        QualityUpdateDeadlineDays = 7
        FeatureUpdateDeadlineDays = 14
        UpdateGracePeriodDays     = 2
        # Feature update pin, e.g. '25H2'. '' = not pinned. Set with -TargetVersion.
        TargetFeatureVersion      = ''
        # The Slack report flags the device if its newest installed quality update is older than this.
        PatchMaxAgeDays           = 45
        # Disable the built-in Administrator, but only if another enabled admin exists.
        DisableBuiltinAdmin    = $true
        # Opt-in options (off by default). Set with -UsbWriteBlock / -PowerShellLogging Enable.
        BlockUsbWrite          = $false
        PowerShellScriptBlockLogging = $false
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
    $fw  = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall'
    $wu  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    # G = group (Base always enforced; OneDrive/Usb/PsLog are switchable), A = area name shown in the Slack report,
    # K = keep on Remove
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

        # --- Security baseline -------------------------------------------------------------------
        # Windows Firewall on for every profile, inbound blocked by default (same keys the Firewall GPO writes)
        @{ G = 'Base'; A = 'Firewall on, inbound blocked (all profiles)'; P = "$fw\DomainProfile";   N = 'EnableFirewall'; V = 1 }
        @{ G = 'Base'; A = 'Firewall on, inbound blocked (all profiles)'; P = "$fw\DomainProfile";   N = 'DefaultInboundAction'; V = 1 }
        @{ G = 'Base'; A = 'Firewall on, inbound blocked (all profiles)'; P = "$fw\PrivateProfile";  N = 'EnableFirewall'; V = 1 }
        @{ G = 'Base'; A = 'Firewall on, inbound blocked (all profiles)'; P = "$fw\PrivateProfile";  N = 'DefaultInboundAction'; V = 1 }
        @{ G = 'Base'; A = 'Firewall on, inbound blocked (all profiles)'; P = "$fw\PublicProfile";   N = 'EnableFirewall'; V = 1 }
        @{ G = 'Base'; A = 'Firewall on, inbound blocked (all profiles)'; P = "$fw\PublicProfile";   N = 'DefaultInboundAction'; V = 1 }
        # Windows Update: install automatically, forced deadlines, users cannot pause
        @{ G = 'Base'; A = 'Windows Update: auto-install, deadlines, no pause'; P = "$wu\AU"; N = 'NoAutoUpdate'; V = 0 }
        @{ G = 'Base'; A = 'Windows Update: auto-install, deadlines, no pause'; P = "$wu\AU"; N = 'AUOptions'; V = 4 }
        @{ G = 'Base'; A = 'Windows Update: auto-install, deadlines, no pause'; P = $wu; N = 'ConfigureDeadlineForQualityUpdates'; V = [int]$script:Cfg.QualityUpdateDeadlineDays }
        @{ G = 'Base'; A = 'Windows Update: auto-install, deadlines, no pause'; P = $wu; N = 'ConfigureDeadlineForFeatureUpdates'; V = [int]$script:Cfg.FeatureUpdateDeadlineDays }
        @{ G = 'Base'; A = 'Windows Update: auto-install, deadlines, no pause'; P = $wu; N = 'ConfigureDeadlineGracePeriod'; V = [int]$script:Cfg.UpdateGracePeriodDays }
        @{ G = 'Base'; A = 'Windows Update: auto-install, deadlines, no pause'; P = $wu; N = 'SetDisablePauseUXAccess'; V = 1 }
        # Feature update pin (-TargetVersion). Y = registry value type. Group 'Pin' is removed when no version is set.
        @{ G = 'Pin'; A = 'Feature update pinned'; P = $wu; N = 'TargetReleaseVersion'; V = 1 }
        @{ G = 'Pin'; A = 'Feature update pinned'; P = $wu; N = 'ProductVersion'; V = 'Windows 11'; Y = 'String' }
        @{ G = 'Pin'; A = 'Feature update pinned'; P = $wu; N = 'TargetReleaseVersionInfo'; V = [string]$script:Cfg.TargetFeatureVersion; Y = 'String' }
        # Legacy / risky protocols
        @{ G = 'Base'; A = 'SMBv1 server disabled'; P = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; N = 'SMB1'; V = 0 }
        @{ G = 'Base'; A = 'LLMNR disabled'; P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; N = 'EnableMulticast'; V = 0 }
        @{ G = 'Base'; A = 'RDP requires NLA'; P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; N = 'UserAuthentication'; V = 1 }
        # AutoRun / AutoPlay off
        @{ G = 'Base'; A = 'AutoRun / AutoPlay disabled'; P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; N = 'NoDriveTypeAutoRun'; V = 255 }
        @{ G = 'Base'; A = 'AutoRun / AutoPlay disabled'; P = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; N = 'NoAutorun'; V = 1 }
        @{ G = 'Base'; A = 'AutoRun / AutoPlay disabled'; P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; N = 'NoAutoplayfornonVolume'; V = 1 }
        # Optional: block writes to USB / removable disks (-UsbWriteBlock Enable)
        @{ G = 'Usb'; A = 'USB storage write blocked'; P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}'; N = 'Deny_Write'; V = 1 }
        # UAC: admin actions need consent on the secure desktop. K = keep on Remove (never turn UAC off).
        @{ G = 'Base'; A = 'UAC: secure-desktop consent'; P = $sys; N = 'EnableLUA'; V = 1; K = $true }
        @{ G = 'Base'; A = 'UAC: secure-desktop consent'; P = $sys; N = 'ConsentPromptBehaviorAdmin'; V = 2 }
        @{ G = 'Base'; A = 'UAC: secure-desktop consent'; P = $sys; N = 'PromptOnSecureDesktop'; V = 1 }
        # Logging: 200 MB Security log (value is KB) and command lines in process-creation events
        @{ G = 'Base'; A = 'Security log 200 MB'; P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'; N = 'MaxSize'; V = 204800 }
        @{ G = 'Base'; A = 'Process command-line auditing'; P = "$sys\Audit"; N = 'ProcessCreationIncludeCmdLine_Enabled'; V = 1 }
        # Optional: PowerShell script-block logging (-PowerShellLogging Enable). Off by default: it records script text.
        @{ G = 'PsLog'; A = 'PowerShell script-block logging'; P = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; N = 'EnableScriptBlockLogging'; V = 1 }
    )
}

# Policy-backed values removed on Remove (live settings such as the Power key are left alone).
$script:RevertSkip = @('HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power')

function Set-MachinePolicies {
    $changed = 0
    $perArea = [ordered]@{}
    $areaOff = @{}
    # A switchable group is "off" when its policy values should be absent.
    $groupOff = @{
        OneDrive = [bool]$script:Cfg.AllowOneDrive
        Pin      = [string]::IsNullOrEmpty([string]$script:Cfg.TargetFeatureVersion)
        Usb      = -not [bool]$script:Cfg.BlockUsbWrite
        PsLog    = -not [bool]$script:Cfg.PowerShellScriptBlockLogging
    }
    foreach ($e in (Get-MachinePolicies)) {
        if (-not $perArea.Contains($e.A)) { $perArea[$e.A] = 0 }
        $isOff = $groupOff.ContainsKey($e.G) -and $groupOff[$e.G]
        $areaOff[$e.A] = $isOff
        $didChange = $false
        try {
            if ($isOff) { $didChange = Remove-RegValue $e.P $e.N }
            else { $didChange = Set-RegValue $e.P $e.N $e.V $(if ($e.Y) { $e.Y } else { 'DWord' }) }
        } catch {
            $script:Failures++
            Write-Log "Policy $($e.A) ($($e.N)) FAILED: $($_.Exception.Message)" 'ERROR'
            if ($perArea[$e.A] -ne -1000) { Add-Result $e.A 'FAILED' $_.Exception.Message }
            $perArea[$e.A] = -1000
            continue
        }
        if ($didChange) { $changed++; $perArea[$e.A]++ }
    }
    foreach ($a in $perArea.Keys) {
        if ($perArea[$a] -lt 0) { continue }   # failure already recorded
        $detail = ''
        if ($a -eq 'OneDrive') { $detail = if ($script:Cfg.AllowOneDrive) { 'ALLOWED (block policies removed)' } else { 'blocked (sync, auto-save, KFM, personal accounts)' } }
        elseif ($a -eq 'Feature update pinned' -and -not $areaOff[$a]) { $detail = "pinned to $($script:Cfg.TargetFeatureVersion)" }
        elseif ($areaOff[$a]) { $detail = 'off (opt-in, not enforced)' }
        Add-Result $a $(if ($perArea[$a] -gt 0) { 'APPLIED' } else { 'OK' }) $detail
    }
    Write-Log "Machine policy: $changed value(s) corrected" $(if ($changed) { 'DRIFT' } else { 'INFO' })
    if ($changed -and -not $script:Cfg.AllowOneDrive) {
        Get-Process -Name OneDrive -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

function Undo-MachinePolicies {
    foreach ($e in (Get-MachinePolicies)) {
        if ($e.K -or ($script:RevertSkip -contains $e.P)) { continue }
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

# ----------------------------------------------------------------------------- accounts (local security policy)
# Uses secedit so the INF keys are locale-independent. Only affects LOCAL accounts: on AD/Entra-joined
# devices, domain password policy is set in the directory, not here.
function Get-SeceditValues {
    $tmp = [IO.Path]::GetTempFileName()
    try {
        & secedit.exe /export /cfg $tmp /areas SECURITYPOLICY /quiet | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "secedit export failed ($LASTEXITCODE)" }
        $vals = @{}
        foreach ($l in (Get-Content -LiteralPath $tmp)) {
            if ($l -match '^\s*(\w+)\s*=\s*(.+?)\s*$') { $vals[$Matches[1]] = $Matches[2] }
        }
        return $vals
    }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}

function Set-AccountPolicy {
    $want = [ordered]@{
        MinimumPasswordLength = '12'
        MaximumPasswordAge    = '-1'     # -1 = passwords never expire (current NIST guidance: length over rotation)
        LockoutBadCount       = '10'
        ResetLockoutCount     = '15'     # minutes
        LockoutDuration       = '15'     # minutes
        EnableGuestAccount    = '0'
    }
    $cur = Get-SeceditValues
    $drift = @($want.Keys | Where-Object { $cur[$_] -ne $want[$_] })
    if ($drift.Count -gt 0) {
        $inf = [IO.Path]::GetTempFileName()
        $sdb = [IO.Path]::GetTempFileName()
        try {
            $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[System Access]')
            foreach ($k in $drift) { $lines += "$k = $($want[$k])" }
            Set-Content -LiteralPath $inf -Value $lines -Encoding Unicode
            Remove-Item -LiteralPath $sdb -Force    # secedit creates the database itself
            & secedit.exe /configure /db $sdb /cfg $inf /areas SECURITYPOLICY /quiet | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "secedit configure failed ($LASTEXITCODE)" }
        }
        finally { Remove-Item -LiteralPath $inf, $sdb -Force -ErrorAction SilentlyContinue }
        Write-Log ('Account policy corrected: ' + ($drift -join ', ')) 'DRIFT'
    }
    $groups = [ordered]@{
        'Password policy: 12+ chars, no forced expiry' = @('MinimumPasswordLength', 'MaximumPasswordAge')
        'Account lockout: 10 attempts, 15 min'         = @('LockoutBadCount', 'ResetLockoutCount', 'LockoutDuration')
        'Guest account disabled'                       = @('EnableGuestAccount')
    }
    foreach ($g in $groups.Keys) {
        $hit = @($groups[$g] | Where-Object { $drift -contains $_ }).Count
        Add-Result $g $(if ($hit -gt 0) { 'APPLIED' } else { 'OK' }) ''
    }
}

# Disables the built-in Administrator, but never the last usable admin (so IT cannot be locked out).
function Disable-BuiltinAdmin {
    $area = 'Built-in Administrator disabled'
    if (-not $script:Cfg.DisableBuiltinAdmin) { Add-Result $area 'OK' 'off (config)'; return }
    $adm = Get-LocalUser | Where-Object { $_.SID.Value -like 'S-1-5-21-*-500' } | Select-Object -First 1
    if (-not $adm) { Add-Result $area 'OK' 'account not found'; return }
    if (-not $adm.Enabled) { Add-Result $area 'OK' ''; return }
    try { $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop) }
    catch { Add-Result $area 'SKIPPED' 'could not list local admins, left enabled'; return }
    $usable = 0
    foreach ($m in $members) {
        $sid = $m.SID.Value
        if ($sid -eq $adm.SID.Value) { continue }
        if ($m.ObjectClass -eq 'User' -and $m.PrincipalSource -eq 'Local') {
            $lu = Get-LocalUser -SID $sid -ErrorAction SilentlyContinue
            if ($lu -and $lu.Enabled) { $usable++ }
        } else { $usable++ }    # domain / Entra user or group: assume it can administer the device
    }
    if ($usable -eq 0) { Add-Result $area 'SKIPPED' 'no other enabled admin exists, left enabled'; return }
    Disable-LocalUser -SID $adm.SID
    Write-Log 'Disabled the built-in Administrator account' 'DRIFT'
    Add-Result $area 'APPLIED' ''
}

# ----------------------------------------------------------------------------- audit + legacy protocols
function Set-AuditPolicy {
    # "Process Creation" success events (4688). The command line itself comes from the registry value in the policy table.
    $guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'
    & auditpol.exe /set "/subcategory:$guid" /success:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "auditpol failed ($LASTEXITCODE)" }
}

function Disable-Smb1Feature {
    $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    if ($f -and $f.State -eq 'Enabled') {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop | Out-Null
        Write-Log 'Removed the SMB1Protocol Windows feature (restart needed)' 'DRIFT'
        return $true
    }
    return $false
}

# ----------------------------------------------------------------------------- BitLocker (report only)
# BitLocker is managed elsewhere. This NEVER enables, disables or changes it, it only reports the state
# so the Slack report shows whether each device is encrypted. A device that is not protected shows as FAILED
# in the report (visibility only: it does not fail the run or change the exit code).
function Test-BitLockerStatus {
    $area = 'BitLocker (system drive)'
    if (-not (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)) { Add-Result $area 'FAILED' 'NOT AVAILABLE: BitLocker not present on this edition'; return }
    $vol = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    $detail = "$($vol.VolumeStatus), $($vol.EncryptionMethod), $($vol.EncryptionPercentage)%"
    if ($vol.ProtectionStatus -eq 'On') { Add-Result $area 'OK' $detail; return }
    if ($vol.VolumeStatus -eq 'EncryptionInProgress') { Add-Result $area 'OK' "encryption in progress ($($vol.EncryptionPercentage)%)"; return }
    if ($vol.VolumeStatus -eq 'FullyEncrypted') { Add-Result $area 'FAILED' "NOT PROTECTED: encrypted but protection is suspended ($($vol.EncryptionMethod))"; return }
    Add-Result $area 'FAILED' "NOT ENCRYPTED ($($vol.VolumeStatus))"
}

# ----------------------------------------------------------------------------- version + patch status (report only)
function Get-WindowsVersionRow {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $disp = if ($cv.DisplayVersion) { $cv.DisplayVersion } else { $cv.ReleaseId }
    $name = if ([int]$cv.CurrentBuild -ge 22000) { 'Windows 11' } else { 'Windows 10' }
    Add-Result 'Windows version' 'OK' "$name $disp, build $($cv.CurrentBuild).$($cv.UBR)"
}

# Reports how old the newest installed quality update is. Visibility only: it never fails the run.
function Test-PatchStatus {
    $area = 'Windows patch status'
    $maxAge = [int]$script:Cfg.PatchMaxAgeDays
    $last = $null
    try {
        $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $count = $searcher.GetTotalHistoryCount()
        if ($count -gt 0) {
            foreach ($h in $searcher.QueryHistory(0, [Math]::Min($count, 100))) {
                if ($h.ResultCode -eq 2 -and $h.Title -match 'Cumulative Update|Security Update|Security Monthly Quality') {
                    if (-not $last -or $h.Date -gt $last) { $last = $h.Date }
                }
            }
        }
    } catch { Write-Log "Update history unavailable: $($_.Exception.Message)" 'WARN' }

    $pending = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or
               (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending')
    $boot = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).LastBootUpTime
    $upDays = if ($boot) { [int]((Get-Date) - $boot).TotalDays } else { -1 }
    $rb = if ($pending) { ", restart pending (up $upDays d)" } else { '' }

    if (-not $last) { Add-Result $area 'SKIPPED' ('no quality update found in Windows Update history' + $rb); return }
    $age = [int]((Get-Date) - $last).TotalDays
    if ($age -gt $maxAge) { Add-Result $area 'FAILED' "last quality update $age days ago (limit $maxAge)$rb"; return }
    if ($pending)         { Add-Result $area 'SKIPPED' "last quality update $age days ago$rb"; return }
    Add-Result $area 'OK' "last quality update $age days ago"
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

    $icon = @{ OK = ':white_check_mark:'; APPLIED = ':hammer_and_wrench:'; FAILED = ':x:'; SKIPPED = ':fast_forward:' }
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
$cfgDirty = $false
if ($PSBoundParameters.ContainsKey('OneDrive'))         { $script:Cfg.AllowOneDrive = ($OneDrive -eq 'Allow'); $cfgDirty = $true }
if ($PSBoundParameters.ContainsKey('TargetVersion'))    { $script:Cfg.TargetFeatureVersion = $(if ($TargetVersion -eq 'None') { '' } else { $TargetVersion }); $cfgDirty = $true }
if ($PSBoundParameters.ContainsKey('UsbWriteBlock'))    { $script:Cfg.BlockUsbWrite = ($UsbWriteBlock -eq 'Enable'); $cfgDirty = $true }
if ($PSBoundParameters.ContainsKey('PowerShellLogging')) { $script:Cfg.PowerShellScriptBlockLogging = ($PowerShellLogging -eq 'Enable'); $cfgDirty = $true }
if ($cfgDirty -and $Mode -ne 'User') { Save-Config; Write-Log 'Options saved to config.json' }

switch ($Mode) {
    'Install' {
        if (-not (Test-IsAdmin)) { Write-Log 'Must run elevated/SYSTEM' 'ERROR'; exit 1 }
        Invoke-Step 'Install files'    { Install-Self }
        Invoke-Step 'Register tasks'   { Register-PolicyTasks }
        Invoke-Step 'Machine policy'   { Set-MachinePolicies }
        Invoke-Step 'Account policy'   { Set-AccountPolicy }
        Invoke-Step 'Built-in admin'   { Disable-BuiltinAdmin }
        Invoke-Step 'Audit policy'     { Set-AuditPolicy }
        Invoke-Step 'SMBv1 feature'    { if (Disable-Smb1Feature) { Add-Result 'SMBv1 feature removed' 'APPLIED' 'restart needed' } }
        Invoke-Step 'BitLocker'        { Test-BitLockerStatus }
        Invoke-Step 'Windows version'  { Get-WindowsVersionRow }
        Invoke-Step 'Patch status'     { Test-PatchStatus }
        Invoke-Step 'Default profile'  { Set-DefaultUserHive }
        Invoke-Step 'Remove apps'      { Remove-UnwantedApps }
        Invoke-Step 'Run user task'    { Start-ScheduledTask -TaskPath $TaskPath -TaskName 'Knix Policy - User' }
    }
    'Machine' {
        if (-not (Test-IsAdmin)) { Write-Log 'Must run elevated/SYSTEM' 'ERROR'; exit 1 }
        Invoke-Step 'Machine policy'   { Set-MachinePolicies }
        Invoke-Step 'Account policy'   { Set-AccountPolicy }
        Invoke-Step 'Built-in admin'   { Disable-BuiltinAdmin }
        Invoke-Step 'Audit policy'     { Set-AuditPolicy }
        Invoke-Step 'BitLocker'        { Test-BitLockerStatus }
        Invoke-Step 'Windows version'  { Get-WindowsVersionRow }
        Invoke-Step 'Patch status'     { Test-PatchStatus }
        Invoke-Step 'Default profile'  { Set-DefaultUserHive }
        Invoke-Step 'Remove apps'      { Remove-UnwantedApps }
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
        Write-Log 'Reverted registry policies. NOT undone: password/lockout policy, Guest and built-in Administrator state, per-user taskbar prefs, removed apps.'
    }
}

if ($Mode -in @('Install', 'Machine')) {
    try { Save-Report } catch { Write-Log "Could not save report: $($_.Exception.Message)" 'WARN' }
    if ($Mode -eq 'Install') { Send-SlackReport }
}

if ($script:Failures -gt 0) { Write-Log "Completed with $($script:Failures) failure(s)" 'ERROR'; exit 1 }
Write-Log 'Completed OK'
exit 0
