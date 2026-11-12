# Atera bootstrap: downloads Apply-KnixPolicy.ps1 from GitHub and runs it as SYSTEM.
# Paste THIS FILE's contents into an Atera PowerShell script (run as System).
# Re-run from Atera whenever you push a change; the script also self-heals via its own scheduled tasks.
#
# Optional: set $Ref to a tag or commit SHA (e.g. 'v1.0') to pin devices to a reviewed version.
# Optional: set $OneDrive to 'Allow' to re-enable OneDrive on the devices this runs on.

$Owner    = 'bengallagher-knix'
$Repo     = 'knix-windows-policy'
$Ref      = 'main'
$OneDrive = ''          # '' = no change, 'Block', or 'Allow'

$ErrorActionPreference = 'Stop'
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $dir  = Join-Path $env:ProgramData 'Knix\Bootstrap'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $file = Join-Path $dir 'Apply-KnixPolicy.ps1'
    $url  = "https://raw.githubusercontent.com/$Owner/$Repo/$Ref/Apply-KnixPolicy.ps1"

    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $file
    if ((Get-Item $file).Length -lt 5000) { throw "Download looks wrong ($url)" }
    Unblock-File -Path $file

    $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $file, '-Mode', 'Install')
    if ($OneDrive) { $args += @('-OneDrive', $OneDrive) }
    & "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" @args
    exit $LASTEXITCODE
}
catch {
    Write-Output "Knix policy bootstrap failed: $($_.Exception.Message)"
    exit 1
}
