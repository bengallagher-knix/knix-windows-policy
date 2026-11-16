# Knix Windows policy baseline

Enforces the Knix Windows baseline on Atera-managed devices (no MDM). Keep this repo free of secrets.

- `Apply-KnixPolicy.ps1`: the baseline. Installs itself to `C:\ProgramData\Knix\Policy` and registers self-healing scheduled tasks.

The Atera bootstrap is **not** in this repo because it holds the Slack token. It lives only in Atera.
It downloads `Apply-KnixPolicy.ps1`, runs it as SYSTEM, and passes `KNIX_SLACK_TOKEN` / `KNIX_SLACK_CHANNEL`
as environment variables so the script can post a per-policy summary to Slack. Never commit tokens here.

## Deploy
1. Run the Atera bootstrap on one pilot device first, as System. Check `C:\ProgramData\Knix\Policy\policy.log`.
2. Then run on all devices and schedule it (weekly is enough).

## WDAC audit (`Apply-KnixWdacAudit.ps1`)
Deploys Windows Defender Application Control (App Control for Business) in **audit mode** (blocks nothing) and collects what
would have been blocked. Built from Microsoft's `DefaultWindows_Audit` template: Windows, Store apps and WHCP drivers are
allowed, everything else is reported. `-Base AllowMicrosoft` also allows anything Microsoft-signed.
- `-Mode Install`: build and deploy the audit policy (no restart on Windows 11 22H2+; safe to re-run, `-Force` redeploys).
  `-Mode Collect`: summarise new findings, write a CSV and a suggested allow policy, post to Slack. `-Mode Remove`: undo.
- It uses a fixed policy ID and only ever touches its own policy. Other WDAC policies on the device are left alone.
- Findings go to the Google Sheet (tab "WDAC Audit Events", one row per device + file, with serial, Windows version, logged-in
  users and the event's user) when `KNIX_SHEET_WEBHOOK` / `KNIX_SHEET_KEY` are set. Otherwise it falls back to a Slack summary.
- Slack token/channel and the sheet webhook/key come from the Atera bootstrap's environment only. Nothing secret is stored
  here or on devices.
- Needs Windows 11 and the ConfigCI PowerShell cmdlets. Files and log: `C:\ProgramData\Knix\WdacAudit`.
- `Apply-KnixPolicy.ps1` does not touch WDAC or AppLocker. Devices that got the old AppLocker audit keep that audit policy until
  it is cleared (run the previous script version's `-Mode Remove`, commit 1ff6935).

## Taskbar
Not managed. Users set up their own taskbar. Older versions set search/Widgets/Copilot policies; those are removed from devices
automatically. Taskbar values written to users' profiles by older versions are left as they are, and users can change them.

## Security baseline (always on)
Password length 12+ and no forced expiry, lockout after 10 tries (15 min), Guest and built-in Administrator disabled
(Administrator only if another enabled admin exists), firewall on / inbound blocked, Windows Update install deadlines (users can still open Windows Update, check and install early, but not pause), SMBv1 / LLMNR off, RDP requires NLA, AutoRun off,
UAC secure-desktop consent, 200 MB Security log, command lines in process-creation events.
- Password and lockout rules affect **local** accounts only. AD/Entra accounts follow the directory's policy.
- The Slack report also shows the Windows version/build and a **patch status** row (days since the newest quality update,
  restart pending). It flags a device older than `PatchMaxAgeDays` (45) as a failed row. Visibility only, never changes anything.
- Optional feature-version pin: `-TargetVersion 25H2` (`None` clears it). Not pinned by default. **A pinned version that reaches
  end of servicing stops getting security patches**, so raise it before then.
- Microsoft Defender is deliberately not managed.
- BitLocker is **report only**: the Slack report shows whether the system drive is encrypted and protected. A device that is not
  shows as a failed row. The script never enables, disables or changes BitLocker.
- Tunables (deadline days, built-in admin) are in `C:\ProgramData\Knix\Policy\config.json`.

## Opt-in switches (off by default, saved on the device)
Pass via `$ExtraArgs` in the Atera bootstrap, or run on a device: `... -Mode Machine -UsbWriteBlock Enable`
- `-UsbWriteBlock Enable|Disable`: blocks writing to USB/removable disks.
- `-PowerShellLogging Enable|Disable`: script-block logging. **Records script text, including any secret pasted into an RMM script.**

`-Mode Remove` does not undo password/lockout policy or disabled accounts.

## Re-enable OneDrive
Set `$OneDrive = 'Allow'` in the Atera bootstrap, or on a device:
`powershell -File "C:\ProgramData\Knix\Policy\Apply-KnixPolicy.ps1" -Mode Machine -OneDrive Allow`

## Safety
- Anyone who can push to this repo can run code as SYSTEM on every device. Require 2FA and limit write access.
- For stricter change control, set `$Ref` to a reviewed tag or commit SHA.
- Revert everything: `-Mode Remove`.
