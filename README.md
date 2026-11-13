# Knix Windows policy baseline

Enforces the Knix Windows baseline on Atera-managed devices (no MDM). Keep this repo free of secrets.

- `Apply-KnixPolicy.ps1`: the baseline. Installs itself to `C:\ProgramData\Knix\Policy` and registers self-healing scheduled tasks.

The Atera bootstrap is **not** in this repo because it holds the Slack token. It lives only in Atera.
It downloads `Apply-KnixPolicy.ps1`, runs it as SYSTEM, and passes `KNIX_SLACK_TOKEN` / `KNIX_SLACK_CHANNEL`
as environment variables so the script can post a per-policy summary to Slack. Never commit tokens here.

## Deploy
1. Run the Atera bootstrap on one pilot device first, as System. Check `C:\ProgramData\Knix\Policy\policy.log`.
2. Then run on all devices and schedule it (weekly is enough).

## AppLocker audit (`Apply-KnixAppLockerAudit.ps1`)
Deploys AppLocker in audit-only mode (blocks nothing) and collects what would have been blocked.
- `-Mode Install`: apply the audit policy. `-Mode Collect`: summarise new findings, write a CSV, post to Slack. `-Mode Remove`: undo.
- Slack token/channel come from the Atera bootstrap's environment only. Nothing secret is stored here or on devices.
- It refuses to run if AppLocker rules it did not create exist. `Apply-KnixPolicy.ps1` no longer touches AppLocker.

## Security baseline (always on)
Password length 12+ and no forced expiry, lockout after 10 tries (15 min), Guest and built-in Administrator disabled
(Administrator only if another enabled admin exists), firewall on / inbound blocked, Defender real-time + cloud + PUA,
Windows Update auto-install with deadlines and no pause, SMBv1 / LLMNR off, RDP requires NLA, AutoRun off,
UAC secure-desktop consent, 200 MB Security log, command lines in process-creation events.
- Password and lockout rules affect **local** accounts only. AD/Entra accounts follow the directory's policy.
- Defender keys are skipped (reported SKIPPED) if Tamper Protection blocks the write.
- Tunables (deadline days, built-in admin) are in `C:\ProgramData\Knix\Policy\config.json`.

## Opt-in switches (off by default, saved on the device)
Pass via `$ExtraArgs` in the Atera bootstrap, or run on a device: `... -Mode Machine -BitLocker Enable`
- `-BitLocker Enable|Disable`: encrypts the system drive (XTS-AES 256, TPM). Only on Entra- or AD-joined devices, because the
  recovery key is escrowed first. Otherwise it reports SKIPPED. If escrow fails, encryption is rolled back.
- `-UsbWriteBlock Enable|Disable`: blocks writing to USB/removable disks.
- `-PowerShellLogging Enable|Disable`: script-block logging. **Records script text, including any secret pasted into an RMM script.**

`-Mode Remove` does not undo password/lockout policy, disabled accounts or BitLocker.

## Re-enable OneDrive
Set `$OneDrive = 'Allow'` in the Atera bootstrap, or on a device:
`powershell -File "C:\ProgramData\Knix\Policy\Apply-KnixPolicy.ps1" -Mode Machine -OneDrive Allow`

## Safety
- Anyone who can push to this repo can run code as SYSTEM on every device. Require 2FA and limit write access.
- For stricter change control, set `$Ref` to a reviewed tag or commit SHA.
- Revert everything: `-Mode Remove`.
