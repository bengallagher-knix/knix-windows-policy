# Knix Windows policy baseline

Enforces the Knix Windows baseline on Atera-managed devices (no MDM). Keep this repo free of secrets.

- `Apply-KnixPolicy.ps1`: the baseline. Installs itself to `C:\ProgramData\Knix\Policy` and registers self-healing scheduled tasks.
- `Run-KnixPolicy.ps1`: Atera bootstrap. Downloads and runs the baseline as SYSTEM.

## Deploy
1. Atera > Admin > Scripts > New script > PowerShell. Paste `Run-KnixPolicy.ps1`.
2. Run on one pilot device first as System. Check `C:\ProgramData\Knix\Policy\policy.log`.
3. Then run on all devices and schedule it (weekly is enough).

## Re-enable OneDrive
Set `$OneDrive = 'Allow'` in the bootstrap, or on a device:
`powershell -File "C:\ProgramData\Knix\Policy\Apply-KnixPolicy.ps1" -Mode Machine -OneDrive Allow`

## Safety
- Anyone who can push to this repo can run code as SYSTEM on every device. Require 2FA and limit write access.
- For stricter change control, set `$Ref` to a reviewed tag or commit SHA.
- Revert everything: `-Mode Remove`.
