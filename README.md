# CyberPatriot-Things

Self-contained hardening scripts for CyberPatriot competition images. Each script audits the live system against the competition README/training-deck requirements, backs up what it's about to change, applies fixes, and writes a PASS/FAIL/WARNING/MANUAL REVIEW/NOT APPLICABLE compliance report.

**Before running any of these on a competition image:** open the script's `CONFIGURATION` region near the top and check the authorized admin/user lists, critical services, and required software against the *live* README for that round — these scripts ship with the values from one specific README and will misclassify accounts if the round's README differs.

None of these scripts delete accounts, clear logs, or reset the firewall. Destructive-sounding actions (removing unauthorized software, deleting flagged media files) are opt-in flags and are otherwise only reported for manual review.

---

## Windows11-Hardening.ps1

Target: Windows 11 workstation image.

Run from an **elevated** PowerShell prompt:

```powershell
# See what it would do, change nothing:
powershell -ExecutionPolicy Bypass -File .\Windows11-Hardening.ps1 -Mode DryRun

# Apply hardening:
powershell -ExecutionPolicy Bypass -File .\Windows11-Hardening.ps1 -Mode Full

# Re-check current state and regenerate the compliance report only:
powershell -ExecutionPolicy Bypass -File .\Windows11-Hardening.ps1 -Mode VerifyOnly
```

Optional switches: `-RemoveUnauthorizedApps`, `-RemoveMediaFiles`, `-SkipAppUpdates`.

Output: logs, registry/secpol/firewall backups, and a CSV compliance report under `C:\CyberPatriot-Hardening\`.

---

## WindowsServer2022-Hardening.ps1

Target: Windows Server 2022, IIS web server role.

Run from an **elevated** PowerShell prompt:

```powershell
# Inspect only:
powershell -ExecutionPolicy Bypass -File .\WindowsServer2022-Hardening.ps1 -Mode DryRun

# Apply hardening (Schannel/SMBv1 changes stay off unless you add -Force):
powershell -ExecutionPolicy Bypass -File .\WindowsServer2022-Hardening.ps1 -Mode Full

# Just IIS + SMB:
powershell -ExecutionPolicy Bypass -File .\WindowsServer2022-Hardening.ps1 -Mode Full -Category IIS,Smb

# Re-check and regenerate the report only:
powershell -ExecutionPolicy Bypass -File .\WindowsServer2022-Hardening.ps1 -Mode VerifyOnly

# Undo one category from the most recent run:
powershell -ExecutionPolicy Bypass -File .\WindowsServer2022-Hardening.ps1 -Mode Rollback -RollbackCategory Firewall
```

Categories: `Accounts, PasswordPolicy, Defender, Firewall, IIS, Services, Smb, FileSystem, Registry, Auditing, WindowsUpdate` (or `All`).

Optional switches: `-RemoveUnauthorizedApps`, `-RemoveMediaFiles`, `-SkipAppUpdates`, `-Force` (allows system-wide Schannel/SMBv1 changes), `-RestartServices`.

Output: logs, IIS/registry/secpol/firewall/SMB backups, and a CSV compliance report under `C:\CyberPatriot-Hardening-Server\`.

---

## Debian-Hardening.sh

Target: Debian 12.

Run as root:

```bash
chmod +x Debian-Hardening.sh

# Inspect only, change nothing:
sudo ./Debian-Hardening.sh --mode dryrun

# Apply hardening (PAM/SSH/firewall changes stay off unless you add --force):
sudo ./Debian-Hardening.sh --mode full --force --assume-yes

# Just accounts + SSH:
sudo ./Debian-Hardening.sh --mode full --force --category accounts,ssh

# Re-check and regenerate the report only:
sudo ./Debian-Hardening.sh --mode verify

# Undo one category from the most recent run:
sudo ./Debian-Hardening.sh --mode rollback --rollback-category ssh
```

Categories: `accounts, password, ssh, firewall, services, files, packages, kernel, apparmor, logging` (or `all`).

Optional flags: `--remove-unauthorized-apps`, `--remove-media-files`, `--fix-sources`, `--force`, `--assume-yes` / `-y`.

Output: logs, config backups (`/etc/passwd`, `shadow`, `sudoers`, `sshd_config`, PAM files, UFW rules), and a CSV compliance report under `/root/cyberpatriot-hardening/`.
