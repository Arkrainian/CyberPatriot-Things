# CyberPatriot-Things

Self-contained hardening scripts for CyberPatriot competition images. Each script audits the live system against the competition README/training-deck requirements, backs up what it's about to change, applies fixes, and writes a PASS/FAIL/WARNING/MANUAL REVIEW/NOT APPLICABLE compliance report.

**Before running any of these on a competition image:** open the script's `CONFIGURATION` region near the top and check the authorized admin/user lists, critical services, and required software against the *live* README for that round — these scripts ship with the values from one specific README and will misclassify accounts if the round's README differs.

None of these scripts delete accounts, clear logs, or reset the firewall. Destructive-sounding actions (removing unauthorized software, deleting flagged media files) are opt-in flags and are otherwise only reported for manual review.

---

## What "optional switches" means, in plain terms

Every switch below is just extra text you type after the script's name, on the same command line, to turn on an optional behavior. If you don't type it, that behavior is off (the safe default). You can combine several switches in one command by just listing them one after another, separated by spaces, in any order.

- **PowerShell scripts** (the two `.ps1` files) use switches written like `-Mode Full` (a dash, then a name, then sometimes a value) or `-Force` (a dash, then a name, no value needed).
- **The Bash script** (`Debian-Hardening.sh`) uses switches written like `--mode full` (two dashes) or `-y` (one dash, short form).

That's the only real difference — PowerShell uses one dash and often capitalizes the switch name; Bash uses two dashes and lowercase. Below, every switch is explained with what it does, when to use it, and a full command you can copy and run as-is.

---

## Windows11-Hardening.ps1

Target: Windows 11 workstation image. Open PowerShell **as Administrator** (right-click PowerShell → "Run as administrator"), then `cd` into the folder containing the script.

### The `-Mode` switch (pick exactly one)

This controls what the script is allowed to do overall.

| Value | What happens |
|---|---|
| `-Mode DryRun` | Changes **nothing**. Prints every action it *would* take, so you can read it over first. Start here. |
| `-Mode AuditOnly` | Same as DryRun for this script — inspects and reports only. |
| `-Mode Full` | Actually applies the fixes. |
| `-Mode VerifyOnly` | Doesn't fix anything — just re-checks the current state and regenerates the compliance report. Use this after you've already hardened the box and want a fresh report. |

```powershell
# Step 1: see what it would do
powershell -ExecutionPolicy Bypass -File .\Windows11-Hardening.ps1 -Mode DryRun

# Step 2: once you're happy, actually apply it
powershell -ExecutionPolicy Bypass -File .\Windows11-Hardening.ps1 -Mode Full

# Later: just regenerate the report without changing anything
powershell -ExecutionPolicy Bypass -File .\Windows11-Hardening.ps1 -Mode VerifyOnly
```

### The optional switches

These only matter when `-Mode Full` is used — they don't do anything extra in DryRun/VerifyOnly, since nothing is being applied anyway.

**`-RemoveUnauthorizedApps`**
By default, if the script finds installed software that matches a known hacking-tool pattern (Nmap, Wireshark, Burp Suite, Mimikatz, etc.), it only writes that down in the report as "MANUAL REVIEW" — it does **not** uninstall it, because the script can't know for certain the live README doesn't actually want that tool kept. Add this switch to tell the script "yes, go ahead and uninstall anything it flags."

```powershell
powershell -ExecutionPolicy Bypass -File .\Windows11-Hardening.ps1 -Mode Full -RemoveUnauthorizedApps
```

**`-RemoveMediaFiles`**
By default, non-work media files (mp3, mp4, jpg, png, etc.) found in Desktop/Downloads/Documents/Music/Videos/Pictures are only listed in the log — not deleted. Add this switch to actually delete them.

```powershell
powershell -ExecutionPolicy Bypass -File .\Windows11-Hardening.ps1 -Mode Full -RemoveMediaFiles
```

**`-SkipAppUpdates`**
By default, the script tries to update required business software (Chrome, Notepad++, LibreOffice, Thunderbird, 7-Zip) using `winget`. Add this switch to skip that step entirely — useful if you don't have internet access during the round, or you'd rather update software by hand.

```powershell
powershell -ExecutionPolicy Bypass -File .\Windows11-Hardening.ps1 -Mode Full -SkipAppUpdates
```

### Combining switches

Just list them all after `-Mode Full`, with spaces between them:

```powershell
powershell -ExecutionPolicy Bypass -File .\Windows11-Hardening.ps1 -Mode Full -RemoveUnauthorizedApps -RemoveMediaFiles
```

That one command: applies all hardening, uninstalls flagged hacking tools, AND deletes flagged media files.

---

## WindowsServer2022-Hardening.ps1

Target: Windows Server 2022 with the IIS web server role. Also run from an **elevated** PowerShell prompt.

### `-Mode` (same four values as above, plus one more)

| Value | What happens |
|---|---|
| `-Mode DryRun` / `-Mode AuditOnly` | Changes nothing, reports what it would do. |
| `-Mode Full` | Applies the fixes. |
| `-Mode VerifyOnly` | Re-checks and regenerates the report only. |
| `-Mode Rollback` | Undoes a previous run. Requires `-RollbackCategory` (see below). |

### `-Category` — run only part of the script

By default the script runs every hardening category. If you only want it to touch certain things (for example, you already fixed accounts by hand and don't want the script touching them), list the categories you want, separated by commas, with no spaces inside the list:

Valid category names: `Accounts`, `PasswordPolicy`, `Defender`, `Firewall`, `IIS`, `Services`, `Smb`, `FileSystem`, `Registry`, `Auditing`, `WindowsUpdate` — or `All` (the default).

```powershell
# Only touch IIS and SMB share settings, leave everything else alone
powershell -ExecutionPolicy Bypass -File .\WindowsServer2022-Hardening.ps1 -Mode Full -Category IIS,Smb
```

### `-Force` — allow the "disruptive" changes

Two specific changes are powerful enough that the script refuses to apply them unless you explicitly say so:
1. Disabling old, insecure SSL/TLS versions (SSLv2/3, TLS 1.0/1.1) system-wide.
2. Removing the old SMBv1 protocol feature.

Without `-Force`, both are just reported as "MANUAL REVIEW" and left alone. With `-Force`, they're applied.

```powershell
powershell -ExecutionPolicy Bypass -File .\WindowsServer2022-Hardening.ps1 -Mode Full -Force
```

### `-RestartServices`

Some IIS settings need an app pool recycle or a `W3SVC` restart to fully take effect. By default the script applies what it can live and just tells you a restart is needed, without doing it (restarting IIS drops active connections). Add this switch to let the script do that restart itself.

```powershell
powershell -ExecutionPolicy Bypass -File .\WindowsServer2022-Hardening.ps1 -Mode Full -RestartServices
```

**`-RemoveUnauthorizedApps`**, **`-RemoveMediaFiles`**, **`-SkipAppUpdates`** — identical meaning to the Windows 11 script above.

### Rolling back a change

If something the script applied causes a problem, you can undo just one category from the most recent run:

```powershell
powershell -ExecutionPolicy Bypass -File .\WindowsServer2022-Hardening.ps1 -Mode Rollback -RollbackCategory Firewall
```

Valid rollback categories: `Firewall`, `PasswordPolicy`, `Registry`, `IIS`, `Smb`, `Accounts`.
If you've run the script more than once and want to roll back to a specific earlier run instead of the most recent one, add `-BackupTimestamp <value>` using one of the folder names under `C:\CyberPatriot-Hardening-Server\Backups\`.

### Combining switches

```powershell
powershell -ExecutionPolicy Bypass -File .\WindowsServer2022-Hardening.ps1 -Mode Full -Category IIS,Smb,Firewall -Force -RestartServices
```

That command: only touches IIS, SMB, and firewall settings; allows the disruptive SSL/TLS and SMBv1 changes; and lets the script restart IIS if needed.

---

## Debian-Hardening.sh

Target: Debian 12. Run as root, from a terminal, in the folder containing the script.

First make it runnable (only needs to be done once):

```bash
chmod +x Debian-Hardening.sh
```

### `--mode` (same idea as the PowerShell scripts, lowercase, two dashes)

| Value | What happens |
|---|---|
| `--mode dryrun` | Changes nothing, prints what it would do. |
| `--mode audit` | Same as dryrun — inspect and report only. |
| `--mode full` | Applies the fixes. |
| `--mode verify` | Re-checks and regenerates the report only. |
| `--mode rollback` | Undoes a previous run. Requires `--rollback-category`. |

```bash
sudo ./Debian-Hardening.sh --mode dryrun
sudo ./Debian-Hardening.sh --mode full
sudo ./Debian-Hardening.sh --mode verify
```

### `--force` — allow the risky edits

This script treats PAM changes (password complexity rules, account lockout policy), SSH hardening (disabling root login, etc.), and `--fix-sources` (below) as "disruptive." Without `--force`, those are reported only, never written. With `--force`, they're applied — but you'll still be asked to confirm each one interactively unless you also pass `--assume-yes`.

```bash
sudo ./Debian-Hardening.sh --mode full --force
```

### `--assume-yes` (or the short form `-y`) — skip the confirmation prompts

Even with `--force`, the script normally pauses and asks "Apply this change? (y/N)" before each disruptive edit, so you can say no to any individual one. If you're running the script unattended (e.g. from a script of your own, or you just don't want to babysit it), add `--assume-yes` to auto-answer yes to everything `--force` unlocked.

```bash
sudo ./Debian-Hardening.sh --mode full --force --assume-yes
# or the short form:
sudo ./Debian-Hardening.sh --mode full --force -y
```

### `--category` — run only part of the script

Same idea as the Windows Server script's `-Category`, but comma-separated with **no spaces** and lowercase:

Valid category names: `accounts`, `password`, `ssh`, `firewall`, `services`, `files`, `packages`, `kernel`, `apparmor`, `logging` — or `all` (the default).

```bash
# Only touch accounts and SSH settings
sudo ./Debian-Hardening.sh --mode full --force --category accounts,ssh
```

### `--remove-unauthorized-apps`

Without it, packages matching known hacking tools (nmap, hydra, ophcrack, etc.) are reported only. With it, the script runs `apt purge` on anything it flags.

```bash
sudo ./Debian-Hardening.sh --mode full --force --remove-unauthorized-apps
```

### `--remove-media-files`

Without it, non-work media files found under `/home` are written to a list for you to review. With it, they're deleted.

```bash
sudo ./Debian-Hardening.sh --mode full --force --remove-media-files
```

### `--fix-sources`

If `/etc/apt/sources.list` looks corrupted or empty (which breaks `apt update`/`apt upgrade`), the script normally just flags this for manual review rather than guessing at your network setup. Pass **both** `--fix-sources` and `--force` to let it overwrite the file with Debian 12's official default mirrors.

```bash
sudo ./Debian-Hardening.sh --mode full --force --fix-sources
```

### Rolling back a change

```bash
sudo ./Debian-Hardening.sh --mode rollback --rollback-category ssh
```

Valid rollback categories: `accounts`, `ssh`, `password`, `firewall`, `kernel`, `sudoers`.
To roll back to a specific earlier run instead of the most recent one, add `--backup-timestamp <value>` using one of the folder names under `/root/cyberpatriot-hardening/backups/`.

### Combining switches — the "just do everything" command

This is the command you'd actually run during a live round, once you've confirmed with a dry run first that nothing looks wrong:

```bash
sudo ./Debian-Hardening.sh --mode full --force --assume-yes --remove-unauthorized-apps
```

That one command: applies every hardening category, unlocks the PAM/SSH/firewall changes, skips the confirmation prompts, and removes any flagged hacking-tool packages. It still leaves media files alone (no `--remove-media-files`) and never touches `sources.list` (no `--fix-sources`).

---

## Quick reference: what happens if you add nothing at all

Run any of the three with no switches beyond `-Mode Full` / `--mode full`, and you get the safest possible behavior: every low-risk, easily-reversible fix is applied automatically, and everything that's either destructive (removing software, deleting files) or genuinely system-wide risky (TLS protocol changes, SMBv1 removal, PAM/SSH edits on Debian) is left alone and written into the compliance report as "MANUAL REVIEW" for you to look at and decide on by hand. The switches exist purely to let you turn specific pieces of that caution off, one at a time, once you've decided you actually want them applied automatically.
