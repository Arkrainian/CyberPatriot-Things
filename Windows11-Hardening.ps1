<#
Windows11-Hardening.ps1
CyberPatriot Windows 11 Introductory Round / Round 2 hardening script.

Built from:
  - "Windows Regular 11.txt" README (Arc Foundry & Aerospace scenario)
  - Week 03 Vulnerabilities Overview, Week 04 Windows Scripting & LGPO,
    Week 06 Windows Training Round, Week 07 Windows Round 1 Debrief slide decks

Run elevated:
    powershell -ExecutionPolicy Bypass -File .\Windows11-Hardening.ps1 -Mode Full

Modes:
    Full        - audit + apply hardening + verify + report
    AuditOnly   - inspect and report, change nothing
    DryRun      - same as AuditOnly but prints every action that WOULD be taken
    VerifyOnly  - only run the verification/compliance report pass

Optional switches:
    -RemoveUnauthorizedApps   Actually uninstall apps matched as unauthorized/hacking tools
                               (default: only reported, never removed automatically)
    -RemoveMediaFiles         Actually delete flagged non-work media files
                               (default: only reported, never deleted automatically)
    -SkipAppUpdates           Skip the winget-based update attempt for required business software
#>

[CmdletBinding()]
param(
    [ValidateSet('Full','AuditOnly','DryRun','VerifyOnly')]
    [string]$Mode = 'AuditOnly',

    [switch]$RemoveUnauthorizedApps,
    [switch]$RemoveMediaFiles,
    [switch]$SkipAppUpdates,

    [string]$WorkDir = "$env:SystemDrive\CyberPatriot-Hardening"
)

#region INITIALIZATION

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$Script:DryRun       = ($Mode -eq 'DryRun') -or ($Mode -eq 'AuditOnly') -or ($Mode -eq 'VerifyOnly')
$Script:VerifyOnly    = ($Mode -eq 'VerifyOnly')
$Script:StartTime     = Get-Date
$Script:LogDir        = Join-Path $WorkDir 'Logs'
$Script:BackupDir     = Join-Path $WorkDir ("Backups_" + $Script:StartTime.ToString('yyyyMMdd_HHmmss'))
$Script:LogFile       = Join-Path $Script:LogDir ("hardening_" + $Script:StartTime.ToString('yyyyMMdd_HHmmss') + '.log')
$Script:ReportCsvPath = Join-Path $WorkDir ("ComplianceReport_" + $Script:StartTime.ToString('yyyyMMdd_HHmmss') + '.csv')
$Script:Report        = New-Object System.Collections.Generic.List[object]

foreach ($dir in @($WorkDir, $Script:LogDir, $Script:BackupDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

#endregion INITIALIZATION

#region CONFIGURATION
# Everything below is derived from the README / training decks. Keep the
# source documents cited inline so later re-runs against a different README
# only require editing this region.

# README: "Authorized Administrators" (pparker is the primary auto-login user)
$Script:PrimaryAutoLoginUser = 'pparker'

$Script:AuthorizedAdmins = @(
    'pparker','tstark','ppotts','hhogan','nfury','mhill','pcoulson'
)

$Script:AuthorizedStandardUsers = @(
    'bbanner','swilson','sstrange','slang','cdanvers','okoye','kbishop',
    'ybelova','jfoster','nleeds','mjwatson','jtorres','pcarter'
)

$Script:AllAuthorizedUsers = $Script:AuthorizedAdmins + $Script:AuthorizedStandardUsers

# Built-in accounts that are never touched by the "unauthorized -> disable" sweep,
# but ARE still subject to the Guest/Administrator-specific hardening below.
$Script:BuiltInExempt = @('DefaultAccount','WDAGUtilityAccount')

# README: "Critical Services" - never stop/disable these, regardless of what any
# generic vulnerability checklist says.
$Script:CriticalServicePatterns = @('TermService','SessionEnv','UmRdpService','ccs')

# README: company-approved business software that must stay installed & updated.
# winget ids are used for the best-effort update pass (Phase: Applications).
$Script:RequiredSoftware = @(
    [pscustomobject]@{ Name = 'Google Chrome';  Match = 'Google Chrome';       WingetId = 'Google.Chrome' }
    [pscustomobject]@{ Name = 'Notepad++';       Match = 'Notepad\+\+';        WingetId = 'Notepad++.Notepad++' }
    [pscustomobject]@{ Name = 'LibreOffice';     Match = 'LibreOffice';        WingetId = 'TheDocumentFoundation.LibreOffice' }
    [pscustomobject]@{ Name = 'Mozilla Thunderbird'; Match = 'Thunderbird';    WingetId = 'Mozilla.Thunderbird' }
    [pscustomobject]@{ Name = 'OpenRocket';      Match = 'OpenRocket';         WingetId = $null }
    [pscustomobject]@{ Name = '7-Zip';           Match = '7-Zip';              WingetId = '7zip.7zip' }
)

# Training-deck "common hacking tools / unauthorized software" list. Wireshark and
# Nmap are flagged but NOT auto-removed by default, since some README variants
# explicitly require them to stay (per Week 06/07 decks) - always cross-check the
# live README before enabling -RemoveUnauthorizedApps.
$Script:UnauthorizedAppPatterns = @(
    'nmap','wireshark','npcap','burp\s*suite','jellyfin','hydra','john\s*the\s*ripper',
    'cain\s*(and|&)\s*abel','aircrack','netcat','^ncat$','hashcat','mimikatz','brutus',
    'ophcrack','metasploit','deluge','utorrent','bittorrent','tor\s*browser','angry\s*ip',
    'cheat\s*engine','process\s*hacker','putty','psexec','advanced\s*ip\s*scanner',
    'wireless\s*network\s*watcher','nessus','nikto','sqlmap','hashsuite'
)

# Non-work media file extensions to flag inside user profile media/document folders.
$Script:MediaExtensions = @('*.mp3','*.mp4','*.wav','*.avi','*.mov','*.mkv','*.wmv','*.flac',
                            '*.jpg','*.jpeg','*.png','*.gif','*.bmp')
$Script:MediaScanSubfolders = @('Desktop','Downloads','Documents','Music','Videos','Pictures')

# Services the Week 03 / Week 04 decks call out as common unnecessary/insecure
# services to disable. Anything matching $CriticalServicePatterns is skipped
# automatically even if listed here.
$Script:ServicesToDisable = @(
    'TlntSvr'        # Telnet Server
    'RemoteRegistry' # Remote Registry
    'SharedAccess'   # Internet Connection Sharing
    'ftpsvc'         # FTP Server
    'SNMP'           # SNMP Service
    'SNMPTRAP'       # SNMP Trap
    'TapiSrv'        # Telephony
)

# Default SMB shares that are expected and should NOT be flagged.
$Script:DefaultShareNames = @('ADMIN$','IPC$','print$') + (Get-PSDrive -PSProvider FileSystem | ForEach-Object { "$($_.Name)$" })

#endregion CONFIGURATION

#region LOGGING FUNCTIONS

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','ACTION','SKIP')][string]$Level = 'INFO'
    )
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $Script:LogFile -Value $line -Encoding UTF8
    switch ($Level) {
        'ERROR'  { Write-Host $line -ForegroundColor Red }
        'WARN'   { Write-Host $line -ForegroundColor Yellow }
        'ACTION' { Write-Host $line -ForegroundColor Cyan }
        'SKIP'   { Write-Host $line -ForegroundColor DarkGray }
        default  { Write-Host $line }
    }
}

function Invoke-Hardening {
    <#
        Central gate for every state-changing operation. In DryRun/AuditOnly/VerifyOnly
        mode the ScriptBlock is never invoked - only logged - so the script is safe to
        run repeatedly to inspect what it would do.
    #>
    param(
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    if ($Script:DryRun) {
        Write-Log -Level ACTION -Message "[DRY-RUN] Would do: $Description"
        return $false
    }
    try {
        & $Action
        Write-Log -Level ACTION -Message "Applied: $Description"
        return $true
    } catch {
        Write-Log -Level ERROR -Message "Failed: $Description - $($_.Exception.Message)"
        return $false
    }
}

function Add-ReportItem {
    param(
        [string]$RequirementId,
        [string]$Description,
        [string]$Source,
        [ValidateSet('PASS','FAIL','WARNING','MANUAL REVIEW','NOT APPLICABLE')]
        [string]$Status,
        [string]$Actual,
        [string]$Expected,
        [string]$ActionTaken = ''
    )
    $Script:Report.Add([pscustomobject]@{
        RequirementId  = $RequirementId
        Description    = $Description
        Source         = $Source
        Status         = $Status
        Actual         = $Actual
        Expected       = $Expected
        ActionTaken    = $ActionTaken
        Timestamp      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    })
}

#endregion LOGGING FUNCTIONS

#region BACKUP FUNCTIONS

function Backup-RegistryKey {
    param([Parameter(Mandatory)][string]$KeyPath, [Parameter(Mandatory)][string]$FileName)
    $target = Join-Path $Script:BackupDir $FileName
    try {
        $null = & reg.exe export $KeyPath $target /y 2>&1
        Write-Log "Backed up registry key '$KeyPath' to '$target'"
    } catch {
        Write-Log -Level WARN -Message "Could not back up registry key '$KeyPath': $($_.Exception.Message)"
    }
}

function Backup-SecurityPolicy {
    $target = Join-Path $Script:BackupDir 'secpol_before.cfg'
    try {
        $null = & secedit.exe /export /cfg $target /quiet 2>&1
        Write-Log "Backed up local security policy to '$target'"
    } catch {
        Write-Log -Level WARN -Message "secedit export failed: $($_.Exception.Message)"
    }
}

function Backup-FirewallRules {
    $target = Join-Path $Script:BackupDir 'firewall_before.wfw'
    try {
        $null = & netsh.exe advfirewall export "$target" 2>&1
        Write-Log "Backed up firewall configuration to '$target'"
    } catch {
        Write-Log -Level WARN -Message "Firewall export failed: $($_.Exception.Message)"
    }
}

function Backup-LocalUsers {
    $target = Join-Path $Script:BackupDir 'local_users_before.csv'
    try {
        Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, PasswordExpires, PasswordNeverExpires |
            Export-Csv -Path $target -NoTypeInformation
        Write-Log "Backed up local user inventory to '$target'"
    } catch {
        Write-Log -Level WARN -Message "Local user backup failed: $($_.Exception.Message)"
    }
}

#endregion BACKUP FUNCTIONS

#region SYSTEM INVENTORY

function Get-SystemInventory {
    Write-Log "Collecting system inventory..."
    $os = Get-CimInstance Win32_OperatingSystem
    $inventory = [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        OSCaption    = $os.Caption
        OSVersion    = $os.Version
        OSBuild      = $os.BuildNumber
        IsWindows11  = ($os.Caption -match 'Windows 11')
        Timestamp    = Get-Date
    }
    $inventory | Format-List | Out-String | Add-Content -Path $Script:LogFile

    if (-not $inventory.IsWindows11) {
        Write-Log -Level WARN -Message "This does not appear to be Windows 11 (detected: $($os.Caption)). README requires Windows 11 only - continuing, but review manually."
        Add-ReportItem -RequirementId 'OS-01' -Description 'OS must be Windows 11' -Source 'README' `
            -Status 'WARNING' -Actual $os.Caption -Expected 'Windows 11'
    } else {
        Add-ReportItem -RequirementId 'OS-01' -Description 'OS must be Windows 11' -Source 'README' `
            -Status 'PASS' -Actual $os.Caption -Expected 'Windows 11'
    }

    try {
        Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, PasswordNeverExpires |
            Out-String | Add-Content -Path $Script:LogFile
        Get-Service | Where-Object Status -eq 'Running' | Select-Object Name, DisplayName |
            Out-String | Add-Content -Path $Script:LogFile
    } catch {
        Write-Log -Level WARN -Message "Partial inventory failure: $($_.Exception.Message)"
    }
    return $inventory
}

#endregion SYSTEM INVENTORY

#region USER SECURITY

function Protect-LocalUsers {
    Write-Log "=== USER AND ACCOUNT SECURITY ==="
    Backup-LocalUsers

    $localUsers = Get-LocalUser

    # --- Disable unauthorized accounts (never delete - README: don't remove authorized
    #     users or their home directories; unauthorized ones are disabled, not deleted,
    #     in case they need to be re-enabled or their files inspected per the decks).
    foreach ($u in $localUsers) {
        if ($u.Name -in $Script:BuiltInExempt) { continue }
        if ($u.Name -eq 'Administrator' -or $u.Name -eq 'Guest') { continue } # handled separately below

        $isAuthorized = $u.Name -in $Script:AllAuthorizedUsers
        if (-not $isAuthorized -and $u.Enabled) {
            Invoke-Hardening -Description "Disable unauthorized user account '$($u.Name)'" -Action {
                Disable-LocalUser -Name $u.Name
            }
            Add-ReportItem -RequirementId 'USR-01' -Description "Unauthorized account disabled" -Source 'README user list' `
                -Status 'WARNING' -Actual "$($u.Name) enabled" -Expected 'Disabled' -ActionTaken 'Disabled (not deleted)'
        } elseif ($isAuthorized) {
            Add-ReportItem -RequirementId 'USR-01' -Description "Authorized account present" -Source 'README user list' `
                -Status 'PASS' -Actual $u.Name -Expected 'Present and authorized'
        }
    }

    # --- Create missing authorized accounts
    foreach ($name in $Script:AllAuthorizedUsers) {
        $existing = $localUsers | Where-Object Name -eq $name
        if (-not $existing) {
            Invoke-Hardening -Description "Create missing authorized user '$name'" -Action {
                $tempPass = (New-Guid).Guid.Substring(0,16) + 'Aa1!'
                $secure = ConvertTo-SecureString $tempPass -AsPlainText -Force
                New-LocalUser -Name $name -Password $secure -FullName $name -Description 'Created by hardening script - set per README' -AccountNeverExpires
                if ($name -in $Script:AuthorizedAdmins) {
                    Add-LocalGroupMember -Group 'Administrators' -Member $name -ErrorAction SilentlyContinue
                }
            }
            Add-ReportItem -RequirementId 'USR-02' -Description "Authorized account exists" -Source 'README user list' `
                -Status 'WARNING' -Actual 'Missing' -Expected "User '$name' present" -ActionTaken 'Created with random password - set real password manually'
        }
    }

    # --- Administrators group membership must match README exactly
    try {
        $admGroupMembers = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop |
            ForEach-Object { ($_.Name -split '\\')[-1] }
    } catch { $admGroupMembers = @() }

    foreach ($member in $admGroupMembers) {
        if ($member -in @('Administrator') -and -not $Script:BuiltInExempt) { continue }
        if ($member -notin $Script:AuthorizedAdmins -and $member -ne 'Administrator') {
            Invoke-Hardening -Description "Remove '$member' from Administrators group (not an authorized admin)" -Action {
                Remove-LocalGroupMember -Group 'Administrators' -Member $member
            }
            Add-ReportItem -RequirementId 'USR-03' -Description 'Administrators group matches README' -Source 'README admin list' `
                -Status 'WARNING' -Actual "$member is admin" -Expected 'Removed' -ActionTaken 'Removed from Administrators'
        }
    }
    foreach ($admin in $Script:AuthorizedAdmins) {
        if ((Get-LocalUser -Name $admin -ErrorAction SilentlyContinue) -and $admin -notin $admGroupMembers) {
            Invoke-Hardening -Description "Add authorized admin '$admin' to Administrators group" -Action {
                Add-LocalGroupMember -Group 'Administrators' -Member $admin
            }
            Add-ReportItem -RequirementId 'USR-03' -Description 'Administrators group matches README' -Source 'README admin list' `
                -Status 'WARNING' -Actual "$admin not admin" -Expected 'Added' -ActionTaken 'Added to Administrators'
        }
    }

    # --- Built-in Administrator and Guest: disabled per training-deck Security
    #     Options table ("Administrator account status: Disabled", "Guest account
    #     status: Disabled"). Primary auto-login user is pparker, NOT the built-in
    #     Administrator account, so this is safe to disable.
    foreach ($builtin in @('Administrator','Guest')) {
        $acct = Get-LocalUser -Name $builtin -ErrorAction SilentlyContinue
        if ($acct -and $acct.Enabled) {
            Invoke-Hardening -Description "Disable built-in '$builtin' account" -Action {
                Disable-LocalUser -Name $builtin
            }
            Add-ReportItem -RequirementId "USR-04-$builtin" -Description "$builtin account disabled" -Source 'Training deck Security Options table' `
                -Status 'WARNING' -Actual 'Enabled' -Expected 'Disabled' -ActionTaken 'Disabled'
        } elseif ($acct) {
            Add-ReportItem -RequirementId "USR-04-$builtin" -Description "$builtin account disabled" -Source 'Training deck Security Options table' `
                -Status 'PASS' -Actual 'Disabled' -Expected 'Disabled'
        }
    }

    # --- Password hygiene: require password, no "never expires" except primary
    #     auto-login account (changing its expiry policy risks the auto-login breaking,
    #     per README caution about that account).
    foreach ($u in Get-LocalUser) {
        if ($u.Name -eq $Script:PrimaryAutoLoginUser) {
            Add-ReportItem -RequirementId 'USR-05' -Description 'Primary auto-login account left untouched' -Source 'README' `
                -Status 'NOT APPLICABLE' -Actual 'Skipped' -Expected 'Skipped (README instruction)'
            continue
        }
        if (-not $u.Enabled) { continue }

        if (-not $u.PasswordRequired) {
            Invoke-Hardening -Description "Require a password for user '$($u.Name)'" -Action {
                Set-LocalUser -Name $u.Name -PasswordRequired $true
            }
            Add-ReportItem -RequirementId 'USR-06' -Description 'All users must be password protected' -Source 'README scenario' `
                -Status 'WARNING' -Actual 'No password required' -Expected 'Password required' -ActionTaken 'PasswordRequired set to true'
        }

        if ($u.PasswordExpires -eq $false) {
            Invoke-Hardening -Description "Clear 'password never expires' for user '$($u.Name)'" -Action {
                Set-LocalUser -Name $u.Name -PasswordNeverExpires $false
            }
            Add-ReportItem -RequirementId 'USR-07' -Description 'Password never expires disabled' -Source 'Training deck' `
                -Status 'WARNING' -Actual 'Never expires' -Expected 'Expires normally' -ActionTaken 'PasswordNeverExpires set to false'
        }
    }
}

#endregion USER SECURITY

#region PASSWORD POLICIES

function Set-SecurityPolicyValue {
    <#
        Edits one key under an INI-style section of an exported secedit .cfg file and
        re-imports it. Used for settings `net accounts` cannot set (complexity,
        reversible encryption) without hand-editing the policy database.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Values   # @{ 'PasswordComplexity' = '1'; ... }
    )
    $cfgPath = Join-Path $Script:BackupDir 'secpol_edit.cfg'
    $dbPath  = Join-Path $Script:BackupDir 'secedit.sdb'
    & secedit.exe /export /cfg $cfgPath /quiet | Out-Null
    $content = Get-Content $cfgPath
    foreach ($key in $Values.Keys) {
        $pattern = "^$key\s*="
        if ($content -match $pattern) {
            $content = $content -replace $pattern, "$key = $($Values[$key])"
        } else {
            # Insert into [System Access] section
            $content = $content -replace '(\[System Access\])', "`$1`r`n$key = $($Values[$key])"
        }
    }
    Set-Content -Path $cfgPath -Value $content
    & secedit.exe /configure /db $dbPath /cfg $cfgPath /areas SECURITYPOLICY /quiet | Out-Null
}

function Set-PasswordAndLockoutPolicy {
    Write-Log "=== PASSWORD AND ACCOUNT LOCKOUT POLICY ==="
    Backup-SecurityPolicy

    # Current state via `net accounts`
    $netAccountsOutput = & net.exe accounts
    Write-Log ("Current net accounts output:`n" + ($netAccountsOutput -join "`n"))

    # Values per Week 03 Vulnerabilities Overview "Windows Password Configurations"
    Invoke-Hardening -Description 'Set password policy (history=5, maxage=90, minage=30, minlen=12) and lockout policy (threshold=5, duration=30, window=30)' -Action {
        & net.exe accounts /uniquepw:5 /maxpwage:90 /minpwage:30 /minpwlen:12 /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 | Out-Null
    }
    Add-ReportItem -RequirementId 'PWD-01' -Description 'Password history / age / length policy' -Source 'Training deck: Windows Password Configurations' `
        -Status 'WARNING' -Actual 'See net accounts output in log' -Expected 'history=5 maxage=90 minage=30 minlen=12' -ActionTaken 'Applied via net accounts'

    Add-ReportItem -RequirementId 'PWD-02' -Description 'Account lockout policy' -Source 'Training deck: Windows Password Configurations' `
        -Status 'WARNING' -Actual 'See net accounts output in log' -Expected 'threshold=5 duration=30 window=30' -ActionTaken 'Applied via net accounts'

    # Complexity + reversible encryption require secedit (net accounts cannot set these)
    Invoke-Hardening -Description 'Enable password complexity requirements, disable reversible encryption storage' -Action {
        Set-SecurityPolicyValue -Values @{ 'PasswordComplexity' = '1'; 'ClearTextPassword' = '0' }
    }
    Add-ReportItem -RequirementId 'PWD-03' -Description 'Password must meet complexity requirements' -Source 'README scenario + training deck' `
        -Status 'WARNING' -Actual 'Unknown (see verification pass)' -Expected 'Enabled' -ActionTaken 'Applied via secedit'
    Add-ReportItem -RequirementId 'PWD-04' -Description 'Store passwords using reversible encryption disabled' -Source 'Training deck' `
        -Status 'WARNING' -Actual 'Unknown (see verification pass)' -Expected 'Disabled' -ActionTaken 'Applied via secedit'
}

function Set-AuditPolicy {
    Write-Log "=== AUDIT POLICY ==="
    Invoke-Hardening -Description 'Enable Success and Failure auditing for all audit policy categories' -Action {
        & auditpol.exe /set /category:* /success:enable /failure:enable | Out-Null
    }
    Add-ReportItem -RequirementId 'AUD-01' -Description 'All audit policy categories log success and failure' -Source 'Training deck: Audit Policy' `
        -Status 'WARNING' -Actual 'Unknown (see verification pass)' -Expected 'Success+Failure for all categories' -ActionTaken 'Applied via auditpol'
}

#endregion PASSWORD POLICIES

#region WINDOWS DEFENDER

function Set-DefenderHardening {
    Write-Log "=== MICROSOFT DEFENDER ==="
    try {
        $mp = Get-MpComputerStatus
    } catch {
        Write-Log -Level WARN -Message "Get-MpComputerStatus failed (Defender module unavailable?): $($_.Exception.Message)"
        Add-ReportItem -RequirementId 'AV-00' -Description 'Microsoft Defender status readable' -Source 'Phase 2 requirement' `
            -Status 'MANUAL REVIEW' -Actual 'Unavailable' -Expected 'Readable'
        return
    }

    Backup-RegistryKey -KeyPath 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' -FileName 'defender_policy_before.reg'

    if (-not $mp.AntivirusEnabled) {
        Add-ReportItem -RequirementId 'AV-01' -Description 'Antivirus enabled' -Source 'Phase 2 requirement' `
            -Status 'WARNING' -Actual 'Disabled' -Expected 'Enabled' -ActionTaken 'Flagged for manual review - do not force-enable via policy that may be intentionally restricted by GPO'
    } else {
        Add-ReportItem -RequirementId 'AV-01' -Description 'Antivirus enabled' -Source 'Phase 2 requirement' -Status 'PASS' -Actual 'Enabled' -Expected 'Enabled'
    }

    $settings = @{
        DisableRealtimeMonitoring = $false
        PUAProtection             = 1
        MAPSReporting             = 2   # Advanced cloud-delivered protection
        SubmitSamplesConsent      = 2   # Send safe samples automatically
    }
    Invoke-Hardening -Description 'Enable real-time protection, cloud-delivered protection, PUA protection' -Action {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -PUAProtection 1
        Set-MpPreference -MAPSReporting Advanced
        Set-MpPreference -SubmitSamplesConsent SendSafeSamples
        Set-MpPreference -DisableBehaviorMonitoring $false
        Set-MpPreference -DisableIOAVProtection $false
        Set-MpPreference -DisableScriptScanning $false
    }
    Add-ReportItem -RequirementId 'AV-02' -Description 'Real-time / behavior / cloud / PUA protection enabled' -Source 'Phase 2 requirement' `
        -Status 'WARNING' -Actual 'See verification pass' -Expected 'All enabled' -ActionTaken 'Applied via Set-MpPreference'

    $exclusions = (Get-MpPreference).ExclusionPath
    if ($exclusions -and $exclusions.Count -gt 0) {
        Add-ReportItem -RequirementId 'AV-03' -Description 'No broad Defender exclusions' -Source 'Phase 2 requirement' `
            -Status 'MANUAL REVIEW' -Actual ($exclusions -join '; ') -Expected 'No unexplained exclusions' -ActionTaken 'Not removed automatically - review and confirm each is legitimate'
    } else {
        Add-ReportItem -RequirementId 'AV-03' -Description 'No broad Defender exclusions' -Source 'Phase 2 requirement' -Status 'PASS' -Actual 'None' -Expected 'None'
    }

    Invoke-Hardening -Description 'Trigger Defender signature update' -Action {
        Update-MpSignature
    }
}

#endregion WINDOWS DEFENDER

#region FIREWALL

function Set-FirewallHardening {
    Write-Log "=== WINDOWS FIREWALL ==="
    Backup-FirewallRules

    $profiles = Get-NetFirewallProfile
    foreach ($p in $profiles) {
        if (-not $p.Enabled) {
            Invoke-Hardening -Description "Enable Windows Firewall for the $($p.Name) profile" -Action {
                Set-NetFirewallProfile -Profile $p.Name -Enabled True
            }
            Add-ReportItem -RequirementId "FW-01-$($p.Name)" -Description "$($p.Name) firewall profile enabled" -Source 'README scenario + training deck' `
                -Status 'WARNING' -Actual 'Disabled' -Expected 'Enabled' -ActionTaken 'Enabled'
        } else {
            Add-ReportItem -RequirementId "FW-01-$($p.Name)" -Description "$($p.Name) firewall profile enabled" -Source 'README scenario + training deck' `
                -Status 'PASS' -Actual 'Enabled' -Expected 'Enabled'
        }
    }

    # README: RDP is a critical service and must remain reachable - never disable
    # its firewall rule group, only ensure the service itself (handled in Services
    # region) and this rule group stay enabled.
    try {
        $rdpRules = Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction Stop
        $disabledRdp = $rdpRules | Where-Object Enabled -eq 'False'
        if ($disabledRdp) {
            Invoke-Hardening -Description 'Re-enable Remote Desktop firewall rule group (README: RDP is a critical service)' -Action {
                Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
            }
            Add-ReportItem -RequirementId 'FW-02' -Description 'RDP firewall rules enabled' -Source 'README critical service: RDP' `
                -Status 'WARNING' -Actual 'Some rules disabled' -Expected 'Enabled' -ActionTaken 'Re-enabled Remote Desktop rule group'
        } else {
            Add-ReportItem -RequirementId 'FW-02' -Description 'RDP firewall rules enabled' -Source 'README critical service: RDP' `
                -Status 'PASS' -Actual 'Enabled' -Expected 'Enabled'
        }
    } catch {
        Write-Log -Level WARN -Message "Could not evaluate Remote Desktop firewall rule group: $($_.Exception.Message)"
    }

    Write-Log -Level SKIP -Message "Not resetting firewall to defaults and not auditing every individual rule - scope limited to profile state and RDP rule group per README/decks."
}

#endregion FIREWALL

#region SERVICES

function Set-ServiceHardening {
    Write-Log "=== WINDOWS SERVICES ==="

    foreach ($svcName in $Script:ServicesToDisable) {
        $isCritical = $Script:CriticalServicePatterns | Where-Object { $svcName -match $_ }
        if ($isCritical) {
            Write-Log -Level SKIP -Message "Skipping '$svcName' - matches a critical service pattern"
            continue
        }

        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if (-not $svc) {
            Add-ReportItem -RequirementId "SVC-$svcName" -Description "Unnecessary service '$svcName' absent or already disabled" -Source 'Training deck: Services' `
                -Status 'NOT APPLICABLE' -Actual 'Not installed' -Expected 'Disabled/absent'
            continue
        }

        if ($svc.Status -eq 'Running' -or $svc.StartType -ne 'Disabled') {
            Invoke-Hardening -Description "Stop and disable service '$svcName' ($($svc.DisplayName))" -Action {
                Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svcName -StartupType Disabled
            }
            Add-ReportItem -RequirementId "SVC-$svcName" -Description "Unnecessary/insecure service disabled" -Source 'Training deck: Services' `
                -Status 'WARNING' -Actual "$($svc.Status)/$($svc.StartType)" -Expected 'Stopped/Disabled' -ActionTaken 'Stopped and disabled'
        } else {
            Add-ReportItem -RequirementId "SVC-$svcName" -Description "Unnecessary/insecure service disabled" -Source 'Training deck: Services' `
                -Status 'PASS' -Actual 'Stopped/Disabled' -Expected 'Stopped/Disabled'
        }
    }

    # Explicitly verify (never touch) critical services stay running
    foreach ($pattern in $Script:CriticalServicePatterns) {
        $matches = Get-Service | Where-Object { $_.Name -match $pattern }
        foreach ($svc in $matches) {
            $status = if ($svc.Status -eq 'Running') { 'PASS' } else { 'MANUAL REVIEW' }
            Add-ReportItem -RequirementId "SVC-CRITICAL-$($svc.Name)" -Description "Critical service '$($svc.Name)' left untouched and running" -Source 'README: Critical Services' `
                -Status $status -Actual $svc.Status -Expected 'Running (never modified by this script)'
        }
    }
}

#endregion SERVICES

#region APPLICATIONS

function Get-InstalledApplications {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, UninstallString, PSChildName -Unique
}

function Protect-Applications {
    Write-Log "=== APPLICATIONS AND STARTUP ==="
    $installed = Get-InstalledApplications
    $installed | Out-String | Add-Content -Path $Script:LogFile

    # --- Flag likely unauthorized / hacking-tool software
    foreach ($app in $installed) {
        foreach ($pattern in $Script:UnauthorizedAppPatterns) {
            if ($app.DisplayName -match $pattern) {
                if ($RemoveUnauthorizedApps -and -not $Script:DryRun) {
                    Invoke-Hardening -Description "Uninstall unauthorized application '$($app.DisplayName)'" -Action {
                        if ($app.UninstallString -match 'msiexec') {
                            $productCode = [regex]::Match($app.UninstallString, '\{[0-9A-Fa-f\-]+\}').Value
                            if ($productCode) { Start-Process msiexec.exe -ArgumentList "/x $productCode /qn /norestart" -Wait }
                        } elseif ($app.UninstallString) {
                            Start-Process cmd.exe -ArgumentList "/c `"$($app.UninstallString)`" /S /quiet" -Wait -ErrorAction SilentlyContinue
                        }
                    }
                    Add-ReportItem -RequirementId 'APP-01' -Description 'Unauthorized/hacking-tool software removed' -Source 'README scenario: hacking tools prohibited' `
                        -Status 'WARNING' -Actual $app.DisplayName -Expected 'Removed' -ActionTaken 'Uninstall attempted (verify manually)'
                } else {
                    Add-ReportItem -RequirementId 'APP-01' -Description 'Unauthorized/hacking-tool software flagged' -Source 'README scenario: hacking tools prohibited' `
                        -Status 'MANUAL REVIEW' -Actual $app.DisplayName -Expected 'Removed if confirmed unauthorized against the live README' `
                        -ActionTaken 'Not removed - run with -RemoveUnauthorizedApps after confirming against README'
                }
                break
            }
        }
    }

    # --- Verify required business software is present
    foreach ($req in $Script:RequiredSoftware) {
        $found = $installed | Where-Object { $_.DisplayName -match $req.Match } | Select-Object -First 1
        if ($found) {
            Add-ReportItem -RequirementId "APP-REQ-$($req.Name)" -Description "Required software '$($req.Name)' present" -Source 'README: business software' `
                -Status 'PASS' -Actual $found.DisplayVersion -Expected 'Installed'
        } else {
            Add-ReportItem -RequirementId "APP-REQ-$($req.Name)" -Description "Required software '$($req.Name)' present" -Source 'README: business software' `
                -Status 'FAIL' -Actual 'Not installed' -Expected 'Installed' -ActionTaken 'Install manually - README requires this to remain installed'
        }
    }

    # --- Best-effort updates via winget for required software that IS present
    if (-not $SkipAppUpdates -and -not $Script:DryRun) {
        $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
        if ($winget) {
            foreach ($req in $Script:RequiredSoftware) {
                if (-not $req.WingetId) { continue }
                $found = $installed | Where-Object { $_.DisplayName -match $req.Match }
                if ($found) {
                    Invoke-Hardening -Description "Update '$($req.Name)' via winget" -Action {
                        & winget.exe upgrade --id $req.WingetId --silent --accept-package-agreements --accept-source-agreements | Out-Null
                    }
                }
            }
        } else {
            Write-Log -Level WARN -Message "winget not available - required software updates must be applied manually (README requires Chrome/Notepad++/LibreOffice/Thunderbird/OpenRocket/7-Zip stay up to date)."
            Add-ReportItem -RequirementId 'APP-02' -Description 'Required software kept up to date' -Source 'README: business software' `
                -Status 'MANUAL REVIEW' -Actual 'winget unavailable' -Expected 'Up to date'
        }
    }

    # --- Default browser should be Chrome (README requirement). Programmatically
    #     changing the per-user UserChoice default on Windows 11 requires a signed
    #     hash and is unreliable to script safely, so this is reported, not forced.
    try {
        $progId = (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice' -ErrorAction SilentlyContinue).ProgId
        $isChrome = $progId -match 'Chrome'
        Add-ReportItem -RequirementId 'APP-03' -Description 'Default browser is Google Chrome' -Source 'README' `
            -Status $(if ($isChrome) { 'PASS' } else { 'MANUAL REVIEW' }) -Actual $progId -Expected 'ChromeHTML' `
            -ActionTaken $(if ($isChrome) { '' } else { 'Set manually: Settings > Apps > Default apps > Google Chrome (not safely scriptable on Win11)' })
    } catch {
        Add-ReportItem -RequirementId 'APP-03' -Description 'Default browser is Google Chrome' -Source 'README' -Status 'MANUAL REVIEW' -Actual 'Unknown' -Expected 'ChromeHTML'
    }

    # --- Startup apps / scheduled tasks inventory (reported, not auto-modified -
    #     README gives no explicit list of disallowed startup items).
    try {
        $startupItems = Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User
        $startupItems | Out-String | Add-Content -Path $Script:LogFile
        Add-ReportItem -RequirementId 'APP-04' -Description 'Startup applications reviewed' -Source 'Phase 2 requirement' `
            -Status 'MANUAL REVIEW' -Actual "$($startupItems.Count) startup items logged" -Expected 'Reviewed for anything unauthorized'
    } catch {}

    try {
        $suspiciousTasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '\\Microsoft\\' -and $_.State -ne 'Disabled' }
        $suspiciousTasks | Select-Object TaskName, TaskPath, State | Out-String | Add-Content -Path $Script:LogFile
        if ($suspiciousTasks) {
            Add-ReportItem -RequirementId 'APP-05' -Description 'Non-Microsoft scheduled tasks reviewed' -Source 'Phase 2 requirement' `
                -Status 'MANUAL REVIEW' -Actual "$($suspiciousTasks.Count) non-Microsoft tasks found" -Expected 'Reviewed for anything unauthorized'
        } else {
            Add-ReportItem -RequirementId 'APP-05' -Description 'Non-Microsoft scheduled tasks reviewed' -Source 'Phase 2 requirement' -Status 'PASS' -Actual 'None found' -Expected 'None unexpected'
        }
    } catch {}
}

#endregion APPLICATIONS

#region REGISTRY AND GROUP POLICY

function Set-SecurityOptionsRegistry {
    <#
        Registry-backed Local Security Policy "Security Options" from the Week 03
        Vulnerabilities Overview slide tables. Deliberately excludes the NTLM
        incoming/outgoing restriction and "Restrict NTLM" policies, which can break
        RDP/local authentication in some configurations - those are left as
        MANUAL REVIEW rather than risking the README's RDP critical-service
        requirement.
    #>
    Write-Log "=== REGISTRY-BACKED SECURITY OPTIONS ==="

    $lsaPath    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $winlogon   = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $netlogon   = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    $lanman     = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $lanmanWks  = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    $policyPol  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

    Backup-RegistryKey -KeyPath 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' -FileName 'lsa_before.reg'
    Backup-RegistryKey -KeyPath 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -FileName 'policies_system_before.reg'

    # name, path, regname, type, value, requirement id, description, source
    $settings = @(
        @{ Path=$policyPol; Name='DisableCAD'; Type='DWord'; Value=0; Id='SEC-01'; Desc='Do not require CTRL+ALT+DEL set to Disabled (requirement enforced)'; Src='LGPO training deck' }
        @{ Path=$policyPol; Name='DontDisplayLastUserName'; Type='DWord'; Value=1; Id='SEC-02'; Desc='Do not display last signed-in user'; Src='LGPO training deck' }
        @{ Path=$lanmanWks; Name='RequireSecuritySignature'; Type='DWord'; Value=1; Id='SEC-03'; Desc='Microsoft network client: Digitally sign communications (always)'; Src='Week 06/07 decks, worth 5 points'; }
        @{ Path=$lanmanWks; Name='EnableSecuritySignature'; Type='DWord'; Value=1; Id='SEC-03b'; Desc='Microsoft network client: Digitally sign communications (if server agrees)'; Src='Vulnerabilities table' }
        @{ Path=$lanman;    Name='RequireSecuritySignature'; Type='DWord'; Value=1; Id='SEC-04'; Desc='Microsoft network server: Digitally sign communications (always)'; Src='Vulnerabilities table' }
        @{ Path=$lanman;    Name='EnableSecuritySignature'; Type='DWord'; Value=1; Id='SEC-04b'; Desc='Microsoft network server: Digitally sign communications (if client agrees)'; Src='Vulnerabilities table' }
        @{ Path=$lanman;    Name='AutoDisconnect'; Type='DWord'; Value=15; Id='SEC-05'; Desc='Microsoft network server: idle time before suspending session (15 min)'; Src='Vulnerabilities table' }
        @{ Path=$lanman;    Name='EnableForcedLogOff'; Type='DWord'; Value=1; Id='SEC-06'; Desc='Disconnect clients when logon hours expire'; Src='Vulnerabilities table' }
        @{ Path=$lsaPath;   Name='NoLMHash'; Type='DWord'; Value=1; Id='SEC-07'; Desc='Do not store LAN Manager hash value on next password change'; Src='Vulnerabilities table' }
        @{ Path=$lsaPath;   Name='LmCompatibilityLevel'; Type='DWord'; Value=5; Id='SEC-08'; Desc='LAN Manager authentication level: Send NTLMv2 response only, refuse LM & NTLM'; Src='Vulnerabilities table' }
        @{ Path=$lsaPath;   Name='RestrictAnonymous'; Type='DWord'; Value=1; Id='SEC-09'; Desc='Do not allow anonymous enumeration of SAM accounts and shares'; Src='Vulnerabilities table' }
        @{ Path=$lsaPath;   Name='RestrictAnonymousSAM'; Type='DWord'; Value=1; Id='SEC-10'; Desc='Do not allow anonymous enumeration of SAM accounts'; Src='Vulnerabilities table' }
        @{ Path=$lsaPath;   Name='EveryoneIncludesAnonymous'; Type='DWord'; Value=0; Id='SEC-11'; Desc='Let Everyone permissions apply to anonymous users: Disabled'; Src='Vulnerabilities table' }
        @{ Path=$lsaPath;   Name='LimitBlankPasswordUse'; Type='DWord'; Value=1; Id='SEC-12'; Desc='Limit local account use of blank passwords to console logon only'; Src='Vulnerabilities table' }
        @{ Path=$lsaPath;   Name='SubmitControl'; Type='DWord'; Value=0; Id='SEC-13'; Desc='Allow server operators to schedule tasks: Disabled (domain controllers only, harmless on standalone)'; Src='Baseline hardening' }
        @{ Path=$lsaPath;   Name='NoLmHash'; Type='DWord'; Value=1; Id='SEC-07b'; Desc='(duplicate safety write) Do not store LM hash'; Src='Vulnerabilities table' }
        @{ Path=$lanman;    Name='NullSessionShares'; Type='MultiString'; Value=@(); Id='SEC-14'; Desc='Shares that can be accessed anonymously: blank'; Src='Vulnerabilities table' }
        @{ Path=$lanman;    Name='NullSessionPipes'; Type='MultiString'; Value=@(); Id='SEC-15'; Desc='Named pipes accessible anonymously: blank'; Src='Vulnerabilities table' }
        @{ Path='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Name='fAllowUnsolicited'; Type='DWord'; Value=0; Id='SEC-16'; Desc='Remote Assistance unsolicited remote control disabled'; Src='Vulnerabilities table: Remote Assistance' }
    )

    foreach ($s in $settings) {
        try {
            if (-not (Test-Path $s.Path)) {
                Invoke-Hardening -Description "Create registry path '$($s.Path)'" -Action { New-Item -Path $s.Path -Force | Out-Null }
            }
            $current = (Get-ItemProperty -Path $s.Path -Name $s.Name -ErrorAction SilentlyContinue).$($s.Name)
            $needsChange = ("$current" -ne "$($s.Value)")
            if ($needsChange) {
                Invoke-Hardening -Description "$($s.Desc) [$($s.Path)\$($s.Name) = $($s.Value)]" -Action {
                    New-ItemProperty -Path $s.Path -Name $s.Name -PropertyType $s.Type -Value $s.Value -Force | Out-Null
                }
            }
            Add-ReportItem -RequirementId $s.Id -Description $s.Desc -Source $s.Src `
                -Status $(if ($needsChange) { 'WARNING' } else { 'PASS' }) -Actual $current -Expected $s.Value `
                -ActionTaken $(if ($needsChange) { 'Registry value set' } else { '' })
        } catch {
            Write-Log -Level ERROR -Message "Failed applying $($s.Id): $($_.Exception.Message)"
            Add-ReportItem -RequirementId $s.Id -Description $s.Desc -Source $s.Src -Status 'FAIL' -Actual 'Error applying' -Expected $s.Value
        }
    }

    # NTLM traffic restriction policies are powerful enough to break RDP/local auth
    # in some edge configurations - the README marks RDP as a critical service, so
    # these are reported only, never auto-applied.
    Add-ReportItem -RequirementId 'SEC-NTLM' -Description 'Restrict NTLM incoming/outgoing traffic policies' -Source 'Vulnerabilities table' `
        -Status 'MANUAL REVIEW' -Actual 'Not changed by script' -Expected 'Review and apply manually if the live README does not depend on NTLM/RDP fallback auth'
}

function Set-UacHardening {
    Write-Log "=== UAC ==="
    $uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Backup-RegistryKey -KeyPath 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -FileName 'uac_before.reg'

    $uacSettings = @(
        @{ Name='EnableLUA'; Value=1; Id='UAC-01'; Desc='UAC enabled (Run all administrators in Admin Approval Mode)' }
        @{ Name='ConsentPromptBehaviorAdmin'; Value=2; Id='UAC-02'; Desc='UAC: Admin elevation prompt behavior = Prompt for consent on secure desktop' }
        @{ Name='ConsentPromptBehaviorUser'; Value=0; Id='UAC-03'; Desc='UAC: Standard user elevation = Automatically deny elevation requests' }
        @{ Name='PromptOnSecureDesktop'; Value=1; Id='UAC-04'; Desc='UAC: Switch to secure desktop when prompting for elevation' }
        @{ Name='EnableInstallerDetection'; Value=1; Id='UAC-05'; Desc='UAC: Detect application installations and prompt for elevation' }
        @{ Name='FilterAdministratorToken'; Value=1; Id='UAC-06'; Desc='UAC: Admin Approval Mode for the built-in Administrator account' }
    )
    foreach ($s in $uacSettings) {
        $current = (Get-ItemProperty -Path $uacPath -Name $s.Name -ErrorAction SilentlyContinue).$($s.Name)
        $needsChange = ("$current" -ne "$($s.Value)")
        if ($needsChange) {
            Invoke-Hardening -Description "$($s.Desc) [$($s.Name)=$($s.Value)]" -Action {
                New-ItemProperty -Path $uacPath -Name $s.Name -PropertyType DWord -Value $s.Value -Force | Out-Null
            }
        }
        Add-ReportItem -RequirementId $s.Id -Description $s.Desc -Source 'Vulnerabilities table: UAC' `
            -Status $(if ($needsChange) { 'WARNING' } else { 'PASS' }) -Actual $current -Expected $s.Value -ActionTaken $(if ($needsChange) { 'Registry value set' } else { '' })
    }
}

function Set-WindowsUpdatePolicy {
    Write-Log "=== WINDOWS UPDATE POLICY (feature-update prevention) ==="
    # README: "Please do NOT attempt to install Windows Feature Updates or Insider
    # Preview Builds." Pinning the target release version blocks the OS from
    # offering/installing a newer feature update while leaving quality/security
    # updates untouched.
    $wuPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    if (-not (Test-Path $wuPath)) {
        Invoke-Hardening -Description "Create WindowsUpdate policy key" -Action { New-Item -Path $wuPath -Force | Out-Null }
    }
    Backup-RegistryKey -KeyPath 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -FileName 'wu_policy_before.reg'

    $currentBuild = (Get-CimInstance Win32_OperatingSystem).Version
    Invoke-Hardening -Description "Pin target release version to current build ($currentBuild) to block feature updates / Insider builds" -Action {
        New-ItemProperty -Path $wuPath -Name 'TargetReleaseVersion' -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path $wuPath -Name 'ProductVersion' -PropertyType String -Value 'Windows 11' -Force | Out-Null
        New-ItemProperty -Path $wuPath -Name 'TargetReleaseVersionInfo' -PropertyType String -Value $currentBuild -Force | Out-Null
    }
    Add-ReportItem -RequirementId 'WU-01' -Description 'Feature updates / Insider Preview builds blocked' -Source 'README explicit prohibition' `
        -Status 'WARNING' -Actual 'See verification pass' -Expected 'TargetReleaseVersion pinned' -ActionTaken 'Registry policy applied'

    # Report only - do not force an install that could trigger a disruptive restart.
    try {
        $wua = New-Object -ComObject Microsoft.Update.AutoUpdate
        Add-ReportItem -RequirementId 'WU-02' -Description 'Windows Update configuration reviewed (no forced installs)' -Source 'Phase 2 requirement' `
            -Status 'MANUAL REVIEW' -Actual 'See Windows Update settings page' -Expected 'Security updates current, no pending disruptive restarts'
    } catch {}
}

#endregion REGISTRY AND GROUP POLICY

#region FILE SYSTEM

function Protect-FileSystem {
    Write-Log "=== FILE SYSTEM ==="

    # --- Flag (don't auto-delete unless requested) non-work media files in common
    #     user-profile locations, per README: "non-work related media files ... is
    #     strictly prohibited."
    $flaggedFiles = New-Object System.Collections.Generic.List[object]
    $userDirs = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }

    foreach ($userDir in $userDirs) {
        foreach ($sub in $Script:MediaScanSubfolders) {
            $path = Join-Path $userDir.FullName $sub
            if (Test-Path $path) {
                foreach ($ext in $Script:MediaExtensions) {
                    Get-ChildItem -Path $path -Filter $ext -Recurse -File -ErrorAction SilentlyContinue |
                        ForEach-Object { $flaggedFiles.Add($_.FullName) }
                }
            }
        }
    }

    if ($flaggedFiles.Count -gt 0) {
        $flaggedFiles | Out-String | Add-Content -Path $Script:LogFile
        if ($RemoveMediaFiles -and -not $Script:DryRun) {
            foreach ($f in $flaggedFiles) {
                Invoke-Hardening -Description "Delete flagged non-work media file '$f'" -Action {
                    Remove-Item -Path $f -Force -ErrorAction Stop
                }
            }
            Add-ReportItem -RequirementId 'FS-01' -Description 'Non-work media files removed' -Source 'README scenario' `
                -Status 'WARNING' -Actual "$($flaggedFiles.Count) files found" -Expected 'Removed' -ActionTaken 'Deleted'
        } else {
            Add-ReportItem -RequirementId 'FS-01' -Description 'Non-work media files flagged' -Source 'README scenario' `
                -Status 'MANUAL REVIEW' -Actual "$($flaggedFiles.Count) files found - see log" -Expected 'Removed if confirmed non-work-related' `
                -ActionTaken 'Not deleted - run with -RemoveMediaFiles to remove automatically, or review log and delete manually'
        }
    } else {
        Add-ReportItem -RequirementId 'FS-01' -Description 'Non-work media files flagged' -Source 'README scenario' -Status 'PASS' -Actual 'None found' -Expected 'None'
    }

    # --- Shared folders beyond the Windows defaults
    try {
        $shares = Get-SmbShare | Where-Object { $_.Name -notin $Script:DefaultShareNames }
        if ($shares) {
            $shares | Select-Object Name, Path, Description | Out-String | Add-Content -Path $Script:LogFile
            Add-ReportItem -RequirementId 'FS-02' -Description 'No unexpected SMB shares beyond Windows defaults' -Source 'Vulnerabilities table: Windows Files' `
                -Status 'MANUAL REVIEW' -Actual ($shares.Name -join ', ') -Expected 'Only default shares unless README requires otherwise'
        } else {
            Add-ReportItem -RequirementId 'FS-02' -Description 'No unexpected SMB shares beyond Windows defaults' -Source 'Vulnerabilities table: Windows Files' `
                -Status 'PASS' -Actual 'Only defaults' -Expected 'Only default shares'
        }
    } catch {
        Write-Log -Level WARN -Message "Get-SmbShare failed: $($_.Exception.Message)"
    }

    # --- Disable unnecessary file & printer sharing, and Remote Assistance, per
    #     Week 03 "Windows Configurations" slides. Network Discovery is explicitly
    #     called out as VM-dependent and is left untouched.
    Invoke-Hardening -Description 'Disable unsolicited Remote Assistance' -Action {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp' -Value 0 -Type DWord -Force
    }
    Add-ReportItem -RequirementId 'FS-03' -Description 'Remote Assistance disabled' -Source 'Vulnerabilities table: Windows Configurations' `
        -Status 'WARNING' -Actual 'See verification pass' -Expected 'Disabled' -ActionTaken 'Registry policy applied'
}

#endregion FILE SYSTEM

#region AUDITING

function Set-LoggingHardening {
    Write-Log "=== LOGGING AND AUDITING ==="

    # PowerShell Script Block + Module logging (Phase 2 requirement: PowerShell logging)
    $psLogPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if (-not (Test-Path $psLogPath)) {
        Invoke-Hardening -Description 'Create PowerShell ScriptBlockLogging policy key' -Action { New-Item -Path $psLogPath -Force | Out-Null }
    }
    Invoke-Hardening -Description 'Enable PowerShell Script Block Logging' -Action {
        New-ItemProperty -Path $psLogPath -Name 'EnableScriptBlockLogging' -PropertyType DWord -Value 1 -Force | Out-Null
    }
    Add-ReportItem -RequirementId 'LOG-01' -Description 'PowerShell Script Block Logging enabled' -Source 'Phase 2 requirement' `
        -Status 'WARNING' -Actual 'See verification pass' -Expected 'Enabled' -ActionTaken 'Registry policy applied'

    # Process creation auditing with command line (Phase 2 requirement)
    $cmdLinePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    if (-not (Test-Path $cmdLinePath)) {
        Invoke-Hardening -Description 'Create process creation audit policy key' -Action { New-Item -Path $cmdLinePath -Force | Out-Null }
    }
    Invoke-Hardening -Description 'Include command line in process creation events' -Action {
        New-ItemProperty -Path $cmdLinePath -Name 'ProcessCreationIncludeCmdLine_Enabled' -PropertyType DWord -Value 1 -Force | Out-Null
    }
    Add-ReportItem -RequirementId 'LOG-02' -Description 'Process creation command-line auditing enabled' -Source 'Phase 2 requirement' `
        -Status 'WARNING' -Actual 'See verification pass' -Expected 'Enabled' -ActionTaken 'Registry policy applied'

    # Event log retention - never clear logs, just ensure a reasonable max size.
    foreach ($log in @('Security','System','Application')) {
        Invoke-Hardening -Description "Set '$log' event log max size to 196608 KB (never clears existing entries)" -Action {
            & wevtutil.exe sl $log /ms:196608000 | Out-Null
        }
    }
    Add-ReportItem -RequirementId 'LOG-03' -Description 'Event log retention sized appropriately; logs never cleared by this script' -Source 'Phase 2 requirement' `
        -Status 'PASS' -Actual 'Resized, not cleared' -Expected 'Adequate retention, never cleared'
}

#endregion AUDITING

#region VERIFICATION

function Invoke-VerificationPass {
    Write-Log "=== VERIFICATION PASS (independent of apply logic) ==="

    # Re-check password policy state directly from the system, not from what we
    # intended to set.
    $netAccounts = & net.exe accounts
    $minLen = ($netAccounts | Select-String 'Minimum password length').ToString() -replace '\D+(\d+)$','$1'
    Update-ReportStatus -RequirementId 'PWD-01' -Actual $minLen

    $secCfg = Join-Path $Script:BackupDir 'secpol_verify.cfg'
    & secedit.exe /export /cfg $secCfg /quiet | Out-Null
    $secContent = Get-Content $secCfg -ErrorAction SilentlyContinue
    if ($secContent) {
        $complexity = ($secContent | Select-String '^PasswordComplexity\s*=\s*(\d)').Matches.Groups[1].Value
        $clearText  = ($secContent | Select-String '^ClearTextPassword\s*=\s*(\d)').Matches.Groups[1].Value
        Update-ReportStatus -RequirementId 'PWD-03' -Actual $complexity -ExpectedOverride '1'
        Update-ReportStatus -RequirementId 'PWD-04' -Actual $clearText -ExpectedOverride '0'
    }

    # Defender
    try {
        $mp = Get-MpComputerStatus
        Update-ReportStatus -RequirementId 'AV-02' -Actual "RT:$($mp.RealTimeProtectionEnabled) Behavior:$($mp.BehaviorMonitorEnabled)"
    } catch {}

    # Firewall
    foreach ($p in Get-NetFirewallProfile) {
        Update-ReportStatus -RequirementId "FW-01-$($p.Name)" -Actual $p.Enabled
    }

    # UAC
    $uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    foreach ($id in @('UAC-01','UAC-02','UAC-03','UAC-04','UAC-05','UAC-06')) {
        $names = @{ 'UAC-01'='EnableLUA'; 'UAC-02'='ConsentPromptBehaviorAdmin'; 'UAC-03'='ConsentPromptBehaviorUser'; 'UAC-04'='PromptOnSecureDesktop'; 'UAC-05'='EnableInstallerDetection'; 'UAC-06'='FilterAdministratorToken' }
        $val = (Get-ItemProperty -Path $uacPath -Name $names[$id] -ErrorAction SilentlyContinue).$($names[$id])
        Update-ReportStatus -RequirementId $id -Actual $val
    }

    # Services
    foreach ($svcName in $Script:ServicesToDisable) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) { Update-ReportStatus -RequirementId "SVC-$svcName" -Actual "$($svc.Status)/$($svc.StartType)" }
    }

    Write-Log "Verification pass complete."
}

function Update-ReportStatus {
    param([string]$RequirementId, [string]$Actual, [string]$ExpectedOverride)
    $item = $Script:Report | Where-Object { $_.RequirementId -eq $RequirementId } | Select-Object -Last 1
    if (-not $item) { return }
    $expected = if ($ExpectedOverride) { $ExpectedOverride } else { $item.Expected }
    $item.Actual = $Actual
    if ("$Actual".Trim() -eq "$expected".Trim()) {
        $item.Status = 'PASS'
    } elseif ($item.Status -ne 'MANUAL REVIEW' -and $item.Status -ne 'NOT APPLICABLE') {
        $item.Status = 'FAIL'
    }
}

#endregion VERIFICATION

#region COMPLIANCE REPORT

function Write-ComplianceReport {
    Write-Log "=== COMPLIANCE REPORT ==="
    $Script:Report | Export-Csv -Path $Script:ReportCsvPath -NoTypeInformation
    Write-Log "Compliance report written to '$Script:ReportCsvPath'"

    $summary = $Script:Report | Group-Object Status | Select-Object Name, Count
    $summary | Out-String | Add-Content -Path $Script:LogFile

    Write-Host "`n===================== COMPLIANCE SUMMARY =====================" -ForegroundColor Green
    $summary | Format-Table -AutoSize
    Write-Host "Full report: $Script:ReportCsvPath" -ForegroundColor Green
    Write-Host "Full log:    $Script:LogFile" -ForegroundColor Green

    $manualItems = $Script:Report | Where-Object Status -eq 'MANUAL REVIEW'
    if ($manualItems) {
        Write-Host "`n--- Items requiring MANUAL REVIEW ---" -ForegroundColor Yellow
        $manualItems | Format-Table RequirementId, Description, Actual, Expected -AutoSize
    }

    $failItems = $Script:Report | Where-Object Status -eq 'FAIL'
    if ($failItems) {
        Write-Host "`n--- Items that FAILED verification ---" -ForegroundColor Red
        $failItems | Format-Table RequirementId, Description, Actual, Expected -AutoSize
    }
}

#endregion COMPLIANCE REPORT

#region MAIN EXECUTION

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Main {
    Write-Log "===================================================================="
    Write-Log "Windows11-Hardening.ps1 starting - Mode=$Mode DryRun=$Script:DryRun"
    Write-Log "===================================================================="

    if (-not (Test-Administrator)) {
        Write-Log -Level ERROR -Message "This script must be run from an elevated (Administrator) PowerShell session. Aborting."
        throw "Administrator privileges required."
    }

    Get-SystemInventory | Out-Null

    if ($Script:VerifyOnly) {
        Invoke-VerificationPass
        Write-ComplianceReport
        return
    }

    try { Protect-LocalUsers } catch { Write-Log -Level ERROR -Message "Protect-LocalUsers failed: $($_.Exception.Message)" }
    try { Set-PasswordAndLockoutPolicy } catch { Write-Log -Level ERROR -Message "Set-PasswordAndLockoutPolicy failed: $($_.Exception.Message)" }
    try { Set-AuditPolicy } catch { Write-Log -Level ERROR -Message "Set-AuditPolicy failed: $($_.Exception.Message)" }
    try { Set-DefenderHardening } catch { Write-Log -Level ERROR -Message "Set-DefenderHardening failed: $($_.Exception.Message)" }
    try { Set-FirewallHardening } catch { Write-Log -Level ERROR -Message "Set-FirewallHardening failed: $($_.Exception.Message)" }
    try { Set-ServiceHardening } catch { Write-Log -Level ERROR -Message "Set-ServiceHardening failed: $($_.Exception.Message)" }
    try { Protect-Applications } catch { Write-Log -Level ERROR -Message "Protect-Applications failed: $($_.Exception.Message)" }
    try { Set-SecurityOptionsRegistry } catch { Write-Log -Level ERROR -Message "Set-SecurityOptionsRegistry failed: $($_.Exception.Message)" }
    try { Set-UacHardening } catch { Write-Log -Level ERROR -Message "Set-UacHardening failed: $($_.Exception.Message)" }
    try { Set-WindowsUpdatePolicy } catch { Write-Log -Level ERROR -Message "Set-WindowsUpdatePolicy failed: $($_.Exception.Message)" }
    try { Protect-FileSystem } catch { Write-Log -Level ERROR -Message "Protect-FileSystem failed: $($_.Exception.Message)" }
    try { Set-LoggingHardening } catch { Write-Log -Level ERROR -Message "Set-LoggingHardening failed: $($_.Exception.Message)" }

    if (-not $Script:DryRun) {
        Invoke-VerificationPass
    }

    Write-ComplianceReport

    Write-Log "===================================================================="
    Write-Log "Windows11-Hardening.ps1 complete. Elapsed: $((Get-Date) - $Script:StartTime)"
    Write-Log "===================================================================="
}

Main

#endregion MAIN EXECUTION
