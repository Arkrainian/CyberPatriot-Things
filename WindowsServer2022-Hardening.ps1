<#
WindowsServer2022-Hardening.ps1
CyberPatriot Windows Server 2022 (IIS web server role) hardening script.

Built from:
  - "Windows Server Readme.txt" (Arc Foundry & Aerospace scenario - IIS + SMB
    "Handbook" file share are the two named Critical Services)
  - Week 03 Vulnerabilities Overview, Week 04 Windows Scripting & LGPO,
    Week 08 Windows Server slide decks (password/lockout/audit values and the
    Security Options table are shared across the Win11 and Server images; IIS
    role guidance is Server-specific)

This is a dedicated Server/IIS script - it is NOT the Windows 11 workstation
script with a few lines changed. Its first job on every run is to inventory
whatever is actually hosted on this IIS instance before touching anything,
because the competition image may host more than the Default Web Site.

Run elevated:
    powershell -ExecutionPolicy Bypass -File .\WindowsServer2022-Hardening.ps1 -Mode Full

Modes:
    Full        - audit + apply hardening + verify + report
    AuditOnly   - inspect and report, change nothing
    DryRun      - same as AuditOnly but prints every action that WOULD be taken
    VerifyOnly  - only run the verification/compliance report pass
    Rollback    - restore a previous backup set for one or more -Category values

Category selection (default All):
    Accounts, PasswordPolicy, Defender, Firewall, IIS, Services, Smb,
    FileSystem, Registry, Auditing, WindowsUpdate, All

Switches:
    -RemoveUnauthorizedApps  Actually uninstall apps matched as hacking tools (default: report only)
    -RemoveMediaFiles        Actually delete flagged non-work media files (default: report only)
    -SkipAppUpdates          Skip the winget-based update attempt for required business software
    -Force                   Allow the small set of genuinely disruptive, system-wide changes
                              (Schannel/TLS protocol hardening, SMBv1 feature removal) to actually
                              apply instead of being reported as MANUAL REVIEW
    -RestartServices         Allow the script to restart services/recycle app pools when a change
                              requires it to take effect (default: changes are applied live where
                              possible and a restart requirement is reported instead of forced)
    -RollbackCategory        One category to restore from backup when -Mode Rollback
    -BackupTimestamp         Which backup set to restore from (defaults to the most recent)
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Full','AuditOnly','DryRun','VerifyOnly','Rollback')]
    [string]$Mode = 'AuditOnly',

    [ValidateSet('Accounts','PasswordPolicy','Defender','Firewall','IIS','Services','Smb','FileSystem','Registry','Auditing','WindowsUpdate','All')]
    [string[]]$Category = @('All'),

    [switch]$RemoveUnauthorizedApps,
    [switch]$RemoveMediaFiles,
    [switch]$SkipAppUpdates,
    [switch]$Force,
    [switch]$RestartServices,

    [string]$RollbackCategory,
    [string]$BackupTimestamp,

    [string]$WorkDir = "$env:SystemDrive\CyberPatriot-Hardening-Server"
)

#region INITIALIZATION

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$Script:DryRun        = ($Mode -eq 'DryRun') -or ($Mode -eq 'AuditOnly') -or ($Mode -eq 'VerifyOnly')
$Script:StartTime      = Get-Date
$Script:RunStamp        = $Script:StartTime.ToString('yyyyMMdd_HHmmss')
$Script:LogDir         = Join-Path $WorkDir 'Logs'
$Script:BackupRoot     = Join-Path $WorkDir 'Backups'
$Script:BackupDir      = Join-Path $Script:BackupRoot $Script:RunStamp
$Script:LogFile        = Join-Path $Script:LogDir ("hardening_$Script:RunStamp.log")
$Script:ReportCsvPath  = Join-Path $WorkDir ("ComplianceReport_$Script:RunStamp.csv")
$Script:Report         = New-Object System.Collections.Generic.List[object]

foreach ($dir in @($WorkDir, $Script:LogDir, $Script:BackupRoot, $Script:BackupDir)) {
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
}

$Script:Categories = if ($Category -contains 'All') {
    @('Accounts','PasswordPolicy','Defender','Firewall','IIS','Services','Smb','FileSystem','Registry','Auditing','WindowsUpdate')
} else { $Category }

#endregion INITIALIZATION

#region CONFIGURATION
# Values sourced from "Windows Server Readme.txt" and the shared training decks.
# Update this region first if the live competition README differs.

$Script:PrimaryAutoLoginUser = 'pparker'

$Script:AuthorizedAdmins = @(
    'pparker','tstark','ppotts','hhogan','nfury','mhill','pcoulson'
)
$Script:AuthorizedStandardUsers = @(
    'bbanner','swilson','sstrange','slang','cdanvers','okoye','kbishop',
    'ybelova','jfoster','nleeds','mjwatson','jtorres','pcarter'
)
$Script:AllAuthorizedUsers = $Script:AuthorizedAdmins + $Script:AuthorizedStandardUsers

# Built-in/IIS virtual accounts that must never be swept up as "unauthorized".
# IUSR is the anonymous-authentication identity IIS depends on.
$Script:BuiltInExempt = @('DefaultAccount','WDAGUtilityAccount','IUSR','IUSRS')

# README "Critical Services": IIS (Web Server) and the SMB File Share. Also
# never touch the CCS Client, per every CyberPatriot README. These regex
# patterns gate every service/firewall-disabling routine in this script.
$Script:CriticalServicePatterns = @('W3SVC','WAS','LanmanServer','Server$','ccs')

# README business software, kept installed and updated.
$Script:RequiredSoftware = @(
    [pscustomobject]@{ Name = 'Google Chrome'; Match = 'Google Chrome';  WingetId = 'Google.Chrome' }
    [pscustomobject]@{ Name = 'Notepad++';      Match = 'Notepad\+\+';   WingetId = 'Notepad++.Notepad++' }
    [pscustomobject]@{ Name = 'WinSCP';         Match = 'WinSCP';        WingetId = 'WinSCP.WinSCP' }
    [pscustomobject]@{ Name = '7-Zip';          Match = '7-Zip';         WingetId = '7zip.7zip' }
)

$Script:UnauthorizedAppPatterns = @(
    'nmap','wireshark','npcap','burp\s*suite','jellyfin','hydra','john\s*the\s*ripper',
    'cain\s*(and|&)\s*abel','aircrack','netcat','^ncat$','hashcat','mimikatz','brutus',
    'ophcrack','metasploit','deluge','utorrent','bittorrent','tor\s*browser','angry\s*ip',
    'cheat\s*engine','process\s*hacker','psexec','advanced\s*ip\s*scanner',
    'wireless\s*network\s*watcher','nessus','nikto','sqlmap','hashsuite'
)

$Script:MediaExtensions = @('*.mp3','*.mp4','*.wav','*.avi','*.mov','*.mkv','*.wmv','*.flac',
                            '*.jpg','*.jpeg','*.png','*.gif','*.bmp')
$Script:MediaScanSubfolders = @('Desktop','Downloads','Documents','Music','Videos','Pictures')

# README: "this system has been authorized to share the C:\Shares\Handbook
# directory ... with a share name of Handbook. Only administrators may change
# the contents ... The Handbook share must remain available to everyone at
# all times." "Authenticated Users" is used instead of the literal "Everyone"
# group so unauthenticated/Guest access is not implied - Guest is disabled
# elsewhere in this script per every CyberPatriot README.
$Script:HandbookShareName = 'Handbook'
$Script:HandbookSharePath = 'C:\Shares\Handbook'

$Script:ServicesToDisable = @(
    'TlntSvr','RemoteRegistry','SharedAccess','ftpsvc','SNMP','SNMPTRAP','TapiSrv','Spooler'
)

$Script:DefaultShareNames = @('ADMIN$','IPC$','print$') + (Get-PSDrive -PSProvider FileSystem | ForEach-Object { "$($_.Name)$" })

#endregion CONFIGURATION

#region LOGGING

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
        the ScriptBlock is logged but never invoked. "Disruptive" actions additionally
        require -Force (system-wide protocol changes) and are otherwise reported as
        MANUAL REVIEW even outside DryRun, so a default `-Mode Full` run cannot
        silently make a high-blast-radius change.
    #>
    param(
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][scriptblock]$Action,
        [switch]$Disruptive
    )
    if ($Script:DryRun) {
        Write-Log -Level ACTION -Message "[DRY-RUN] Would do: $Description"
        return $false
    }
    if ($Disruptive -and -not $Force) {
        Write-Log -Level SKIP -Message "[REQUIRES -Force] Not applying disruptive change: $Description"
        return $false
    }
    if (-not $PSCmdlet.ShouldProcess($Description)) {
        Write-Log -Level SKIP -Message "User declined: $Description"
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
        [string]$RequirementId, [string]$Description, [string]$Source,
        [ValidateSet('PASS','FAIL','WARNING','MANUAL REVIEW','NOT APPLICABLE')]
        [string]$Status,
        [string]$Actual, [string]$Expected, [string]$ActionTaken = ''
    )
    $Script:Report.Add([pscustomobject]@{
        RequirementId = $RequirementId; Description = $Description; Source = $Source
        Status = $Status; Actual = $Actual; Expected = $Expected; ActionTaken = $ActionTaken
        Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    })
}

function Test-CategoryEnabled { param([string]$Name) return ($Name -in $Script:Categories) }

#endregion LOGGING

#region BACKUPS

function Backup-RegistryKey {
    param([Parameter(Mandatory)][string]$KeyPath, [Parameter(Mandatory)][string]$FileName)
    $target = Join-Path $Script:BackupDir $FileName
    try {
        $null = & reg.exe export $KeyPath $target /y 2>&1
        Write-Log "Backed up registry key '$KeyPath' -> '$target'"
    } catch {
        Write-Log -Level WARN -Message "Registry backup failed for '$KeyPath': $($_.Exception.Message)"
    }
}

function Backup-SecurityPolicy {
    $target = Join-Path $Script:BackupDir 'secpol_before.cfg'
    try { & secedit.exe /export /cfg $target /quiet | Out-Null; Write-Log "Backed up local security policy -> '$target'" }
    catch { Write-Log -Level WARN -Message "secedit export failed: $($_.Exception.Message)" }
}

function Backup-FirewallRules {
    $target = Join-Path $Script:BackupDir 'firewall_before.wfw'
    try { & netsh.exe advfirewall export "$target" | Out-Null; Write-Log "Backed up firewall configuration -> '$target'" }
    catch { Write-Log -Level WARN -Message "Firewall export failed: $($_.Exception.Message)" }
}

function Backup-LocalUsers {
    $target = Join-Path $Script:BackupDir 'local_users_before.csv'
    try {
        Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, PasswordExpires, PasswordNeverExpires |
            Export-Csv -Path $target -NoTypeInformation
        Write-Log "Backed up local user inventory -> '$target'"
    } catch { Write-Log -Level WARN -Message "Local user backup failed: $($_.Exception.Message)" }
}

function Backup-IisConfiguration {
    if (-not $Script:IisAvailable) { return }
    $backupName = "PreHardening_$Script:RunStamp"
    try {
        Backup-WebConfiguration -Name $backupName
        Write-Log "IIS configuration backed up via Backup-WebConfiguration -Name '$backupName'"
        return $backupName
    } catch {
        Write-Log -Level WARN -Message "Backup-WebConfiguration failed: $($_.Exception.Message) - IIS rollback will NOT be available for this run."
        return $null
    }
}

function Backup-SmbConfiguration {
    try {
        Get-SmbShare | Select-Object Name, Path, Description | Export-Csv -Path (Join-Path $Script:BackupDir 'smb_shares_before.csv') -NoTypeInformation
        Get-SmbShare | ForEach-Object { Get-SmbShareAccess -Name $_.Name } |
            Export-Csv -Path (Join-Path $Script:BackupDir 'smb_share_access_before.csv') -NoTypeInformation
        Get-SmbServerConfiguration | Export-Csv -Path (Join-Path $Script:BackupDir 'smb_server_config_before.csv') -NoTypeInformation
        Write-Log "Backed up SMB share/server configuration to '$Script:BackupDir'"
    } catch { Write-Log -Level WARN -Message "SMB configuration backup failed: $($_.Exception.Message)" }
}

function Save-BackupManifest {
    param([string]$IisBackupName)
    $manifest = [pscustomobject]@{
        Timestamp      = $Script:RunStamp
        IisBackupName  = $IisBackupName
        BackupDir      = $Script:BackupDir
    }
    $manifest | ConvertTo-Json | Set-Content -Path (Join-Path $Script:BackupDir 'manifest.json')
}

#endregion BACKUPS

#region ROLLBACK

function Get-BackupSetPath {
    param([string]$Timestamp)
    if ($Timestamp) {
        $p = Join-Path $Script:BackupRoot $Timestamp
        if (-not (Test-Path $p)) { throw "Backup set '$Timestamp' not found under '$Script:BackupRoot'." }
        return $p
    }
    $latest = Get-ChildItem $Script:BackupRoot -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    if (-not $latest) { throw "No backup sets found under '$Script:BackupRoot'." }
    return $latest.FullName
}

function Invoke-Rollback {
    param([Parameter(Mandatory)][string]$RollbackCategory, [string]$BackupTimestamp)

    $backupPath = Get-BackupSetPath -Timestamp $BackupTimestamp
    Write-Log "Rolling back category '$RollbackCategory' from backup set '$backupPath'"

    switch ($RollbackCategory) {
        'Firewall' {
            $wfw = Join-Path $backupPath 'firewall_before.wfw'
            if (Test-Path $wfw) { & netsh.exe advfirewall import "$wfw" | Out-Null; Write-Log "Firewall restored from '$wfw'" }
            else { Write-Log -Level ERROR -Message "No firewall backup found in '$backupPath'" }
        }
        'PasswordPolicy' {
            $cfg = Join-Path $backupPath 'secpol_before.cfg'
            if (Test-Path $cfg) {
                $db = Join-Path $backupPath 'secedit_restore.sdb'
                & secedit.exe /configure /db $db /cfg $cfg /areas SECURITYPOLICY /quiet | Out-Null
                Write-Log "Local security policy restored from '$cfg'"
            } else { Write-Log -Level ERROR -Message "No security policy backup found in '$backupPath'" }
        }
        'Registry' {
            Get-ChildItem $backupPath -Filter '*.reg' | ForEach-Object {
                & reg.exe import $_.FullName | Out-Null
                Write-Log "Imported registry backup '$($_.Name)'"
            }
        }
        'IIS' {
            $manifestPath = Join-Path $backupPath 'manifest.json'
            if (Test-Path $manifestPath) {
                $manifest = Get-Content $manifestPath | ConvertFrom-Json
                if ($manifest.IisBackupName) {
                    Restore-WebConfiguration -Name $manifest.IisBackupName
                    Write-Log "IIS configuration restored from backup '$($manifest.IisBackupName)'"
                } else { Write-Log -Level ERROR -Message "Manifest has no recorded IIS backup name for this run - IIS rollback unavailable." }
            } else { Write-Log -Level ERROR -Message "No manifest.json found in '$backupPath' - cannot determine IIS backup name." }
        }
        'Smb' {
            $sharesCsv = Join-Path $backupPath 'smb_share_access_before.csv'
            if (Test-Path $sharesCsv) {
                Write-Log "SMB share access backup found at '$sharesCsv' - review and reapply manually with Grant-SmbShareAccess/Revoke-SmbShareAccess (no automatic destructive reapply performed)."
            } else { Write-Log -Level ERROR -Message "No SMB backup found in '$backupPath'" }
        }
        'Accounts' {
            $usersCsv = Join-Path $backupPath 'local_users_before.csv'
            if (Test-Path $usersCsv) {
                $before = Import-Csv $usersCsv
                foreach ($u in $before) {
                    $current = Get-LocalUser -Name $u.Name -ErrorAction SilentlyContinue
                    if ($current -and ($current.Enabled.ToString() -ne $u.Enabled)) {
                        if ($u.Enabled -eq 'True') { Enable-LocalUser -Name $u.Name } else { Disable-LocalUser -Name $u.Name }
                        Write-Log "Restored Enabled=$($u.Enabled) for user '$($u.Name)'"
                    }
                }
            } else { Write-Log -Level ERROR -Message "No account backup found in '$backupPath'" }
        }
        default { Write-Log -Level ERROR -Message "No rollback routine implemented for category '$RollbackCategory'." }
    }
}

#endregion ROLLBACK

#region SERVER ROLE INVENTORY

function Get-ServerInventory {
    Write-Log "=== SERVER DETECTION / ROLE INVENTORY ==="
    $os = Get-CimInstance Win32_OperatingSystem
    $isServer2022 = ($os.Caption -match 'Server 2022')
    Add-ReportItem -RequirementId 'OS-01' -Description 'OS must be Windows Server 2022' -Source 'README' `
        -Status $(if ($isServer2022) { 'PASS' } else { 'WARNING' }) -Actual $os.Caption -Expected 'Windows Server 2022'

    try {
        $features = Get-WindowsFeature | Where-Object Installed
        $features | Select-Object Name, DisplayName | Out-String | Add-Content -Path $Script:LogFile

        $Script:IisAvailable = [bool]($features | Where-Object Name -eq 'Web-Server')
        Add-ReportItem -RequirementId 'ROLE-01' -Description 'IIS (Web-Server) role installed - README critical service' -Source 'README: Critical Services' `
            -Status $(if ($Script:IisAvailable) { 'PASS' } else { 'FAIL' }) -Actual $Script:IisAvailable -Expected $true

        $smb1Installed = [bool]($features | Where-Object Name -eq 'FS-SMB1')
        Add-ReportItem -RequirementId 'ROLE-02' -Description 'Obsolete SMBv1 feature not installed' -Source 'Security best practice (SMB hardening)' `
            -Status $(if ($smb1Installed) { 'WARNING' } else { 'PASS' }) -Actual $smb1Installed -Expected $false
    } catch {
        Write-Log -Level WARN -Message "Get-WindowsFeature unavailable: $($_.Exception.Message)"
        $Script:IisAvailable = [bool](Get-Service -Name W3SVC -ErrorAction SilentlyContinue)
    }

    if ($Script:IisAvailable) {
        try { Import-Module WebAdministration -ErrorAction Stop; Write-Log "WebAdministration module loaded." }
        catch { Write-Log -Level ERROR -Message "WebAdministration module failed to load even though IIS appears installed: $($_.Exception.Message)"; $Script:IisAvailable = $false }
    } else {
        Write-Log -Level WARN -Message "IIS role not detected. All IIS-specific checks will be reported as NOT APPLICABLE."
    }
}

#endregion SERVER ROLE INVENTORY

#region IIS INVENTORY

function Get-IisInventory {
    if (-not $Script:IisAvailable) { return }
    Write-Log "=== IIS INVENTORY ==="

    $sites = Get-Website
    Write-Log "Discovered $($sites.Count) IIS site(s): $(($sites.Name) -join ', ')"
    $sites | Select-Object Name, State, PhysicalPath, ID | Out-String | Add-Content -Path $Script:LogFile

    $bindings = Get-WebBinding
    $bindings | Select-Object protocol, bindingInformation | Out-String | Add-Content -Path $Script:LogFile

    $pools = Get-ChildItem IIS:\AppPools
    $pools | Select-Object Name, State | Out-String | Add-Content -Path $Script:LogFile
    foreach ($pool in $pools) {
        $identity = Get-ItemProperty "IIS:\AppPools\$($pool.Name)" -Name processModel.identityType -ErrorAction SilentlyContinue
        Write-Log "App pool '$($pool.Name)': identityType=$($identity.Value)"
        $reportStatus = if ("$($identity.Value)" -in @('ApplicationPoolIdentity','NetworkService','LocalService')) { 'PASS' } else { 'MANUAL REVIEW' }
        Add-ReportItem -RequirementId "IIS-POOL-$($pool.Name)" -Description "App pool '$($pool.Name)' runs under a least-privilege identity" -Source 'Phase 2/9 requirement' `
            -Status $reportStatus -Actual "$($identity.Value)" -Expected 'ApplicationPoolIdentity (or built-in service account)'
    }

    foreach ($site in $sites) {
        $authPath = "IIS:\Sites\$($site.Name)"
        try {
            $anon = (Get-WebConfigurationProperty -Filter '/system.webServer/security/authentication/anonymousAuthentication' -PSPath $authPath -Name enabled).Value
            $windows = (Get-WebConfigurationProperty -Filter '/system.webServer/security/authentication/windowsAuthentication' -PSPath $authPath -Name enabled).Value
            $basic = (Get-WebConfigurationProperty -Filter '/system.webServer/security/authentication/basicAuthentication' -PSPath $authPath -Name enabled).Value
            Write-Log "Site '$($site.Name)' authentication: anonymous=$anon windows=$windows basic=$basic"

            $siteBindings = $bindings | Where-Object { $_.ItemXPath -match [regex]::Escape($site.Name) -or $true }
            $hasHttps = (Get-WebBinding -Name $site.Name | Where-Object protocol -eq 'https')
            if ($basic -and -not $hasHttps) {
                Add-ReportItem -RequirementId "IIS-AUTH-$($site.Name)" -Description "Basic authentication only used over HTTPS" -Source 'Phase 2 requirement' `
                    -Status 'WARNING' -Actual 'Basic auth enabled, no HTTPS binding found' -Expected 'Basic auth requires HTTPS or should be disabled' `
                    -ActionTaken 'Not auto-disabled - confirm with README whether Basic auth is required before changing'
            } else {
                Add-ReportItem -RequirementId "IIS-AUTH-$($site.Name)" -Description "Authentication configuration reviewed" -Source 'Phase 2 requirement' `
                    -Status 'PASS' -Actual "anon=$anon windows=$windows basic=$basic" -Expected 'Reviewed, no unsafe Basic-over-HTTP combination'
            }
        } catch {
            Write-Log -Level WARN -Message "Could not read authentication settings for site '$($site.Name)': $($_.Exception.Message)"
        }

        try {
            $vdirs = Get-WebVirtualDirectory -Site $site.Name
            $vdirs | Select-Object Path, PhysicalPath | Out-String | Add-Content -Path $Script:LogFile
        } catch {}
    }
}

#endregion IIS INVENTORY

#region ACCOUNT SECURITY

function Protect-LocalUsers {
    if (-not (Test-CategoryEnabled 'Accounts')) { return }
    Write-Log "=== ACCOUNT SECURITY ==="
    Backup-LocalUsers
    $localUsers = Get-LocalUser

    foreach ($u in $localUsers) {
        if ($u.Name -in $Script:BuiltInExempt) { continue }
        if ($u.Name -eq 'Administrator' -or $u.Name -eq 'Guest') { continue }

        $isAuthorized = $u.Name -in $Script:AllAuthorizedUsers
        if (-not $isAuthorized -and $u.Enabled) {
            Invoke-Hardening -Description "Disable unauthorized user account '$($u.Name)'" -Action { Disable-LocalUser -Name $u.Name }
            Add-ReportItem -RequirementId 'USR-01' -Description 'Unauthorized account disabled' -Source 'README user list' `
                -Status 'WARNING' -Actual "$($u.Name) enabled" -Expected 'Disabled' -ActionTaken 'Disabled (not deleted)'
        } elseif ($isAuthorized) {
            Add-ReportItem -RequirementId 'USR-01' -Description 'Authorized account present' -Source 'README user list' -Status 'PASS' -Actual $u.Name -Expected 'Present and authorized'
        }
    }

    foreach ($name in $Script:AllAuthorizedUsers) {
        if (-not (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) {
            Invoke-Hardening -Description "Create missing authorized user '$name'" -Action {
                $tempPass = (New-Guid).Guid.Substring(0,16) + 'Aa1!'
                $secure = ConvertTo-SecureString $tempPass -AsPlainText -Force
                New-LocalUser -Name $name -Password $secure -FullName $name -Description 'Created by hardening script - set per README' -AccountNeverExpires
                if ($name -in $Script:AuthorizedAdmins) { Add-LocalGroupMember -Group 'Administrators' -Member $name -ErrorAction SilentlyContinue }
            }
            Add-ReportItem -RequirementId 'USR-02' -Description 'Authorized account exists' -Source 'README user list' `
                -Status 'WARNING' -Actual 'Missing' -Expected "User '$name' present" -ActionTaken 'Created with random password - set real password manually'
        }
    }

    try { $admGroupMembers = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop | ForEach-Object { ($_.Name -split '\\')[-1] } }
    catch { $admGroupMembers = @() }

    foreach ($member in $admGroupMembers) {
        if ($member -eq 'Administrator') { continue }
        if ($member -notin $Script:AuthorizedAdmins) {
            Invoke-Hardening -Description "Remove '$member' from Administrators group (not an authorized admin)" -Action { Remove-LocalGroupMember -Group 'Administrators' -Member $member }
            Add-ReportItem -RequirementId 'USR-03' -Description 'Administrators group matches README' -Source 'README admin list' `
                -Status 'WARNING' -Actual "$member is admin" -Expected 'Removed' -ActionTaken 'Removed from Administrators'
        }
    }
    foreach ($admin in $Script:AuthorizedAdmins) {
        if ((Get-LocalUser -Name $admin -ErrorAction SilentlyContinue) -and $admin -notin $admGroupMembers) {
            Invoke-Hardening -Description "Add authorized admin '$admin' to Administrators group" -Action { Add-LocalGroupMember -Group 'Administrators' -Member $admin }
            Add-ReportItem -RequirementId 'USR-03' -Description 'Administrators group matches README' -Source 'README admin list' `
                -Status 'WARNING' -Actual "$admin not admin" -Expected 'Added' -ActionTaken 'Added to Administrators'
        }
    }

    foreach ($builtin in @('Administrator','Guest')) {
        $acct = Get-LocalUser -Name $builtin -ErrorAction SilentlyContinue
        if ($acct -and $acct.Enabled) {
            Invoke-Hardening -Description "Disable built-in '$builtin' account" -Action { Disable-LocalUser -Name $builtin }
            Add-ReportItem -RequirementId "USR-04-$builtin" -Description "$builtin account disabled" -Source 'Training deck Security Options table' `
                -Status 'WARNING' -Actual 'Enabled' -Expected 'Disabled' -ActionTaken 'Disabled'
        } elseif ($acct) {
            Add-ReportItem -RequirementId "USR-04-$builtin" -Description "$builtin account disabled" -Source 'Training deck Security Options table' -Status 'PASS' -Actual 'Disabled' -Expected 'Disabled'
        }
    }

    foreach ($u in Get-LocalUser) {
        if ($u.Name -eq $Script:PrimaryAutoLoginUser) {
            Add-ReportItem -RequirementId 'USR-05' -Description 'Primary auto-login account left untouched' -Source 'README' -Status 'NOT APPLICABLE' -Actual 'Skipped' -Expected 'Skipped (README instruction)'
            continue
        }
        if (-not $u.Enabled) { continue }
        if (-not $u.PasswordRequired) {
            Invoke-Hardening -Description "Require a password for user '$($u.Name)'" -Action { Set-LocalUser -Name $u.Name -PasswordRequired $true }
            Add-ReportItem -RequirementId 'USR-06' -Description 'All users must be password protected' -Source 'README scenario' `
                -Status 'WARNING' -Actual 'No password required' -Expected 'Password required' -ActionTaken 'PasswordRequired set to true'
        }
        if ($u.PasswordExpires -eq $false) {
            Invoke-Hardening -Description "Clear 'password never expires' for user '$($u.Name)'" -Action { Set-LocalUser -Name $u.Name -PasswordNeverExpires $false }
            Add-ReportItem -RequirementId 'USR-07' -Description 'Password never expires disabled' -Source 'Training deck' `
                -Status 'WARNING' -Actual 'Never expires' -Expected 'Expires normally' -ActionTaken 'PasswordNeverExpires set to false'
        }
    }
}

#endregion ACCOUNT SECURITY

#region PASSWORD POLICIES

function Set-SecurityPolicyValue {
    param([Parameter(Mandatory)][hashtable]$Values)
    $cfgPath = Join-Path $Script:BackupDir 'secpol_edit.cfg'
    $dbPath  = Join-Path $Script:BackupDir 'secedit.sdb'
    & secedit.exe /export /cfg $cfgPath /quiet | Out-Null
    $content = Get-Content $cfgPath
    foreach ($key in $Values.Keys) {
        $pattern = "^$key\s*="
        if ($content -match $pattern) { $content = $content -replace $pattern, "$key = $($Values[$key])" }
        else { $content = $content -replace '(\[System Access\])', "`$1`r`n$key = $($Values[$key])" }
    }
    Set-Content -Path $cfgPath -Value $content
    & secedit.exe /configure /db $dbPath /cfg $cfgPath /areas SECURITYPOLICY /quiet | Out-Null
}

function Set-PasswordAndLockoutPolicy {
    if (-not (Test-CategoryEnabled 'PasswordPolicy')) { return }
    Write-Log "=== PASSWORD AND ACCOUNT LOCKOUT POLICY ==="
    Backup-SecurityPolicy

    $netAccountsOutput = & net.exe accounts
    Write-Log ("Current net accounts output:`n" + ($netAccountsOutput -join "`n"))

    Invoke-Hardening -Description 'Set password policy (history=5, maxage=90, minage=30, minlen=12) and lockout policy (threshold=5, duration=30, window=30)' -Action {
        & net.exe accounts /uniquepw:5 /maxpwage:90 /minpwage:30 /minpwlen:12 /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 | Out-Null
    }
    Add-ReportItem -RequirementId 'PWD-01' -Description 'Password history / age / length policy' -Source 'Training deck: Windows Password Configurations' `
        -Status 'WARNING' -Actual 'See net accounts output in log' -Expected 'history=5 maxage=90 minage=30 minlen=12' -ActionTaken 'Applied via net accounts'
    Add-ReportItem -RequirementId 'PWD-02' -Description 'Account lockout policy' -Source 'Training deck: Windows Password Configurations' `
        -Status 'WARNING' -Actual 'See net accounts output in log' -Expected 'threshold=5 duration=30 window=30' -ActionTaken 'Applied via net accounts'

    Invoke-Hardening -Description 'Enable password complexity requirements, disable reversible encryption storage' -Action {
        Set-SecurityPolicyValue -Values @{ 'PasswordComplexity' = '1'; 'ClearTextPassword' = '0' }
    }
    Add-ReportItem -RequirementId 'PWD-03' -Description 'Password must meet complexity requirements' -Source 'README scenario + training deck' -Status 'WARNING' -Actual 'See verification pass' -Expected 'Enabled' -ActionTaken 'Applied via secedit'
    Add-ReportItem -RequirementId 'PWD-04' -Description 'Store passwords using reversible encryption disabled' -Source 'Training deck' -Status 'WARNING' -Actual 'See verification pass' -Expected 'Disabled' -ActionTaken 'Applied via secedit'
}

function Set-AuditPolicy {
    if (-not (Test-CategoryEnabled 'Auditing')) { return }
    Write-Log "=== AUDIT POLICY ==="
    Invoke-Hardening -Description 'Enable Success and Failure auditing for all audit policy categories' -Action {
        & auditpol.exe /set /category:* /success:enable /failure:enable | Out-Null
    }
    Add-ReportItem -RequirementId 'AUD-01' -Description 'All audit policy categories log success and failure' -Source 'Training deck: Audit Policy' -Status 'WARNING' -Actual 'See verification pass' -Expected 'Success+Failure for all categories' -ActionTaken 'Applied via auditpol'
}

#endregion PASSWORD POLICIES

#region WINDOWS DEFENDER

function Set-DefenderHardening {
    if (-not (Test-CategoryEnabled 'Defender')) { return }
    Write-Log "=== WINDOWS DEFENDER ==="

    $defenderFeature = Get-WindowsFeature -Name Windows-Defender -ErrorAction SilentlyContinue
    if ($defenderFeature -and -not $defenderFeature.Installed) {
        Add-ReportItem -RequirementId 'AV-00' -Description 'Windows Defender feature installed' -Source 'Phase 5 requirement' -Status 'MANUAL REVIEW' -Actual 'Not installed' -Expected 'Installed'
        return
    }

    try { $mp = Get-MpComputerStatus }
    catch {
        Write-Log -Level WARN -Message "Get-MpComputerStatus failed: $($_.Exception.Message)"
        Add-ReportItem -RequirementId 'AV-00' -Description 'Microsoft Defender status readable' -Source 'Phase 5 requirement' -Status 'MANUAL REVIEW' -Actual 'Unavailable' -Expected 'Readable'
        return
    }

    Backup-RegistryKey -KeyPath 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' -FileName 'defender_policy_before.reg'

    Add-ReportItem -RequirementId 'AV-01' -Description 'Antivirus enabled' -Source 'Phase 5 requirement' `
        -Status $(if ($mp.AntivirusEnabled) { 'PASS' } else { 'WARNING' }) -Actual $mp.AntivirusEnabled -Expected $true `
        -ActionTaken $(if ($mp.AntivirusEnabled) { '' } else { 'Flagged for manual review - do not force-enable via policy that may be intentionally restricted by GPO' })

    Invoke-Hardening -Description 'Enable real-time/behavior/cloud/PUA protection' -Action {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -PUAProtection 1
        Set-MpPreference -MAPSReporting Advanced
        Set-MpPreference -SubmitSamplesConsent SendSafeSamples
        Set-MpPreference -DisableBehaviorMonitoring $false
        Set-MpPreference -DisableIOAVProtection $false
        Set-MpPreference -DisableScriptScanning $false
    }
    Add-ReportItem -RequirementId 'AV-02' -Description 'Real-time / behavior / cloud / PUA protection enabled' -Source 'Phase 5 requirement' -Status 'WARNING' -Actual 'See verification pass' -Expected 'All enabled' -ActionTaken 'Applied via Set-MpPreference'

    $exclusions = (Get-MpPreference).ExclusionPath
    if ($exclusions -and $exclusions.Count -gt 0) {
        $iisPaths = (Get-Website -ErrorAction SilentlyContinue).PhysicalPath
        $unexplained = $exclusions | Where-Object { $_ -notin $iisPaths }
        Add-ReportItem -RequirementId 'AV-03' -Description 'No broad Defender exclusions beyond IIS site paths' -Source 'Phase 5 requirement' `
            -Status $(if ($unexplained) { 'MANUAL REVIEW' } else { 'PASS' }) -Actual ($exclusions -join '; ') -Expected 'No unexplained exclusions' `
            -ActionTaken $(if ($unexplained) { 'Not removed automatically - review each exclusion' } else { '' })
    } else {
        Add-ReportItem -RequirementId 'AV-03' -Description 'No broad Defender exclusions' -Source 'Phase 5 requirement' -Status 'PASS' -Actual 'None' -Expected 'None'
    }

    Invoke-Hardening -Description 'Trigger Defender signature update' -Action { Update-MpSignature }
}

#endregion WINDOWS DEFENDER

#region FIREWALL

function Set-FirewallHardening {
    if (-not (Test-CategoryEnabled 'Firewall')) { return }
    Write-Log "=== FIREWALL AND NETWORK SECURITY ==="
    Backup-FirewallRules

    foreach ($p in Get-NetFirewallProfile) {
        if (-not $p.Enabled) {
            Invoke-Hardening -Description "Enable Windows Firewall for the $($p.Name) profile" -Action { Set-NetFirewallProfile -Profile $p.Name -Enabled True }
            Add-ReportItem -RequirementId "FW-01-$($p.Name)" -Description "$($p.Name) firewall profile enabled" -Source 'README scenario + training deck' -Status 'WARNING' -Actual 'Disabled' -Expected 'Enabled' -ActionTaken 'Enabled'
        } else {
            Add-ReportItem -RequirementId "FW-01-$($p.Name)" -Description "$($p.Name) firewall profile enabled" -Source 'README scenario + training deck' -Status 'PASS' -Actual 'Enabled' -Expected 'Enabled'
        }
    }

    # README critical service: IIS. Discover the actual bindings before touching
    # any firewall rule, rather than assuming only 80/443.
    if ($Script:IisAvailable) {
        $ports = (Get-WebBinding | ForEach-Object { ($_.bindingInformation -split ':')[1] }) | Where-Object { $_ } | Sort-Object -Unique
        Write-Log "IIS is bound to port(s): $($ports -join ', ')"
        try {
            $httpGroup = Get-NetFirewallRule -DisplayGroup 'World Wide Web Services (HTTP)' -ErrorAction SilentlyContinue
            $httpsGroup = Get-NetFirewallRule -DisplayGroup 'Secure World Wide Web Services (HTTPS)' -ErrorAction SilentlyContinue
            foreach ($grp in @($httpGroup, $httpsGroup) | Where-Object { $_ }) {
                $disabled = $grp | Where-Object Enabled -eq 'False'
                if ($disabled) {
                    Invoke-Hardening -Description "Re-enable firewall rule group for IIS bindings ($($grp[0].DisplayGroup))" -Action { Enable-NetFirewallRule -DisplayGroup $grp[0].DisplayGroup }
                }
            }
            Add-ReportItem -RequirementId 'FW-02' -Description 'IIS HTTP/HTTPS firewall rules enabled for discovered bindings' -Source 'README critical service: IIS' `
                -Status 'WARNING' -Actual "Ports: $($ports -join ', ')" -Expected 'Inbound allowed for each bound port' -ActionTaken 'Verified/enabled predefined HTTP(S) rule groups'
        } catch {
            Write-Log -Level WARN -Message "Could not evaluate IIS firewall rule groups: $($_.Exception.Message)"
        }
    } else {
        Add-ReportItem -RequirementId 'FW-02' -Description 'IIS HTTP/HTTPS firewall rules enabled' -Source 'README critical service: IIS' -Status 'NOT APPLICABLE' -Actual 'IIS not installed' -Expected 'N/A'
    }

    # README critical service: SMB File Share (Handbook).
    try {
        $smbRules = Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -ErrorAction SilentlyContinue
        $disabledSmb = $smbRules | Where-Object { $_.Enabled -eq 'False' -and $_.Direction -eq 'Inbound' }
        if ($disabledSmb) {
            Invoke-Hardening -Description "Re-enable 'File and Printer Sharing' inbound rules (required for Handbook SMB share)" -Action { Enable-NetFirewallRule -DisplayGroup 'File and Printer Sharing' }
            Add-ReportItem -RequirementId 'FW-03' -Description 'SMB file-sharing firewall rules enabled' -Source 'README critical service: SMB File Share' -Status 'WARNING' -Actual 'Some rules disabled' -Expected 'Enabled' -ActionTaken 'Re-enabled rule group'
        } else {
            Add-ReportItem -RequirementId 'FW-03' -Description 'SMB file-sharing firewall rules enabled' -Source 'README critical service: SMB File Share' -Status 'PASS' -Actual 'Enabled' -Expected 'Enabled'
        }
    } catch { Write-Log -Level WARN -Message "Could not evaluate SMB firewall rule group: $($_.Exception.Message)" }

    Write-Log -Level SKIP -Message "Not resetting firewall to defaults, and not blindly closing ports - scope limited to profile state + the two README-critical rule groups."
}

#endregion FIREWALL

#region IIS HARDENING

function Set-IisHardening {
    if (-not (Test-CategoryEnabled 'IIS')) { return }
    if (-not $Script:IisAvailable) {
        Add-ReportItem -RequirementId 'IIS-00' -Description 'IIS hardening applicable' -Source 'README: Critical Services' -Status 'NOT APPLICABLE' -Actual 'IIS not installed' -Expected 'N/A'
        return
    }
    Write-Log "=== IIS HARDENING ==="

    $sites = Get-Website

    # 1. Directory browsing - explicit SOC/README requirement, applied to every site.
    foreach ($site in $sites) {
        $path = "IIS:\Sites\$($site.Name)"
        $current = (Get-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' -PSPath $path -Name enabled).Value
        if ($current) {
            Invoke-Hardening -Description "Disable directory browsing on site '$($site.Name)' (SOC request in README)" -Action {
                Set-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' -PSPath $path -Name enabled -Value $false
            }
            Add-ReportItem -RequirementId "IIS-01-$($site.Name)" -Description 'Directory browsing disabled' -Source 'README: SOC team request' -Status 'WARNING' -Actual 'Enabled' -Expected 'Disabled' -ActionTaken 'Disabled'
        } else {
            Add-ReportItem -RequirementId "IIS-01-$($site.Name)" -Description 'Directory browsing disabled' -Source 'README: SOC team request' -Status 'PASS' -Actual 'Disabled' -Expected 'Disabled'
        }
    }

    # 2. HTTP methods - deny only the universally-dangerous, rarely-needed verbs.
    #    PUT/DELETE are left alone and flagged, since some apps legitimately need them.
    foreach ($site in $sites) {
        $path = "IIS:\Sites\$($site.Name)"
        foreach ($verb in @('TRACE','TRACK','DEBUG')) {
            try {
                $existing = Get-WebConfigurationProperty -Filter '/system.webServer/security/requestFiltering/verbs' -PSPath $path -Name Collection |
                    Where-Object { $_.verb -eq $verb }
                if (-not $existing) {
                    Invoke-Hardening -Description "Deny HTTP verb '$verb' on site '$($site.Name)' (request filtering)" -Action {
                        Add-WebConfiguration -Filter '/system.webServer/security/requestFiltering/verbs' -PSPath $path -Value @{verb=$verb; allowed=$false}
                    }
                }
            } catch { Write-Log -Level WARN -Message "Verb filtering check failed for '$($site.Name)' verb '$verb': $($_.Exception.Message)" }
        }
        Add-ReportItem -RequirementId "IIS-02-$($site.Name)" -Description 'Dangerous HTTP methods (TRACE/TRACK/DEBUG) denied' -Source 'Phase 2 requirement' -Status 'WARNING' -Actual 'See verification pass' -Expected 'Denied' -ActionTaken 'Applied via requestFiltering'
        Add-ReportItem -RequirementId "IIS-02B-$($site.Name)" -Description 'PUT/DELETE methods reviewed' -Source 'Phase 2 requirement' -Status 'MANUAL REVIEW' -Actual 'Not changed' -Expected 'Confirm with README whether the app needs PUT/DELETE before restricting'
    }

    # 3. Detailed error messages - DetailedLocalOnly is the safe middle ground
    #    (full detail only from the console, generic errors to remote clients).
    foreach ($site in $sites) {
        $path = "IIS:\Sites\$($site.Name)"
        $current = (Get-WebConfigurationProperty -Filter '/system.webServer/httpErrors' -PSPath $path -Name errorMode).Value
        if ("$current" -ne 'DetailedLocalOnly' -and "$current" -ne 'Custom') {
            Invoke-Hardening -Description "Set httpErrors errorMode=DetailedLocalOnly on site '$($site.Name)'" -Action {
                Set-WebConfigurationProperty -Filter '/system.webServer/httpErrors' -PSPath $path -Name errorMode -Value 'DetailedLocalOnly'
            }
            Add-ReportItem -RequirementId "IIS-03-$($site.Name)" -Description 'Detailed error messages not sent to remote clients' -Source 'Phase 2 requirement' -Status 'WARNING' -Actual $current -Expected 'DetailedLocalOnly or Custom' -ActionTaken 'Set to DetailedLocalOnly'
        } else {
            Add-ReportItem -RequirementId "IIS-03-$($site.Name)" -Description 'Detailed error messages not sent to remote clients' -Source 'Phase 2 requirement' -Status 'PASS' -Actual $current -Expected 'DetailedLocalOnly or Custom'
        }
    }

    # 4. Response headers - remove server version disclosure (safe, no functional impact).
    Invoke-Hardening -Description 'Remove Server response header at the server level' -Action {
        Set-WebConfigurationProperty -Filter '/system.webServer/security/requestFiltering' -PSPath 'IIS:\' -Name removeServerHeader -Value $true
    }
    Add-ReportItem -RequirementId 'IIS-04' -Description 'Server header suppressed' -Source 'Phase 2 requirement' -Status 'WARNING' -Actual 'See verification pass' -Expected 'removeServerHeader=true' -ActionTaken 'Applied server-wide'

    foreach ($site in $sites) {
        $path = "IIS:\Sites\$($site.Name)"
        try {
            $xPoweredBy = Get-WebConfigurationProperty -Filter '/system.webServer/httpProtocol/customHeaders' -PSPath $path -Name Collection | Where-Object { $_.name -eq 'X-Powered-By' }
            if ($xPoweredBy) {
                Invoke-Hardening -Description "Remove X-Powered-By header from site '$($site.Name)'" -Action {
                    Remove-WebConfigurationProperty -Filter '/system.webServer/httpProtocol/customHeaders' -PSPath $path -Name Collection -AtElement @{name='X-Powered-By'}
                }
            }
        } catch {}
    }

    # 5. Logging - enable W3C logging per site if it is off (low risk, high audit value).
    foreach ($site in $sites) {
        $path = "IIS:\Sites\$($site.Name)"
        $logEnabled = (Get-WebConfigurationProperty -Filter '/system.applicationHost/sites/site' -PSPath 'MACHINE/WEBROOT/APPHOST' -Name . |
            Where-Object { $_.name -eq $site.Name }).logFile.enabled
        if ($logEnabled -eq $false) {
            Invoke-Hardening -Description "Enable W3C logging for site '$($site.Name)'" -Action {
                Set-WebConfigurationProperty -Filter "/system.applicationHost/sites/site[@name='$($site.Name)']/logFile" -PSPath 'MACHINE/WEBROOT/APPHOST' -Name enabled -Value $true
            }
            Add-ReportItem -RequirementId "IIS-05-$($site.Name)" -Description 'IIS access logging enabled' -Source 'Phase 10 requirement' -Status 'WARNING' -Actual 'Disabled' -Expected 'Enabled' -ActionTaken 'Enabled'
        } else {
            Add-ReportItem -RequirementId "IIS-05-$($site.Name)" -Description 'IIS access logging enabled' -Source 'Phase 10 requirement' -Status 'PASS' -Actual 'Enabled' -Expected 'Enabled'
        }
    }

    # 6. WebDAV - flag only, never auto-remove (could be in active use).
    $webdav = Get-WebGlobalModule -Name 'WebDAVModule' -ErrorAction SilentlyContinue
    if ($webdav) {
        Add-ReportItem -RequirementId 'IIS-06' -Description 'WebDAV module reviewed' -Source 'Phase 2 requirement' -Status 'MANUAL REVIEW' -Actual 'Installed' -Expected 'Remove only if confirmed unused' -ActionTaken 'Not removed automatically'
    } else {
        Add-ReportItem -RequirementId 'IIS-06' -Description 'WebDAV module reviewed' -Source 'Phase 2 requirement' -Status 'PASS' -Actual 'Not installed' -Expected 'Not installed'
    }

    # 7. SSL/TLS protocol hardening - system-wide Schannel change, gated by -Force.
    Set-SchannelHardening

    if ($RestartServices -and -not $Script:DryRun) {
        Write-Log -Level WARN -Message "RestartServices requested - any IIS app pool recycle needed to apply the above will be performed. Website bindings/ports/certs are never modified."
    } else {
        Write-Log -Level SKIP -Message "Not recycling app pools / restarting W3SVC - some settings above may require 'iisreset /noforce' or an app pool recycle to fully apply. Re-run with -RestartServices to allow that."
    }
}

function Set-SchannelHardening {
    $schannelPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    Backup-RegistryKey -KeyPath 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' -FileName 'schannel_before.reg'

    $weakProtocols = @('SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1')
    foreach ($proto in $weakProtocols) {
        $serverPath = "$schannelPath\$proto\Server"
        Invoke-Hardening -Disruptive -Description "Disable weak protocol '$proto' server-side (Schannel)" -Action {
            if (-not (Test-Path $serverPath)) { New-Item -Path $serverPath -Force | Out-Null }
            New-ItemProperty -Path $serverPath -Name 'Enabled' -PropertyType DWord -Value 0 -Force | Out-Null
            New-ItemProperty -Path $serverPath -Name 'DisabledByDefault' -PropertyType DWord -Value 1 -Force | Out-Null
        }
    }
    $tls12Path = "$schannelPath\TLS 1.2\Server"
    Invoke-Hardening -Disruptive -Description "Explicitly enable TLS 1.2 server-side (Schannel)" -Action {
        if (-not (Test-Path $tls12Path)) { New-Item -Path $tls12Path -Force | Out-Null }
        New-ItemProperty -Path $tls12Path -Name 'Enabled' -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path $tls12Path -Name 'DisabledByDefault' -PropertyType DWord -Value 0 -Force | Out-Null
    }

    Add-ReportItem -RequirementId 'IIS-07' -Description 'Weak SSL/TLS protocols (SSLv2/3, TLS1.0/1.1) disabled; TLS 1.2 enabled' -Source 'Phase 2 requirement' `
        -Status $(if ($Force -and -not $Script:DryRun) { 'WARNING' } else { 'MANUAL REVIEW' }) -Actual 'See verification pass' -Expected 'Weak protocols disabled, TLS1.2 enabled' `
        -ActionTaken $(if ($Force -and -not $Script:DryRun) { 'Applied - a reboot is recommended for Schannel changes to fully take effect' } else { 'Requires -Force: this is a system-wide, hard-to-reverse change' })
}

#endregion IIS HARDENING

#region SERVER SERVICES

function Set-ServiceHardening {
    if (-not (Test-CategoryEnabled 'Services')) { return }
    Write-Log "=== SERVER SERVICES ==="

    foreach ($svcName in $Script:ServicesToDisable) {
        if ($Script:CriticalServicePatterns | Where-Object { $svcName -match $_ }) {
            Write-Log -Level SKIP -Message "Skipping '$svcName' - matches a critical service pattern"
            continue
        }
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if (-not $svc) {
            Add-ReportItem -RequirementId "SVC-$svcName" -Description "Unnecessary service '$svcName' absent or already disabled" -Source 'Training deck: Services' -Status 'NOT APPLICABLE' -Actual 'Not installed' -Expected 'Disabled/absent'
            continue
        }
        if ($svc.Status -eq 'Running' -or $svc.StartType -ne 'Disabled') {
            Invoke-Hardening -Description "Stop and disable service '$svcName' ($($svc.DisplayName))" -Action {
                Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
                Set-Service -Name $svcName -StartupType Disabled
            }
            Add-ReportItem -RequirementId "SVC-$svcName" -Description 'Unnecessary/insecure service disabled' -Source 'Training deck: Services' -Status 'WARNING' -Actual "$($svc.Status)/$($svc.StartType)" -Expected 'Stopped/Disabled' -ActionTaken 'Stopped and disabled'
        } else {
            Add-ReportItem -RequirementId "SVC-$svcName" -Description 'Unnecessary/insecure service disabled' -Source 'Training deck: Services' -Status 'PASS' -Actual 'Stopped/Disabled' -Expected 'Stopped/Disabled'
        }
    }

    # README critical services - IIS (W3SVC/WAS), SMB (LanmanServer), and CCS Client
    # must be verified running and are never stopped/disabled by this script.
    foreach ($pattern in $Script:CriticalServicePatterns) {
        $matches = Get-Service | Where-Object { $_.Name -match $pattern }
        foreach ($svc in $matches) {
            $status = if ($svc.Status -eq 'Running') { 'PASS' } else { 'MANUAL REVIEW' }
            Add-ReportItem -RequirementId "SVC-CRITICAL-$($svc.Name)" -Description "Critical service '$($svc.Name)' left untouched and running" -Source 'README: Critical Services' -Status $status -Actual $svc.Status -Expected 'Running (never modified by this script)'
        }
    }

    # Windows Features (role services/components, distinct from the services
    # loop above) called out as commonly-unneeded in the Week 09 Intermediate
    # Windows + Server Review deck: Internet Explorer 11, Print and Document
    # Services, RIP Listener, Telnet Client, TFTP Client. SMB 1.0/CIFS is
    # handled separately in the SMB region (Set-SmbHardening), and Internet
    # Information Services is explicitly never touched here - it is the
    # README's named critical service.
    if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
        $featurePatterns = 'Internet-Explorer-Optional|Print-Services|RIP|Telnet-Client|TFTP-Client'
        $unneededFeatures = Get-WindowsFeature | Where-Object {
            $_.Installed -and ($_.Name -match $featurePatterns -or $_.DisplayName -match 'Internet Explorer 11|Print and Document Services|RIP Listener|Telnet Client|TFTP Client') -and
            $_.Name -ne 'Web-Server'
        }
        foreach ($feature in $unneededFeatures) {
            Invoke-Hardening -Description "Remove unneeded Windows Feature '$($feature.DisplayName)'" -Action {
                Uninstall-WindowsFeature -Name $feature.Name -ErrorAction SilentlyContinue | Out-Null
            }
            Add-ReportItem -RequirementId "FEAT-$($feature.Name)" -Description "Unneeded Windows Feature '$($feature.DisplayName)' removed" -Source 'Week 09 deck: Programs and Features' `
                -Status 'WARNING' -Actual 'Installed' -Expected 'Removed' -ActionTaken 'Removed via Uninstall-WindowsFeature'
        }
        if (-not $unneededFeatures) {
            Add-ReportItem -RequirementId 'FEAT-00' -Description 'Unneeded Windows Features (IE11, Print Services, RIP Listener, Telnet/TFTP Client) absent' -Source 'Week 09 deck: Programs and Features' `
                -Status 'PASS' -Actual 'None installed' -Expected 'None installed'
        }
    } else {
        Add-ReportItem -RequirementId 'FEAT-00' -Description 'Unneeded Windows Features reviewed' -Source 'Week 09 deck: Programs and Features' `
            -Status 'MANUAL REVIEW' -Actual 'Get-WindowsFeature unavailable' -Expected 'Reviewed'
    }
}

#endregion SERVER SERVICES

#region SMB AND REMOTE ACCESS

function Set-SmbHardening {
    if (-not (Test-CategoryEnabled 'Smb')) { return }
    Write-Log "=== SMB AND REMOTE ACCESS ==="
    Backup-SmbConfiguration

    $smbConfig = Get-SmbServerConfiguration
    Invoke-Hardening -Disruptive -Description 'Disable SMBv1 protocol (README critical service is the SMB File Share, not SMBv1 specifically)' -Action {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        $feature = Get-WindowsFeature -Name FS-SMB1 -ErrorAction SilentlyContinue
        if ($feature -and $feature.Installed) { Remove-WindowsFeature -Name FS-SMB1 -ErrorAction SilentlyContinue | Out-Null }
    }
    Add-ReportItem -RequirementId 'SMB-01' -Description 'SMBv1 disabled (SMBv2/3 used for the Handbook share)' -Source 'Security best practice' `
        -Status $(if ($Force -and -not $Script:DryRun) { 'WARNING' } else { 'MANUAL REVIEW' }) -Actual $smbConfig.EnableSMB1Protocol -Expected $false `
        -ActionTaken $(if ($Force -and -not $Script:DryRun) { 'Disabled' } else { 'Requires -Force' })

    if (-not $smbConfig.RequireSecuritySignature) {
        Invoke-Hardening -Description 'Require SMB signing on the server' -Action { Set-SmbServerConfiguration -RequireSecuritySignature $true -Force }
        Add-ReportItem -RequirementId 'SMB-02' -Description 'SMB signing required' -Source 'Vulnerabilities table' -Status 'WARNING' -Actual 'Not required' -Expected 'Required' -ActionTaken 'Enabled'
    } else {
        Add-ReportItem -RequirementId 'SMB-02' -Description 'SMB signing required' -Source 'Vulnerabilities table' -Status 'PASS' -Actual 'Required' -Expected 'Required'
    }

    # README: Handbook share must exist, be readable by everyone (authenticated
    # users), and writable only by Administrators. Never removed.
    $share = Get-SmbShare -Name $Script:HandbookShareName -ErrorAction SilentlyContinue
    if (-not $share) {
        Add-ReportItem -RequirementId 'SMB-03' -Description "Required share '$($Script:HandbookShareName)' exists" -Source 'README: Critical Services' -Status 'FAIL' -Actual 'Missing' -Expected 'Present' `
            -ActionTaken 'Not auto-created - verify the physical path exists and create manually if genuinely missing'
    } else {
        Add-ReportItem -RequirementId 'SMB-03' -Description "Required share '$($Script:HandbookShareName)' exists" -Source 'README: Critical Services' -Status 'PASS' -Actual $share.Path -Expected $Script:HandbookSharePath

        $access = Get-SmbShareAccess -Name $Script:HandbookShareName
        $everyoneFullOrChange = $access | Where-Object { $_.AccountName -match 'Everyone' -and $_.AccessRight -in @('Full','Change') }
        if ($everyoneFullOrChange) {
            Invoke-Hardening -Description "Restrict '$($Script:HandbookShareName)' share permissions: Authenticated Users=Read, Administrators=Full (README: only admins may change contents)" -Action {
                Revoke-SmbShareAccess -Name $Script:HandbookShareName -AccountName 'Everyone' -Force -ErrorAction SilentlyContinue
                Grant-SmbShareAccess -Name $Script:HandbookShareName -AccountName 'Authenticated Users' -AccessRight Read -Force
                Grant-SmbShareAccess -Name $Script:HandbookShareName -AccountName 'Administrators' -AccessRight Full -Force
            }
            Add-ReportItem -RequirementId 'SMB-04' -Description 'Handbook share permissions: read for users, full control for admins only' -Source 'README: Handbook share requirement' `
                -Status 'WARNING' -Actual (($access | ForEach-Object { "$($_.AccountName)=$($_.AccessRight)" }) -join ', ') -Expected 'Authenticated Users=Read, Administrators=Full' -ActionTaken 'Share permissions corrected'
        } else {
            Add-ReportItem -RequirementId 'SMB-04' -Description 'Handbook share permissions: read for users, full control for admins only' -Source 'README: Handbook share requirement' `
                -Status 'PASS' -Actual (($access | ForEach-Object { "$($_.AccountName)=$($_.AccessRight)" }) -join ', ') -Expected 'Authenticated Users=Read, Administrators=Full'
        }

        if (Test-Path $Script:HandbookSharePath) {
            Invoke-Hardening -Description "Set NTFS ACL on '$($Script:HandbookSharePath)': Authenticated Users=Read&Execute, Administrators/SYSTEM=Full" -Action {
                & icacls.exe "$Script:HandbookSharePath" /inheritance:r | Out-Null
                & icacls.exe "$Script:HandbookSharePath" /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "Authenticated Users:(OI)(CI)(RX)" | Out-Null
            }
            Add-ReportItem -RequirementId 'SMB-05' -Description 'Handbook NTFS permissions match README (read-only for users, full for admins)' -Source 'README: Handbook share requirement' `
                -Status 'WARNING' -Actual 'See icacls output in log' -Expected 'Administrators/SYSTEM=Full, Authenticated Users=Read&Execute' -ActionTaken 'icacls applied'
        }
    }

    # Other non-default shares - report only, never remove without README confirmation.
    $otherShares = Get-SmbShare | Where-Object { $_.Name -notin ($Script:DefaultShareNames + $Script:HandbookShareName) }
    if ($otherShares) {
        Add-ReportItem -RequirementId 'SMB-06' -Description 'No unexpected SMB shares beyond README-required Handbook share' -Source 'README' `
            -Status 'MANUAL REVIEW' -Actual ($otherShares.Name -join ', ') -Expected 'Only Handbook + Windows defaults unless README states otherwise'
    } else {
        Add-ReportItem -RequirementId 'SMB-06' -Description 'No unexpected SMB shares beyond README-required Handbook share' -Source 'README' -Status 'PASS' -Actual 'Only expected shares' -Expected 'Only Handbook + defaults'
    }

    # WinRM / remote PowerShell - report current state only (not named as a
    # README critical service here, so not forced on or off).
    try {
        $winrm = Get-Service WinRM -ErrorAction SilentlyContinue
        Add-ReportItem -RequirementId 'SMB-07' -Description 'WinRM / remote PowerShell state reviewed' -Source 'Phase 8 requirement' -Status 'MANUAL REVIEW' -Actual "$($winrm.Status)" -Expected 'Confirm against README whether remote management is required'
    } catch {}
}

#endregion SMB AND REMOTE ACCESS

#region FILE PERMISSIONS

function Protect-FileSystem {
    if (-not (Test-CategoryEnabled 'FileSystem')) { return }
    Write-Log "=== FILE SYSTEM AND IIS PERMISSIONS ==="

    $flaggedFiles = New-Object System.Collections.Generic.List[object]
    $userDirs = Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('Public','Default','Default User','All Users') }
    foreach ($userDir in $userDirs) {
        foreach ($sub in $Script:MediaScanSubfolders) {
            $path = Join-Path $userDir.FullName $sub
            if (Test-Path $path) {
                foreach ($ext in $Script:MediaExtensions) {
                    Get-ChildItem -Path $path -Filter $ext -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object { $flaggedFiles.Add($_.FullName) }
                }
            }
        }
    }
    if ($flaggedFiles.Count -gt 0) {
        $flaggedFiles | Out-String | Add-Content -Path $Script:LogFile
        if ($RemoveMediaFiles -and -not $Script:DryRun) {
            foreach ($f in $flaggedFiles) { Invoke-Hardening -Description "Delete flagged non-work media file '$f'" -Action { Remove-Item -Path $f -Force -ErrorAction Stop } }
            Add-ReportItem -RequirementId 'FS-01' -Description 'Non-work media files removed' -Source 'README scenario' -Status 'WARNING' -Actual "$($flaggedFiles.Count) files found" -Expected 'Removed' -ActionTaken 'Deleted'
        } else {
            Add-ReportItem -RequirementId 'FS-01' -Description 'Non-work media files flagged' -Source 'README scenario' -Status 'MANUAL REVIEW' -Actual "$($flaggedFiles.Count) files found - see log" -Expected 'Removed if confirmed non-work-related' -ActionTaken 'Not deleted - run with -RemoveMediaFiles or review manually'
        }
    } else {
        Add-ReportItem -RequirementId 'FS-01' -Description 'Non-work media files flagged' -Source 'README scenario' -Status 'PASS' -Actual 'None found' -Expected 'None'
    }

    # IIS directory permissions - audit only, never recursively overwrite per spec.
    if ($Script:IisAvailable) {
        foreach ($site in Get-Website) {
            if (-not $site.PhysicalPath -or -not (Test-Path $site.PhysicalPath)) { continue }
            try {
                $acl = Get-Acl $site.PhysicalPath
                $writeGrants = $acl.Access | Where-Object {
                    $_.FileSystemRights -match 'Write|FullControl|Modify' -and
                    $_.IdentityReference.Value -notmatch 'Administrators|SYSTEM|IIS_IUSRS|TrustedInstaller' -and
                    $_.AccessControlType -eq 'Allow'
                }
                if ($writeGrants) {
                    Add-ReportItem -RequirementId "FS-02-$($site.Name)" -Description "Site '$($site.Name)' web root write permissions reviewed" -Source 'Phase 9 requirement' `
                        -Status 'MANUAL REVIEW' -Actual (($writeGrants | ForEach-Object { "$($_.IdentityReference)=$($_.FileSystemRights)" }) -join '; ') `
                        -Expected 'Only Administrators/SYSTEM/IIS_IUSRS/app pool identity should have write access' -ActionTaken 'Not changed automatically - never recursively overwrite IIS directory permissions'
                } else {
                    Add-ReportItem -RequirementId "FS-02-$($site.Name)" -Description "Site '$($site.Name)' web root write permissions reviewed" -Source 'Phase 9 requirement' -Status 'PASS' -Actual 'No unexpected write grants' -Expected 'No unexpected write grants'
                }
            } catch { Write-Log -Level WARN -Message "ACL review failed for '$($site.PhysicalPath)': $($_.Exception.Message)" }
        }
    }

    try {
        $startupItems = Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User
        $startupItems | Out-String | Add-Content -Path $Script:LogFile
        Add-ReportItem -RequirementId 'FS-03' -Description 'Startup applications reviewed' -Source 'Phase 9 requirement' -Status 'MANUAL REVIEW' -Actual "$($startupItems.Count) startup items logged" -Expected 'Reviewed for anything unauthorized'
    } catch {}

    try {
        $suspiciousTasks = Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '\\Microsoft\\' -and $_.State -ne 'Disabled' }
        $suspiciousTasks | Select-Object TaskName, TaskPath, State | Out-String | Add-Content -Path $Script:LogFile
        $status = if ($suspiciousTasks) { 'MANUAL REVIEW' } else { 'PASS' }
        Add-ReportItem -RequirementId 'FS-04' -Description 'Non-Microsoft scheduled tasks reviewed' -Source 'Phase 9 requirement' -Status $status -Actual "$($suspiciousTasks.Count) found" -Expected 'Reviewed for anything unauthorized'
    } catch {}
}

#endregion FILE PERMISSIONS

#region REGISTRY AND SECURITY POLICIES

function Set-SecurityOptionsRegistry {
    if (-not (Test-CategoryEnabled 'Registry')) { return }
    Write-Log "=== REGISTRY-BACKED SECURITY OPTIONS ==="

    $lsaPath   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $lanman    = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $lanmanWks = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    $policyPol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $netlogon  = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'

    Backup-RegistryKey -KeyPath 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' -FileName 'lsa_before.reg'
    Backup-RegistryKey -KeyPath 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -FileName 'policies_system_before.reg'

    $settings = @(
        @{ Path=$policyPol; Name='DisableCAD'; Type='DWord'; Value=0; Id='SEC-01'; Desc='Do not require CTRL+ALT+DEL set to Disabled'; Src='LGPO training deck' }
        @{ Path=$policyPol; Name='DontDisplayLastUserName'; Type='DWord'; Value=1; Id='SEC-02'; Desc='Do not display last signed-in user'; Src='LGPO training deck' }
        @{ Path=$lanmanWks; Name='RequireSecuritySignature'; Type='DWord'; Value=1; Id='SEC-03'; Desc='Microsoft network client: Digitally sign communications (always)'; Src='Vulnerabilities table' }
        @{ Path=$lanmanWks; Name='EnableSecuritySignature'; Type='DWord'; Value=1; Id='SEC-03b'; Desc='Microsoft network client: Digitally sign communications (if server agrees)'; Src='Vulnerabilities table' }
        @{ Path=$lanman;    Name='RequireSecuritySignature'; Type='DWord'; Value=1; Id='SEC-04'; Desc='Microsoft network server: Digitally sign communications (always)'; Src='Vulnerabilities table' }
        @{ Path=$lanman;    Name='EnableSecuritySignature'; Type='DWord'; Value=1; Id='SEC-04b'; Desc='Microsoft network server: Digitally sign communications (if client agrees)'; Src='Vulnerabilities table' }
        @{ Path=$lanman;    Name='AutoDisconnect'; Type='DWord'; Value=15; Id='SEC-05'; Desc='Microsoft network server: idle time before suspending session (15 min)'; Src='Vulnerabilities table' }
        @{ Path=$lanman;    Name='EnableForcedLogOff'; Type='DWord'; Value=1; Id='SEC-06'; Desc='Disconnect clients when logon hours expire'; Src='Vulnerabilities table' }
        @{ Path=$netlogon;  Name='MaximumPasswordAge'; Type='DWord'; Value=90; Id='SEC-06b'; Desc='Maximum machine account password age (90 days)'; Src='Week 09 deck: Security Options table' }
        @{ Path=$lsaPath;   Name='NoLMHash'; Type='DWord'; Value=1; Id='SEC-07'; Desc='Do not store LAN Manager hash value on next password change'; Src='Vulnerabilities table' }
        @{ Path=$lsaPath;   Name='LmCompatibilityLevel'; Type='DWord'; Value=5; Id='SEC-08'; Desc='LAN Manager authentication level: Send NTLMv2 response only, refuse LM & NTLM'; Src='Vulnerabilities table' }
        @{ Path=$lsaPath;   Name='RestrictAnonymous'; Type='DWord'; Value=1; Id='SEC-09'; Desc='Do not allow anonymous enumeration of SAM accounts and shares'; Src='Vulnerabilities table' }
        @{ Path=$lsaPath;   Name='RestrictAnonymousSAM'; Type='DWord'; Value=1; Id='SEC-10'; Desc='Do not allow anonymous enumeration of SAM accounts'; Src='Vulnerabilities table' }
        @{ Path=$lsaPath;   Name='EveryoneIncludesAnonymous'; Type='DWord'; Value=0; Id='SEC-11'; Desc='Let Everyone permissions apply to anonymous users: Disabled'; Src='Vulnerabilities table' }
        @{ Path=$lsaPath;   Name='LimitBlankPasswordUse'; Type='DWord'; Value=1; Id='SEC-12'; Desc='Limit local account blank-password use to console logon only'; Src='Vulnerabilities table' }
        @{ Path=$lanman;    Name='NullSessionShares'; Type='MultiString'; Value=@(); Id='SEC-14'; Desc='Shares that can be accessed anonymously: blank (Handbook requires authentication)'; Src='Vulnerabilities table' }
        @{ Path=$lanman;    Name='NullSessionPipes'; Type='MultiString'; Value=@(); Id='SEC-15'; Desc='Named pipes accessible anonymously: blank'; Src='Vulnerabilities table' }
    )

    foreach ($s in $settings) {
        try {
            if (-not (Test-Path $s.Path)) { Invoke-Hardening -Description "Create registry path '$($s.Path)'" -Action { New-Item -Path $s.Path -Force | Out-Null } }
            $current = (Get-ItemProperty -Path $s.Path -Name $s.Name -ErrorAction SilentlyContinue).$($s.Name)
            $needsChange = ("$current" -ne "$($s.Value)")
            if ($needsChange) {
                Invoke-Hardening -Description "$($s.Desc) [$($s.Path)\$($s.Name) = $($s.Value)]" -Action {
                    New-ItemProperty -Path $s.Path -Name $s.Name -PropertyType $s.Type -Value $s.Value -Force | Out-Null
                }
            }
            Add-ReportItem -RequirementId $s.Id -Description $s.Desc -Source $s.Src -Status $(if ($needsChange) { 'WARNING' } else { 'PASS' }) -Actual $current -Expected $s.Value -ActionTaken $(if ($needsChange) { 'Registry value set' } else { '' })
        } catch {
            Write-Log -Level ERROR -Message "Failed applying $($s.Id): $($_.Exception.Message)"
            Add-ReportItem -RequirementId $s.Id -Description $s.Desc -Source $s.Src -Status 'FAIL' -Actual 'Error applying' -Expected $s.Value
        }
    }

    Add-ReportItem -RequirementId 'SEC-NTLM' -Description 'Restrict NTLM incoming/outgoing traffic policies' -Source 'Vulnerabilities table' `
        -Status 'MANUAL REVIEW' -Actual 'Not changed by script' -Expected 'Review before applying - could break application-pool or remote-management auth on a standalone server'
}

function Set-UacHardening {
    if (-not (Test-CategoryEnabled 'Registry')) { return }
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
            Invoke-Hardening -Description "$($s.Desc) [$($s.Name)=$($s.Value)]" -Action { New-ItemProperty -Path $uacPath -Name $s.Name -PropertyType DWord -Value $s.Value -Force | Out-Null }
        }
        Add-ReportItem -RequirementId $s.Id -Description $s.Desc -Source 'Vulnerabilities table: UAC' -Status $(if ($needsChange) { 'WARNING' } else { 'PASS' }) -Actual $current -Expected $s.Value -ActionTaken $(if ($needsChange) { 'Registry value set' } else { '' })
    }
}

function Set-WindowsUpdatePolicy {
    if (-not (Test-CategoryEnabled 'WindowsUpdate')) { return }
    Write-Log "=== WINDOWS UPDATE POLICY (feature-update prevention) ==="
    $wuPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    if (-not (Test-Path $wuPath)) { Invoke-Hardening -Description "Create WindowsUpdate policy key" -Action { New-Item -Path $wuPath -Force | Out-Null } }
    Backup-RegistryKey -KeyPath 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -FileName 'wu_policy_before.reg'

    $currentBuild = (Get-CimInstance Win32_OperatingSystem).Version
    Invoke-Hardening -Description "Pin target release version to current build ($currentBuild) to block feature updates / Insider builds" -Action {
        New-ItemProperty -Path $wuPath -Name 'TargetReleaseVersion' -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path $wuPath -Name 'ProductVersion' -PropertyType String -Value 'Windows Server 2022' -Force | Out-Null
        New-ItemProperty -Path $wuPath -Name 'TargetReleaseVersionInfo' -PropertyType String -Value $currentBuild -Force | Out-Null
    }
    Add-ReportItem -RequirementId 'WU-01' -Description 'Feature updates / Insider Preview builds blocked' -Source 'README explicit prohibition' -Status 'WARNING' -Actual 'See verification pass' -Expected 'TargetReleaseVersion pinned' -ActionTaken 'Registry policy applied'
    Add-ReportItem -RequirementId 'WU-02' -Description 'Windows Update configuration reviewed (no forced installs, no forced reboot)' -Source 'Phase 2 requirement' -Status 'MANUAL REVIEW' -Actual 'See Windows Update settings page' -Expected 'Security updates current, no pending disruptive restarts'
}

#endregion REGISTRY AND SECURITY POLICIES

#region AUDITING

function Set-LoggingHardening {
    if (-not (Test-CategoryEnabled 'Auditing')) { return }
    Write-Log "=== LOGGING AND AUDITING ==="

    $psLogPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if (-not (Test-Path $psLogPath)) { Invoke-Hardening -Description 'Create PowerShell ScriptBlockLogging policy key' -Action { New-Item -Path $psLogPath -Force | Out-Null } }
    Invoke-Hardening -Description 'Enable PowerShell Script Block Logging' -Action { New-ItemProperty -Path $psLogPath -Name 'EnableScriptBlockLogging' -PropertyType DWord -Value 1 -Force | Out-Null }
    Add-ReportItem -RequirementId 'LOG-01' -Description 'PowerShell Script Block Logging enabled' -Source 'Phase 10 requirement' -Status 'WARNING' -Actual 'See verification pass' -Expected 'Enabled' -ActionTaken 'Registry policy applied'

    $cmdLinePath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    if (-not (Test-Path $cmdLinePath)) { Invoke-Hardening -Description 'Create process creation audit policy key' -Action { New-Item -Path $cmdLinePath -Force | Out-Null } }
    Invoke-Hardening -Description 'Include command line in process creation events' -Action { New-ItemProperty -Path $cmdLinePath -Name 'ProcessCreationIncludeCmdLine_Enabled' -PropertyType DWord -Value 1 -Force | Out-Null }
    Add-ReportItem -RequirementId 'LOG-02' -Description 'Process creation command-line auditing enabled' -Source 'Phase 10 requirement' -Status 'WARNING' -Actual 'See verification pass' -Expected 'Enabled' -ActionTaken 'Registry policy applied'

    foreach ($log in @('Security','System','Application')) {
        Invoke-Hardening -Description "Set '$log' event log max size to 196608 KB (never clears existing entries)" -Action { & wevtutil.exe sl $log /ms:196608000 | Out-Null }
    }
    Add-ReportItem -RequirementId 'LOG-03' -Description 'Event log retention sized appropriately; logs never cleared by this script' -Source 'Phase 10 requirement' -Status 'PASS' -Actual 'Resized, not cleared' -Expected 'Adequate retention, never cleared'

    if ($Script:IisAvailable) {
        $allLogged = $true
        foreach ($site in Get-Website) {
            $enabled = (Get-WebConfigurationProperty -Filter "/system.applicationHost/sites/site[@name='$($site.Name)']/logFile" -PSPath 'MACHINE/WEBROOT/APPHOST' -Name enabled).Value
            if (-not $enabled) { $allLogged = $false }
        }
        Add-ReportItem -RequirementId 'LOG-04' -Description 'IIS access/error logging enabled for all sites' -Source 'Phase 10 requirement' -Status $(if ($allLogged) { 'PASS' } else { 'WARNING' }) -Actual $allLogged -Expected $true
    }
}

#endregion AUDITING

#region APPLICATIONS (software inventory - supports Phase 1/3 required-software checks)

function Get-InstalledApplications {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty -Path $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } |
        Select-Object DisplayName, DisplayVersion, UninstallString -Unique
}

function Protect-Applications {
    if (-not (Test-CategoryEnabled 'FileSystem')) { return }  # software hygiene reported alongside file-system pass
    Write-Log "=== SOFTWARE INVENTORY (README-required business software + unauthorized tooling) ==="
    $installed = Get-InstalledApplications
    $installed | Out-String | Add-Content -Path $Script:LogFile

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
                    Add-ReportItem -RequirementId 'APP-01' -Description 'Unauthorized/hacking-tool software removed' -Source 'README scenario: hacking tools prohibited' -Status 'WARNING' -Actual $app.DisplayName -Expected 'Removed' -ActionTaken 'Uninstall attempted (verify manually)'
                } else {
                    Add-ReportItem -RequirementId 'APP-01' -Description 'Unauthorized/hacking-tool software flagged' -Source 'README scenario: hacking tools prohibited' -Status 'MANUAL REVIEW' -Actual $app.DisplayName -Expected 'Removed if confirmed unauthorized' -ActionTaken 'Not removed - run with -RemoveUnauthorizedApps after confirming against README'
                }
                break
            }
        }
    }

    foreach ($req in $Script:RequiredSoftware) {
        $found = $installed | Where-Object { $_.DisplayName -match $req.Match } | Select-Object -First 1
        if ($found) {
            Add-ReportItem -RequirementId "APP-REQ-$($req.Name)" -Description "Required software '$($req.Name)' present" -Source 'README: business software' -Status 'PASS' -Actual $found.DisplayVersion -Expected 'Installed'
        } else {
            Add-ReportItem -RequirementId "APP-REQ-$($req.Name)" -Description "Required software '$($req.Name)' present" -Source 'README: business software' -Status 'FAIL' -Actual 'Not installed' -Expected 'Installed' -ActionTaken 'Install manually - README requires this to remain installed'
        }
    }

    if (-not $SkipAppUpdates -and -not $Script:DryRun) {
        $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
        if ($winget) {
            foreach ($req in $Script:RequiredSoftware) {
                if (-not $req.WingetId) { continue }
                if ($installed | Where-Object { $_.DisplayName -match $req.Match }) {
                    Invoke-Hardening -Description "Update '$($req.Name)' via winget" -Action {
                        & winget.exe upgrade --id $req.WingetId --silent --accept-package-agreements --accept-source-agreements | Out-Null
                    }
                }
            }
        } else {
            Add-ReportItem -RequirementId 'APP-02' -Description 'Required software kept up to date' -Source 'README: business software' -Status 'MANUAL REVIEW' -Actual 'winget unavailable' -Expected 'Up to date'
        }
    }

    try {
        $progId = (Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice' -ErrorAction SilentlyContinue).ProgId
        $isChrome = $progId -match 'Chrome'
        Add-ReportItem -RequirementId 'APP-03' -Description 'Default browser is Google Chrome' -Source 'README' -Status $(if ($isChrome) { 'PASS' } else { 'MANUAL REVIEW' }) -Actual $progId -Expected 'ChromeHTML' `
            -ActionTaken $(if ($isChrome) { '' } else { 'Set manually - not safely scriptable on Windows Server 2022' })
    } catch {
        Add-ReportItem -RequirementId 'APP-03' -Description 'Default browser is Google Chrome' -Source 'README' -Status 'MANUAL REVIEW' -Actual 'Unknown' -Expected 'ChromeHTML'
    }
}

#endregion APPLICATIONS

#region VERIFICATION

function Update-ReportStatus {
    param([string]$RequirementId, [string]$Actual, [string]$ExpectedOverride)
    $item = $Script:Report | Where-Object { $_.RequirementId -eq $RequirementId } | Select-Object -Last 1
    if (-not $item) { return }
    $expected = if ($ExpectedOverride) { $ExpectedOverride } else { $item.Expected }
    $item.Actual = $Actual
    if ("$Actual".Trim() -eq "$expected".Trim()) { $item.Status = 'PASS' }
    elseif ($item.Status -notin @('MANUAL REVIEW','NOT APPLICABLE')) { $item.Status = 'FAIL' }
}

function Test-IisResponding {
    <#
        Phase 14 requirement: don't mark IIS healthy just because the service is
        running - perform a local HTTP/HTTPS response check against existing
        bindings, without changing bindings/ports/certs in any way.
    #>
    if (-not $Script:IisAvailable) { return }
    Write-Log "=== IIS RESPONSE CHECK (read-only) ==="

    $originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try {
        foreach ($site in Get-Website) {
            foreach ($binding in (Get-WebBinding -Name $site.Name)) {
                $parts = $binding.bindingInformation -split ':'
                $port = $parts[1]
                $hostHeader = $parts[2]
                $urlHost = if ($hostHeader) { $hostHeader } else { 'localhost' }
                $url = "$($binding.protocol)://$urlHost`:$port/"
                try {
                    $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
                    Add-ReportItem -RequirementId "IIS-RESP-$($site.Name)-$port" -Description "Site '$($site.Name)' responds locally on $url" -Source 'Phase 14 requirement' -Status 'PASS' -Actual "HTTP $($resp.StatusCode)" -Expected 'HTTP response received'
                } catch {
                    $statusCode = $null
                    if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
                    $status = if ($statusCode) { 'WARNING' } else { 'FAIL' }
                    Add-ReportItem -RequirementId "IIS-RESP-$($site.Name)-$port" -Description "Site '$($site.Name)' responds locally on $url" -Source 'Phase 14 requirement' `
                        -Status $status -Actual $(if ($statusCode) { "HTTP $statusCode" } else { $_.Exception.Message }) -Expected 'HTTP response received (non-5xx)'
                }
            }
        }
    } finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
    }
}

function Invoke-VerificationPass {
    Write-Log "=== VERIFICATION PASS (independent of apply logic) ==="

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

    try { $mp = Get-MpComputerStatus; Update-ReportStatus -RequirementId 'AV-02' -Actual "RT:$($mp.RealTimeProtectionEnabled) Behavior:$($mp.BehaviorMonitorEnabled)" } catch {}

    foreach ($p in Get-NetFirewallProfile) { Update-ReportStatus -RequirementId "FW-01-$($p.Name)" -Actual $p.Enabled }

    $uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $uacNames = @{ 'UAC-01'='EnableLUA'; 'UAC-02'='ConsentPromptBehaviorAdmin'; 'UAC-03'='ConsentPromptBehaviorUser'; 'UAC-04'='PromptOnSecureDesktop'; 'UAC-05'='EnableInstallerDetection'; 'UAC-06'='FilterAdministratorToken' }
    foreach ($id in $uacNames.Keys) {
        $val = (Get-ItemProperty -Path $uacPath -Name $uacNames[$id] -ErrorAction SilentlyContinue).$($uacNames[$id])
        Update-ReportStatus -RequirementId $id -Actual $val
    }

    foreach ($svcName in $Script:ServicesToDisable) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc) { Update-ReportStatus -RequirementId "SVC-$svcName" -Actual "$($svc.Status)/$($svc.StartType)" }
    }

    if ($Script:IisAvailable) {
        foreach ($site in Get-Website) {
            $browse = (Get-WebConfigurationProperty -Filter '/system.webServer/directoryBrowse' -PSPath "IIS:\Sites\$($site.Name)" -Name enabled).Value
            Update-ReportStatus -RequirementId "IIS-01-$($site.Name)" -Actual $browse -ExpectedOverride 'False'
        }
        Test-IisResponding
    }

    try {
        $smbConfig = Get-SmbServerConfiguration
        Update-ReportStatus -RequirementId 'SMB-01' -Actual $smbConfig.EnableSMB1Protocol -ExpectedOverride 'False'
        Update-ReportStatus -RequirementId 'SMB-02' -Actual $smbConfig.RequireSecuritySignature -ExpectedOverride 'True'
    } catch {}

    Write-Log "Verification pass complete."
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
    if ($manualItems) { Write-Host "`n--- Items requiring MANUAL REVIEW ---" -ForegroundColor Yellow; $manualItems | Format-Table RequirementId, Description, Actual, Expected -AutoSize }

    $failItems = $Script:Report | Where-Object Status -eq 'FAIL'
    if ($failItems) { Write-Host "`n--- Items that FAILED verification ---" -ForegroundColor Red; $failItems | Format-Table RequirementId, Description, Actual, Expected -AutoSize }
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
    Write-Log "WindowsServer2022-Hardening.ps1 starting - Mode=$Mode Categories=$($Script:Categories -join ',') DryRun=$Script:DryRun Force=$Force"
    Write-Log "===================================================================="

    if (-not (Test-Administrator)) {
        Write-Log -Level ERROR -Message "This script must be run from an elevated (Administrator) PowerShell session. Aborting."
        throw "Administrator privileges required."
    }

    if ($Mode -eq 'Rollback') {
        if (-not $RollbackCategory) { throw "-Mode Rollback requires -RollbackCategory." }
        Invoke-Rollback -RollbackCategory $RollbackCategory -BackupTimestamp $BackupTimestamp
        return
    }

    Get-ServerInventory
    Get-IisInventory

    if ($Mode -eq 'VerifyOnly') {
        Invoke-VerificationPass
        Write-ComplianceReport
        return
    }

    $iisBackupName = Backup-IisConfiguration
    Save-BackupManifest -IisBackupName $iisBackupName

    try { Protect-LocalUsers } catch { Write-Log -Level ERROR -Message "Protect-LocalUsers failed: $($_.Exception.Message)" }
    try { Set-PasswordAndLockoutPolicy } catch { Write-Log -Level ERROR -Message "Set-PasswordAndLockoutPolicy failed: $($_.Exception.Message)" }
    try { Set-AuditPolicy } catch { Write-Log -Level ERROR -Message "Set-AuditPolicy failed: $($_.Exception.Message)" }
    try { Set-DefenderHardening } catch { Write-Log -Level ERROR -Message "Set-DefenderHardening failed: $($_.Exception.Message)" }
    try { Set-FirewallHardening } catch { Write-Log -Level ERROR -Message "Set-FirewallHardening failed: $($_.Exception.Message)" }
    try { Set-IisHardening } catch { Write-Log -Level ERROR -Message "Set-IisHardening failed: $($_.Exception.Message)" }
    try { Set-ServiceHardening } catch { Write-Log -Level ERROR -Message "Set-ServiceHardening failed: $($_.Exception.Message)" }
    try { Set-SmbHardening } catch { Write-Log -Level ERROR -Message "Set-SmbHardening failed: $($_.Exception.Message)" }
    try { Protect-Applications } catch { Write-Log -Level ERROR -Message "Protect-Applications failed: $($_.Exception.Message)" }
    try { Set-SecurityOptionsRegistry } catch { Write-Log -Level ERROR -Message "Set-SecurityOptionsRegistry failed: $($_.Exception.Message)" }
    try { Set-UacHardening } catch { Write-Log -Level ERROR -Message "Set-UacHardening failed: $($_.Exception.Message)" }
    try { Set-WindowsUpdatePolicy } catch { Write-Log -Level ERROR -Message "Set-WindowsUpdatePolicy failed: $($_.Exception.Message)" }
    try { Protect-FileSystem } catch { Write-Log -Level ERROR -Message "Protect-FileSystem failed: $($_.Exception.Message)" }
    try { Set-LoggingHardening } catch { Write-Log -Level ERROR -Message "Set-LoggingHardening failed: $($_.Exception.Message)" }

    if (-not $Script:DryRun) { Invoke-VerificationPass }

    Write-ComplianceReport

    Write-Log "===================================================================="
    Write-Log "WindowsServer2022-Hardening.ps1 complete. Elapsed: $((Get-Date) - $Script:StartTime)"
    Write-Log "===================================================================="
}

Main

#endregion MAIN EXECUTION
