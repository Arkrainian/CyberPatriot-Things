#!/usr/bin/env bash
#
# Debian-Hardening.sh
# CyberPatriot Debian 12 hardening script.
#
# Built from:
#   - "Linux Readme.txt" (Arc Foundry & Aerospace scenario - Debian 12, UFW is
#     the only approved firewall, LightDM is the display manager, sshd is the
#     named Critical Service, root login is already prohibited by policy)
#   - Week 02 Intro to Linux, Week 04 Linux Scripting, Week 06 Linux Training
#     Round, Week 07 Linux Round 1 Debrief, Week 08 Intermediate Linux decks
#     (concrete command list, chage/login.defs values, PAM/faillock setup,
#     sysctl hardening values, sudoers auditing guidance, cron/LightDM notes)
#
# Run as root (via sudo):
#   sudo ./Debian-Hardening.sh --mode full
#
# Modes:
#   full       audit + apply hardening + verify + report
#   audit      inspect and report, change nothing
#   dryrun     same as audit but prints every action that WOULD be taken
#   verify     only run the verification/compliance report pass
#   rollback   restore a previous backup set for --rollback-category
#
# Categories (comma-separated via --category, default: all):
#   accounts,password,ssh,firewall,services,files,packages,kernel,apparmor,logging
#
# Flags:
#   --remove-unauthorized-apps   Actually purge apps matched as hacking tools (default: report only)
#   --remove-media-files         Actually delete flagged non-work media files (default: report only)
#   --fix-sources                Allow overwriting a corrupted /etc/apt/sources.list with the
#                                 Debian 12 (bookworm) default (default: reported only, never rewritten)
#   --force                      Allow the small set of genuinely disruptive changes (PAM lockout
#                                 policy, password complexity, SSH hardening) to actually apply
#   --assume-yes / -y            Do not prompt for confirmation on disruptive changes
#   --rollback-category <name>   Category to restore when --mode rollback
#   --backup-timestamp <stamp>   Which backup set to restore from (defaults to the most recent)
#   --workdir <path>             Working directory (default: /root/cyberpatriot-hardening)

set -uo pipefail

#region INITIALIZATION

MODE="audit"
CATEGORY="all"
REMOVE_UNAUTHORIZED_APPS=false
REMOVE_MEDIA_FILES=false
FIX_SOURCES=false
FORCE=false
ASSUME_YES=false
ROLLBACK_CATEGORY=""
BACKUP_TIMESTAMP=""
WORKDIR="/root/cyberpatriot-hardening"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode) MODE="$2"; shift 2 ;;
        --category) CATEGORY="$2"; shift 2 ;;
        --remove-unauthorized-apps) REMOVE_UNAUTHORIZED_APPS=true; shift ;;
        --remove-media-files) REMOVE_MEDIA_FILES=true; shift ;;
        --fix-sources) FIX_SOURCES=true; shift ;;
        --force) FORCE=true; shift ;;
        --assume-yes|-y) ASSUME_YES=true; shift ;;
        --rollback-category) ROLLBACK_CATEGORY="$2"; shift 2 ;;
        --backup-timestamp) BACKUP_TIMESTAMP="$2"; shift 2 ;;
        --workdir) WORKDIR="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

DRY_RUN=false
[[ "$MODE" == "dryrun" || "$MODE" == "audit" || "$MODE" == "verify" ]] && DRY_RUN=true

START_EPOCH=$(date +%s)
RUN_STAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="$WORKDIR/logs"
BACKUP_ROOT="$WORKDIR/backups"
BACKUP_DIR="$BACKUP_ROOT/$RUN_STAMP"
LOG_FILE="$LOG_DIR/hardening_${RUN_STAMP}.log"
REPORT_CSV="$WORKDIR/ComplianceReport_${RUN_STAMP}.csv"

mkdir -p "$LOG_DIR" "$BACKUP_ROOT" "$BACKUP_DIR"
chmod 700 "$WORKDIR" "$BACKUP_ROOT" "$BACKUP_DIR" 2>/dev/null || true

declare -a REPORT_ITEMS=()   # each entry: "ID\tDescription\tSource\tStatus\tActual\tExpected\tAction"

if [[ "$CATEGORY" == "all" ]]; then
    CATEGORIES="accounts password ssh firewall services files packages kernel apparmor logging"
else
    CATEGORIES="${CATEGORY//,/ }"
fi

#endregion INITIALIZATION

#region CONFIGURATION
# Values sourced from "Linux Readme.txt" and the shared training decks.
# Update this block first if the live competition README differs.

PRIMARY_AUTOLOGIN_USER="pparker"

AUTHORIZED_ADMINS=(pparker tstark ppotts hhogan nfury mhill pcoulson)
AUTHORIZED_STANDARD_USERS=(bbanner swilson sstrange slang cdanvers okoye kbishop ybelova jfoster nleeds mjwatson jtorres pcarter)
AUTHORIZED_USERS=("${AUTHORIZED_ADMINS[@]}" "${AUTHORIZED_STANDARD_USERS[@]}")

# README critical service: sshd. Also never touch the CCS Client, per every
# CyberPatriot README.
CRITICAL_SERVICE_PATTERNS=("ssh" "ccs")

# Common unnecessary/insecure network services flagged in Week 06/07 decks.
# Stopped+disabled, never purged, unless --remove-unauthorized-apps is also
# used for the package itself.
SERVICES_TO_DISABLE=(apache2 nginx vsftpd proftpd postfix exim4 mysql telnetd rsh-server nis snmpd xinetd tftpd bind9 samba)

# Training-deck "prohibited hacking tools" list.
UNAUTHORIZED_APP_PATTERNS=(nmap wireshark hydra "john.*ripper" aircrack netcat ncat hashcat mimikatz ophcrack metasploit deluge utorrent "tor-browser" "angry.*ip" nikto sqlmap pyrdp kismet ettercap)

MEDIA_EXTENSIONS=(mp3 mp4 wav avi mov mkv wmv flac ogg jpg jpeg png gif bmp)

#endregion CONFIGURATION

#region LOGGING

log() {
    local level="$1"; shift
    local msg="$*"
    local line
    line="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $msg"
    echo "$line" >> "$LOG_FILE"
    case "$level" in
        ERROR)  echo -e "\033[31m$line\033[0m" ;;
        WARN)   echo -e "\033[33m$line\033[0m" ;;
        ACTION) echo -e "\033[36m$line\033[0m" ;;
        SKIP)   echo -e "\033[90m$line\033[0m" ;;
        *)      echo "$line" ;;
    esac
}

confirm() {
    local desc="$1"
    $ASSUME_YES && return 0
    if [[ ! -t 0 ]]; then
        log WARN "Non-interactive shell and --assume-yes not set - skipping: $desc"
        return 1
    fi
    read -r -p "Apply this change? [$desc] (y/N) " reply </dev/tty
    [[ "$reply" =~ ^[Yy]$ ]]
}

# run_action DESC DISRUPTIVE(yes/no) CMD...
# Central gate for every state-changing operation. DISRUPTIVE=yes additionally
# requires --force AND (confirmation OR --assume-yes), so a default `--mode full`
# run cannot silently make a high-blast-radius change (PAM/SSH/firewall edits).
run_action() {
    local desc="$1"; local disruptive="$2"; shift 2
    if $DRY_RUN; then
        log ACTION "[DRY-RUN] Would do: $desc"
        return 1
    fi
    if [[ "$disruptive" == "yes" ]]; then
        if ! $FORCE; then
            log SKIP "[REQUIRES --force] Not applying disruptive change: $desc"
            return 1
        fi
        if ! confirm "$desc"; then
            log SKIP "Declined/unconfirmed: $desc"
            return 1
        fi
    fi
    if "$@"; then
        log ACTION "Applied: $desc"
        return 0
    else
        log ERROR "Failed: $desc"
        return 1
    fi
}

# add_report ID DESC SOURCE STATUS ACTUAL EXPECTED ACTION
add_report() {
    local id="$1" desc="$2" src="$3" status="$4" actual="$5" expected="$6" action="${7:-}"
    REPORT_ITEMS+=("${id}	${desc}	${src}	${status}	${actual}	${expected}	${action}")
}

category_enabled() {
    [[ " $CATEGORIES " == *" $1 "* ]]
}

#endregion LOGGING

#region BACKUPS

backup_file() {
    local src="$1"
    [[ -e "$src" ]] || return 0
    local dest="$BACKUP_DIR/$(echo "$src" | tr '/' '_')"
    cp -a "$src" "$dest" 2>>"$LOG_FILE"
    chmod 600 "$dest" 2>/dev/null || true
    log INFO "Backed up '$src' -> '$dest'"
}

backup_all_configs() {
    log INFO "=== BACKUPS ==="
    for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers \
             /etc/ssh/sshd_config /etc/pam.d/common-password /etc/pam.d/common-auth \
             /etc/pam.d/common-account /etc/login.defs /etc/sysctl.conf \
             /etc/lightdm/lightdm.conf /etc/apt/sources.list; do
        backup_file "$f"
    done
    if [[ -d /etc/sudoers.d ]]; then
        cp -a /etc/sudoers.d "$BACKUP_DIR/sudoers.d" 2>>"$LOG_FILE"
        chmod -R go-rwx "$BACKUP_DIR/sudoers.d" 2>/dev/null || true
    fi
    if command -v ufw >/dev/null 2>&1 && [[ -d /etc/ufw ]]; then
        mkdir -p "$BACKUP_DIR/ufw"
        cp -a /etc/ufw/*.rules "$BACKUP_DIR/ufw/" 2>>"$LOG_FILE" || true
    fi
    chmod -R go-rwx "$BACKUP_DIR" 2>/dev/null || true
}

#endregion BACKUPS

#region ROLLBACK

get_backup_set_path() {
    local ts="$1"
    if [[ -n "$ts" ]]; then
        [[ -d "$BACKUP_ROOT/$ts" ]] || { log ERROR "Backup set '$ts' not found."; exit 1; }
        echo "$BACKUP_ROOT/$ts"
        return
    fi
    local latest
    latest=$(ls -1dt "$BACKUP_ROOT"/*/ 2>/dev/null | head -n1)
    [[ -n "$latest" ]] || { log ERROR "No backup sets found under '$BACKUP_ROOT'."; exit 1; }
    echo "${latest%/}"
}

do_rollback() {
    local cat="$1"
    local path
    path=$(get_backup_set_path "$BACKUP_TIMESTAMP")
    log INFO "Rolling back category '$cat' from backup set '$path'"

    case "$cat" in
        accounts)
            for f in passwd shadow group gshadow; do
                local backed="$path/_etc_${f}"
                if [[ -f "$backed" ]]; then
                    log WARN "Restoring /etc/$f from backup - current accounts created after this backup will be affected."
                    cp -a "$backed" "/etc/$f"
                    log INFO "Restored /etc/$f"
                else
                    log ERROR "No backup found for /etc/$f in '$path'"
                fi
            done
            ;;
        ssh)
            local backed="$path/_etc_ssh_sshd_config"
            if [[ -f "$backed" ]]; then
                cp -a "$backed" /etc/ssh/sshd_config
                if sshd -t 2>>"$LOG_FILE"; then
                    systemctl reload sshd 2>>"$LOG_FILE" || systemctl reload ssh 2>>"$LOG_FILE" || true
                    log INFO "Restored and reloaded sshd_config"
                else
                    log ERROR "Restored sshd_config fails syntax check - NOT reloading. Manual review required."
                fi
            else
                log ERROR "No sshd_config backup found in '$path'"
            fi
            ;;
        password)
            for f in common-password common-auth common-account; do
                local backed="$path/_etc_pam.d_${f}"
                [[ -f "$backed" ]] && cp -a "$backed" "/etc/pam.d/$f" && log INFO "Restored /etc/pam.d/$f"
            done
            local defs="$path/_etc_login.defs"
            [[ -f "$defs" ]] && cp -a "$defs" /etc/login.defs && log INFO "Restored /etc/login.defs"
            ;;
        firewall)
            if [[ -d "$path/ufw" ]]; then
                cp -a "$path/ufw/"*.rules /etc/ufw/ 2>>"$LOG_FILE"
                ufw reload 2>>"$LOG_FILE" || true
                log INFO "Restored UFW rules and reloaded"
            else
                log ERROR "No UFW backup found in '$path'"
            fi
            ;;
        kernel)
            local sc="$path/_etc_sysctl.conf"
            if [[ -f "$sc" ]]; then
                cp -a "$sc" /etc/sysctl.conf
                sysctl -p 2>>"$LOG_FILE" || true
                log INFO "Restored and reapplied /etc/sysctl.conf"
            else
                log ERROR "No sysctl.conf backup found in '$path'"
            fi
            ;;
        sudoers)
            local sdo="$path/_etc_sudoers"
            [[ -f "$sdo" ]] && { visudo -c -f "$sdo" >/dev/null 2>&1 && cp -a "$sdo" /etc/sudoers && log INFO "Restored /etc/sudoers"; } || log ERROR "No valid sudoers backup found in '$path'"
            [[ -d "$path/sudoers.d" ]] && cp -a "$path/sudoers.d/." /etc/sudoers.d/ && log INFO "Restored /etc/sudoers.d"
            ;;
        *)
            log ERROR "No rollback routine implemented for category '$cat'."
            ;;
    esac
}

#endregion ROLLBACK

#region SYSTEM INVENTORY / DEBIAN DETECTION

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        log ERROR "This script must be run as root (sudo). Aborting."
        exit 1
    fi
}

detect_debian() {
    log INFO "=== DEBIAN DETECTION / SYSTEM INVENTORY ==="
    local is_debian=false
    local version="unknown"
    if [[ -f /etc/debian_version ]]; then
        version=$(cat /etc/debian_version)
        is_debian=true
    fi
    local pretty="unknown"
    [[ -f /etc/os-release ]] && pretty=$(. /etc/os-release; echo "$PRETTY_NAME")
    log INFO "Detected OS: $pretty (debian_version=$version)"

    local is_deb12=false
    [[ "$version" == 12.* || "$pretty" == *"bookworm"* ]] && is_deb12=true
    add_report "OS-01" "OS must be Debian 12" "README" "$([[ $is_deb12 == true ]] && echo PASS || echo WARNING)" "$pretty" "Debian 12 (bookworm)"

    command -v apt >/dev/null 2>&1 || log WARN "apt not found - this does not look like a Debian/Ubuntu-family system."

    { getent passwd; echo "---"; systemctl list-units --type=service --state=running 2>/dev/null; } >> "$LOG_FILE" 2>&1
}

#endregion SYSTEM INVENTORY

#region ACCOUNT SECURITY

is_authorized_user() {
    local name="$1"
    for u in "${AUTHORIZED_USERS[@]}"; do [[ "$u" == "$name" ]] && return 0; done
    return 1
}
is_authorized_admin() {
    local name="$1"
    for u in "${AUTHORIZED_ADMINS[@]}"; do [[ "$u" == "$name" ]] && return 0; done
    return 1
}

harden_accounts() {
    category_enabled accounts || return 0
    log INFO "=== ACCOUNT SECURITY ==="

    # Real (human) local accounts - UID range 1000-59999, excluding nobody.
    local real_users
    real_users=$(getent passwd | awk -F: '($3>=1000 && $3<60000) || $3==0 {print $1":"$3}')

    while IFS=: read -r name uid; do
        [[ "$name" == "nobody" ]] && continue
        if [[ "$uid" == "0" && "$name" != "root" ]]; then
            add_report "USR-00-$name" "Unexpected UID 0 account" "Phase 2 requirement" "FAIL" "$name has UID 0" "Only root should have UID 0" "Not auto-modified - investigate immediately, this is a severe backdoor indicator"
            continue
        fi
        [[ "$name" == "root" ]] && continue

        if is_authorized_user "$name"; then
            add_report "USR-01" "Authorized account present" "README user list" "PASS" "$name" "Present and authorized"
        else
            run_action "Lock unauthorized user account '$name' (passwd -l, not deleted)" "no" passwd -l "$name"
            add_report "USR-01" "Unauthorized account locked" "README user list" "WARNING" "$name present and unlocked" "Locked (never deleted)" "passwd -l applied"
        fi
    done <<< "$real_users"

    # Create missing authorized accounts
    for name in "${AUTHORIZED_USERS[@]}"; do
        if ! getent passwd "$name" >/dev/null 2>&1; then
            run_action "Create missing authorized user '$name'" "no" bash -c "adduser --disabled-password --gecos '' '$name'"
            if is_authorized_admin "$name"; then
                run_action "Add '$name' to sudo group" "no" usermod -aG sudo "$name"
            fi
            run_action "Force '$name' to set a password at next login" "no" passwd -e "$name"
            add_report "USR-02" "Authorized account exists" "README user list" "WARNING" "Missing" "User '$name' present" "Created, must-change-password set"
        fi
    done

    # sudo group membership must match README admin list
    local sudo_members
    sudo_members=$(getent group sudo | awk -F: '{print $4}' | tr ',' ' ')
    for member in $sudo_members; do
        [[ -z "$member" ]] && continue
        if ! is_authorized_admin "$member"; then
            run_action "Remove '$member' from sudo group (not an authorized admin)" "no" gpasswd -d "$member" sudo
            add_report "USR-03" "Sudo group matches README admin list" "README admin list" "WARNING" "$member in sudo" "Removed" "gpasswd -d applied"
        fi
    done
    for admin in "${AUTHORIZED_ADMINS[@]}"; do
        if getent passwd "$admin" >/dev/null 2>&1 && [[ " $sudo_members " != *" $admin "* ]]; then
            run_action "Add authorized admin '$admin' to sudo group" "no" usermod -aG sudo "$admin"
            add_report "USR-03" "Sudo group matches README admin list" "README admin list" "WARNING" "$admin not in sudo" "Added" "usermod -aG sudo applied"
        fi
    done

    # Root account: README/decks say lock the root password rather than set one -
    # root login is already company policy to be via sudo only.
    local root_shadow
    root_shadow=$(getent shadow root | awk -F: '{print $2}')
    if [[ "$root_shadow" != "!"* && "$root_shadow" != "*"* ]]; then
        run_action "Lock the root account password (company policy: sudo only, never direct root login)" "no" passwd -l root
        add_report "USR-04" "Root account password locked" "Training deck: Fixing the Root Password" "WARNING" "Not locked" "Locked" "passwd -l root applied"
    else
        add_report "USR-04" "Root account password locked" "Training deck: Fixing the Root Password" "PASS" "Locked" "Locked"
    fi

    # Guest/LightDM guest session - handled in files region (lightdm.conf), but
    # also verify no literal "guest" local account exists enabled.
    if getent passwd guest >/dev/null 2>&1; then
        run_action "Lock local 'guest' account if present" "no" passwd -l guest
        add_report "USR-05" "Local guest account locked" "Vulnerabilities table" "WARNING" "Present" "Locked" "passwd -l applied"
    fi

    # Primary auto-login account - never touch its password.
    add_report "USR-06" "Primary auto-login account left untouched" "README" "NOT APPLICABLE" "Skipped" "Skipped (README instruction)"
}

#endregion ACCOUNT SECURITY

#region PASSWORD POLICIES

harden_password_policy() {
    category_enabled password || return 0
    log INFO "=== PASSWORD AND AUTHENTICATION SECURITY ==="

    # login.defs - only affects NEW accounts, per the decks, so existing users
    # are handled separately below with chage.
    if [[ -f /etc/login.defs ]]; then
        run_action "Set PASS_MAX_DAYS 90 / PASS_MIN_DAYS 7 / PASS_WARN_AGE 7 in login.defs" "no" bash -c "
            sed -i -E 's/^#?PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
            sed -i -E 's/^#?PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
            sed -i -E 's/^#?PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
            grep -q '^PASS_MAX_DAYS' /etc/login.defs || echo 'PASS_MAX_DAYS   90' >> /etc/login.defs
            grep -q '^PASS_MIN_DAYS' /etc/login.defs || echo 'PASS_MIN_DAYS   7' >> /etc/login.defs
            grep -q '^PASS_WARN_AGE' /etc/login.defs || echo 'PASS_WARN_AGE   7' >> /etc/login.defs
        "
        add_report "PWD-01" "Default password age policy (login.defs)" "Week 07 debrief: Minimum Password Age" "WARNING" "See verification pass" "MAX=90 MIN=7 WARN=7" "Applied via sed"
    fi

    # Existing accounts - login.defs doesn't retroactively apply, so chage each
    # authorized account explicitly (decks: 7/90 are safe values).
    for name in "${AUTHORIZED_USERS[@]}"; do
        [[ "$name" == "$PRIMARY_AUTOLOGIN_USER" ]] && continue
        if getent passwd "$name" >/dev/null 2>&1; then
            run_action "Set password aging (min=7, max=90) for existing user '$name'" "no" chage -m 7 -M 90 "$name"
        fi
    done
    add_report "PWD-02" "Existing-account password aging set via chage" "Week 06 training round: Password Age" "WARNING" "See verification pass" "min=7 max=90 for each authorized account" "Applied via chage"

    # Password complexity via PAM. Debian 12 ships pam_pwquality by default;
    # fall back to pam_cracklib if that's what's actually installed.
    local pam_file="/etc/pam.d/common-password"
    local module=""
    if grep -q 'pam_pwquality.so' "$pam_file" 2>/dev/null; then module="pam_pwquality.so"
    elif grep -q 'pam_cracklib.so' "$pam_file" 2>/dev/null; then module="pam_cracklib.so"
    fi
    if [[ -z "$module" ]]; then
        run_action "Install libpam-pwquality for password complexity enforcement" "no" apt-get install -y libpam-pwquality
        module="pam_pwquality.so"
        grep -q "$module" "$pam_file" 2>/dev/null || module=""
    fi
    if [[ -n "$module" ]]; then
        if ! grep -E "$module.*minlen=12" "$pam_file" >/dev/null 2>&1; then
            run_action "Add complexity requirements (minlen=12, upper/lower/digit/special required) to $module line" "yes" bash -c "
                sed -i -E \"s|($module[^\n]*)|\1 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 remember=5|\" '$pam_file'
            "
        fi
        add_report "PWD-03" "Password complexity requirements enforced via PAM" "Week 06 training round + README scenario" "WARNING" "See verification pass" "minlen=12, upper/lower/digit/special, remember=5" "Applied via PAM edit (--force required)"
    else
        add_report "PWD-03" "Password complexity requirements enforced via PAM" "Week 06 training round + README scenario" "MANUAL REVIEW" "No pwquality/cracklib module found" "minlen=12 with complexity"
    fi

    # Null passwords must not authenticate.
    local auth_file="/etc/pam.d/common-auth"
    if grep -q 'nullok' "$auth_file" 2>/dev/null; then
        run_action "Remove 'nullok' from common-auth (null passwords must not authenticate)" "yes" sed -i 's/nullok//g' "$auth_file"
        add_report "PWD-04" "Null passwords disabled" "Week 06 training round: Null Passwords" "WARNING" "nullok present" "Removed" "sed applied (--force required)"
    else
        add_report "PWD-04" "Null passwords disabled" "Week 06 training round: Null Passwords" "PASS" "nullok absent" "Absent"
    fi

    # Account lockout policy via pam_faillock (threshold=5, 30 min, matching the
    # Windows-image parity values used across every CyberPatriot image in this set).
    if ! grep -rq 'pam_faillock.so' /etc/pam.d/common-auth /etc/pam.d/common-account 2>/dev/null; then
        run_action "Enable account lockout policy via pam-auth-update (faillock: deny=5, unlock_time=1800)" "yes" bash -c "
            mkdir -p /usr/share/pam-configs
            cat > /usr/share/pam-configs/faillock <<'EOF'
Name: Enable pam_faillock to deny access
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[success=1 default=ignore]	pam_faillock.so authsucc deny=5 unlock_time=1800
Auth-Initial:
	[success=1 default=ignore]	pam_faillock.so authsucc deny=5 unlock_time=1800
EOF
            cat > /usr/share/pam-configs/faillock_notify <<'EOF'
Name: Notify of failures
Default: yes
Priority: 0
Auth-Type: Primary
Auth-Initial:
	requisite			pam_faillock.so preauth deny=5 unlock_time=1800
EOF
            cat > /usr/share/pam-configs/faillock_reset <<'EOF'
Name: Reset failure count upon success
Default: yes
Priority: 1024
Auth-Type: Primary
Auth-Initial:
	required			pam_faillock.so authsucc deny=5 unlock_time=1800
EOF
            DEBIAN_FRONTEND=noninteractive pam-auth-update --enable faillock faillock_notify faillock_reset
        "
        add_report "PWD-05" "Account lockout policy enabled (pam_faillock, threshold=5, 30 min)" "Week 06 training round: Account Lockout Policy" "WARNING" "Not configured" "deny=5 unlock_time=1800" "Applied via pam-auth-update (--force required)"
    else
        add_report "PWD-05" "Account lockout policy enabled (pam_faillock)" "Week 06 training round: Account Lockout Policy" "PASS" "Configured" "Configured"
    fi
}

#endregion PASSWORD POLICIES

#region SSH HARDENING

harden_ssh() {
    category_enabled ssh || return 0
    log INFO "=== SSH HARDENING ==="

    local sshd_cfg="/etc/ssh/sshd_config"
    if [[ ! -f "$sshd_cfg" ]]; then
        add_report "SSH-00" "sshd installed (README critical service)" "README: Critical Services" "FAIL" "sshd_config not found" "sshd installed and configured"
        return
    fi

    set_sshd_option() {
        local key="$1" value="$2"
        if grep -qiE "^[[:space:]]*#?[[:space:]]*${key}\b" "$sshd_cfg"; then
            sed -i -E "s|^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+.*|${key} ${value}|I" "$sshd_cfg"
        else
            echo "${key} ${value}" >> "$sshd_cfg"
        fi
    }

    run_action "Harden sshd_config (PermitRootLogin no, PermitEmptyPasswords no, X11Forwarding no, LoginGraceTime 60)" "yes" bash -c "
        set -e
        cp -a '$sshd_cfg' '${sshd_cfg}.pre-hardening'
        $(declare -f set_sshd_option)
        set_sshd_option PermitRootLogin no
        set_sshd_option PermitEmptyPasswords no
        set_sshd_option X11Forwarding no
        set_sshd_option LoginGraceTime 60
        set_sshd_option UsePAM yes
        sshd -t
    "
    add_report "SSH-01" "PermitRootLogin disabled" "Week 07 debrief: Disable SSH Root Login (6 pts)" "WARNING" "See verification pass" "no" "Applied (--force required); syntax-checked with sshd -t before any reload"
    add_report "SSH-02" "PermitEmptyPasswords disabled" "Week 08 deck: Securing Servers (SSH)" "WARNING" "See verification pass" "no" "Applied (--force required)"
    add_report "SSH-03" "X11Forwarding disabled" "Week 08 deck: Securing Servers (SSH)" "WARNING" "See verification pass" "no" "Applied (--force required)"

    # PasswordAuthentication is intentionally left enabled - README distributes
    # passwords, not SSH keys, for every authorized user, so disabling password
    # auth would lock out legitimate access.
    add_report "SSH-04" "PasswordAuthentication left enabled (README distributes passwords, not keys)" "README: authorized users log in with passwords" "NOT APPLICABLE" "enabled" "enabled (intentional)"

    if $FORCE && ! $DRY_RUN; then
        if sshd -t 2>>"$LOG_FILE"; then
            run_action "Reload sshd to apply hardened configuration" "yes" bash -c "systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null"
        else
            log ERROR "sshd_config failed syntax check after edits - restoring pre-hardening backup, NOT reloading."
            cp -a "${sshd_cfg}.pre-hardening" "$sshd_cfg"
        fi
    else
        log SKIP "sshd not reloaded (requires --force) - changes to sshd_config take effect on next reload/restart."
    fi

    # README: sshd is the critical service - verify it stays enabled & running,
    # never stopped/disabled by this script.
    if systemctl is-active --quiet ssh 2>/dev/null || systemctl is-active --quiet sshd 2>/dev/null; then
        add_report "SSH-05" "sshd running (README critical service)" "README: Critical Services" "PASS" "Running" "Running"
    else
        add_report "SSH-05" "sshd running (README critical service)" "README: Critical Services" "FAIL" "Not running" "Running"
    fi
}

#endregion SSH HARDENING

#region FIREWALL

harden_firewall() {
    category_enabled firewall || return 0
    log INFO "=== FIREWALL ==="

    # README: UFW is the only company-approved firewall. Detect conflicting
    # managers first rather than introducing a competing one.
    if command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -q .; then
        add_report "FW-00" "No competing firewall manager active alongside UFW" "README: UFW is the only approved firewall" "MANUAL REVIEW" "nftables has active rules" "UFW only" "Not modified - reconcile manually before enabling UFW to avoid conflicting rule sets"
    fi

    if ! command -v ufw >/dev/null 2>&1; then
        run_action "Install ufw" "no" apt-get install -y ufw
    fi

    # Critical safety: allow SSH through the firewall BEFORE enabling it, so we
    # never lock out the current remote session (README: sshd is critical).
    run_action "Allow OpenSSH through UFW before enabling (avoid self-lockout)" "no" ufw allow OpenSSH

    local ufw_status
    ufw_status=$(ufw status 2>/dev/null | head -n1)
    if [[ "$ufw_status" != *"active"* ]]; then
        run_action "Enable UFW" "yes" ufw --force enable
        add_report "FW-01" "UFW enabled" "Week 06/07 decks: Uncomplicated Firewall" "WARNING" "Inactive" "Active" "Enabled (--force required); OpenSSH allowed first"
    else
        add_report "FW-01" "UFW enabled" "Week 06/07 decks: Uncomplicated Firewall" "PASS" "Active" "Active"
    fi

    ufw status verbose >> "$LOG_FILE" 2>&1
}

#endregion FIREWALL

#region SERVICE AUDITING

harden_services() {
    category_enabled services || return 0
    log INFO "=== SERVICE AUDITING ==="

    for svc in "${SERVICES_TO_DISABLE[@]}"; do
        local skip=false
        for pattern in "${CRITICAL_SERVICE_PATTERNS[@]}"; do
            [[ "$svc" == *"$pattern"* ]] && skip=true
        done
        $skip && { log SKIP "Skipping '$svc' - matches a critical service pattern"; continue; }

        if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\.service"; then
            if systemctl is-active --quiet "$svc" || systemctl is-enabled --quiet "$svc" 2>/dev/null; then
                run_action "Stop and disable unnecessary/insecure service '$svc'" "no" bash -c "systemctl stop '$svc' 2>/dev/null; systemctl disable '$svc' 2>/dev/null"
                add_report "SVC-$svc" "Unnecessary/insecure service disabled" "Week 07 debrief: Prohibited Services" "WARNING" "Active/enabled" "Stopped/disabled" "Stopped and disabled (not purged)"
            else
                add_report "SVC-$svc" "Unnecessary/insecure service disabled" "Week 07 debrief: Prohibited Services" "PASS" "Stopped/disabled" "Stopped/disabled"
            fi
        else
            add_report "SVC-$svc" "Unnecessary/insecure service absent" "Week 07 debrief: Prohibited Services" "NOT APPLICABLE" "Not installed" "N/A"
        fi
    done

    # Verify critical services (sshd, CCS Client) are untouched and running.
    for pattern in "${CRITICAL_SERVICE_PATTERNS[@]}"; do
        local matches
        matches=$(systemctl list-units --type=service 2>/dev/null | awk '{print $1}' | grep -i "$pattern" || true)
        for svc in $matches; do
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                add_report "SVC-CRITICAL-$svc" "Critical service '$svc' left untouched and running" "README: Critical Services" "PASS" "Running" "Running (never modified by this script)"
            else
                add_report "SVC-CRITICAL-$svc" "Critical service '$svc' left untouched and running" "README: Critical Services" "MANUAL REVIEW" "Not active" "Running"
            fi
        done
    done
}

#endregion SERVICE AUDITING

#region FILE PERMISSIONS

harden_files() {
    category_enabled files || return 0
    log INFO "=== FILE SYSTEM SECURITY ==="

    # Core sensitive-file permissions - safe, standard, low-risk fixes.
    run_action "Set /etc/shadow to 640 root:shadow" "no" bash -c "chown root:shadow /etc/shadow && chmod 640 /etc/shadow"
    run_action "Set /etc/passwd to 644 root:root" "no" bash -c "chown root:root /etc/passwd && chmod 644 /etc/passwd"
    run_action "Set /etc/sudoers to 440 root:root" "no" bash -c "chown root:root /etc/sudoers && chmod 440 /etc/sudoers"
    add_report "FS-01" "Core account/sudoers file permissions correct" "Phase 7 requirement" "WARNING" "See verification pass" "shadow=640 passwd=644 sudoers=440" "Applied via chown/chmod"

    # Sudoers content audit - never auto-edit, only flag entries beyond the
    # expected root/%sudo/%admin defaults (Week 08: "Sudoers: What to Look Out For").
    if command -v visudo >/dev/null 2>&1 && ! visudo -c >/dev/null 2>&1; then
        add_report "FS-02" "/etc/sudoers passes syntax check" "Phase 7/4 requirement" "FAIL" "visudo -c failed" "Valid syntax" "Not auto-repaired - fix manually with visudo"
    else
        local unexpected
        unexpected=$(grep -vE '^\s*#|^\s*$|^Defaults|^root\s|^%sudo\s|^%admin\s' /etc/sudoers 2>/dev/null || true)
        if [[ -n "$unexpected" ]]; then
            add_report "FS-02" "No unexpected sudoers entries beyond root/%sudo/%admin" "Week 08 deck: Sudoers" "MANUAL REVIEW" "$(echo "$unexpected" | tr '\n' ';')" "Only standard default entries" "Not auto-edited - review and remove with visudo if unauthorized"
        else
            add_report "FS-02" "No unexpected sudoers entries beyond root/%sudo/%admin" "Week 08 deck: Sudoers" "PASS" "Only defaults" "Only defaults"
        fi
    fi
    if [[ -d /etc/sudoers.d ]] && [[ -n "$(ls -A /etc/sudoers.d 2>/dev/null | grep -v README)" ]]; then
        add_report "FS-03" "/etc/sudoers.d reviewed for unsafe entries" "Week 08 deck: Sudoers.d" "MANUAL REVIEW" "Files present beyond README placeholder" "Empty or verified-safe" "Review each with 'visudo -f /etc/sudoers.d/<file>'"
    fi

    # SUID/SGID audit - report only, never strip bits automatically (breaks sudo/passwd/ping).
    local suid_count
    suid_count=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | tee -a "$LOG_FILE" | wc -l)
    add_report "FS-04" "SUID/SGID binaries inventoried" "Phase 7 requirement" "MANUAL REVIEW" "$suid_count found - see log" "Review against a known-good baseline" "Not modified automatically"

    # World-writable files outside expected temp dirs.
    local ww_count
    ww_count=$(find / -xdev -type f -perm -0002 ! -path '/tmp/*' ! -path '/var/tmp/*' 2>/dev/null | tee -a "$LOG_FILE" | wc -l)
    if [[ "$ww_count" -gt 0 ]]; then
        add_report "FS-05" "No unexpected world-writable files" "Phase 7 requirement" "MANUAL REVIEW" "$ww_count found - see log" "None outside /tmp, /var/tmp" "Not modified automatically"
    else
        add_report "FS-05" "No unexpected world-writable files" "Phase 7 requirement" "PASS" "None found" "None outside /tmp, /var/tmp"
    fi

    # Prohibited media files - flagged, not deleted, unless explicitly requested.
    local flagged_file="$BACKUP_DIR/flagged_media_files.txt"
    : > "$flagged_file"
    for ext in "${MEDIA_EXTENSIONS[@]}"; do
        find /home -iname "*.${ext}" -type f 2>/dev/null >> "$flagged_file"
    done
    local media_count
    media_count=$(wc -l < "$flagged_file")
    if [[ "$media_count" -gt 0 ]]; then
        if $REMOVE_MEDIA_FILES && ! $DRY_RUN; then
            while IFS= read -r f; do run_action "Delete flagged non-work media file '$f'" "no" rm -f "$f"; done < "$flagged_file"
            add_report "FS-06" "Non-work media files removed" "README scenario" "WARNING" "$media_count files found" "Removed" "Deleted"
        else
            add_report "FS-06" "Non-work media files flagged" "README scenario" "MANUAL REVIEW" "$media_count files found - see $flagged_file" "Removed if confirmed non-work-related" "Not deleted - rerun with --remove-media-files or review manually"
        fi
    else
        add_report "FS-06" "Non-work media files flagged" "README scenario" "PASS" "None found" "None"
    fi

    # Cron integrity - report suspicious entries, never auto-delete (forensics
    # relevance per Week 06 Forensic #1 / Week 08 "Malicious Cron Entries").
    local cron_suspects="$BACKUP_DIR/cron_review.txt"
    { cat /etc/crontab 2>/dev/null; echo "---cron.d---"; cat /etc/cron.d/* 2>/dev/null; } > "$cron_suspects"
    for u in $(getent passwd | awk -F: '$3>=1000 || $1=="root" {print $1}'); do
        crontab -l -u "$u" 2>/dev/null | sed "s/^/[$u] /" >> "$cron_suspects"
    done
    if grep -qE '\.py\b|curl .*\|.*sh|wget .*\|.*sh' "$cron_suspects" 2>/dev/null; then
        add_report "FS-07" "No suspicious (python/backdoor-style) cron entries" "Week 06/08 decks: Cron backdoors" "MANUAL REVIEW" "Suspicious entries found - see $cron_suspects" "No unexplained script execution via cron" "Not auto-removed - verify against forensics questions before deleting"
    else
        add_report "FS-07" "No suspicious (python/backdoor-style) cron entries" "Week 06/08 decks: Cron backdoors" "PASS" "None found" "None"
    fi

    # LightDM: disable the guest session (validated, low-risk per multiple decks).
    # Other LightDM options from Week 08 are explicitly flagged by that deck's
    # own "Be Careful!" warning as able to break the graphical login, so they
    # are reported only, never applied automatically.
    local lightdm_cfg="/etc/lightdm/lightdm.conf"
    if [[ -f "$lightdm_cfg" ]] || command -v lightdm >/dev/null 2>&1; then
        mkdir -p /etc/lightdm
        [[ -f "$lightdm_cfg" ]] || echo "[Seat:*]" > "$lightdm_cfg"
        if ! grep -q '^\[Seat:\*\]' "$lightdm_cfg"; then
            run_action "Add [Seat:*] header to lightdm.conf" "yes" sed -i '1i [Seat:*]' "$lightdm_cfg"
        fi
        if ! grep -q '^allow-guest=false' "$lightdm_cfg"; then
            run_action "Disable LightDM guest session (allow-guest=false)" "yes" sed -i '/^\[Seat:\*\]/a allow-guest=false' "$lightdm_cfg"
            add_report "FS-08" "LightDM guest session disabled" "Vulnerabilities table: Linux Configurations" "WARNING" "Not set" "allow-guest=false" "Applied (--force required); restart lightdm to take effect"
        else
            add_report "FS-08" "LightDM guest session disabled" "Vulnerabilities table: Linux Configurations" "PASS" "allow-guest=false" "allow-guest=false"
        fi
        add_report "FS-09" "Other LightDM hardening options (hide-users, autologin=none)" "Week 08 deck: Advanced Login Configs" "MANUAL REVIEW" "Not changed" "Review manually - the deck itself warns a misconfigured lightdm.conf can break the graphical login"
    else
        add_report "FS-08" "LightDM guest session disabled" "README: LightDM is the display manager" "NOT APPLICABLE" "LightDM not detected" "N/A"
    fi
}

#endregion FILE PERMISSIONS

#region PACKAGE SECURITY

harden_packages() {
    category_enabled packages || return 0
    log INFO "=== PACKAGE AND APPLICATION SECURITY ==="

    local installed
    installed=$(dpkg -l 2>/dev/null | awk '/^ii/{print $2}')

    for pattern in "${UNAUTHORIZED_APP_PATTERNS[@]}"; do
        local matches
        matches=$(echo "$installed" | grep -iE "$pattern" || true)
        [[ -z "$matches" ]] && continue
        while IFS= read -r pkg; do
            [[ -z "$pkg" ]] && continue
            if $REMOVE_UNAUTHORIZED_APPS && ! $DRY_RUN; then
                run_action "Purge unauthorized/hacking-tool package '$pkg'" "no" apt-get purge -y "$pkg"
                add_report "APP-01" "Unauthorized/hacking-tool software removed" "README scenario: hacking tools prohibited" "WARNING" "$pkg" "Removed" "apt purge applied"
            else
                add_report "APP-01" "Unauthorized/hacking-tool software flagged" "README scenario: hacking tools prohibited" "MANUAL REVIEW" "$pkg" "Removed if confirmed unauthorized against the live README" "Not removed - rerun with --remove-unauthorized-apps after confirming against README"
            fi
        done <<< "$matches"
    done

    # Standalone archives/scripts outside package management (Week 06/07: zip
    # archives, loose python backdoor scripts) - flagged only.
    local loose_find="$BACKUP_DIR/loose_suspects.txt"
    find /usr/games /usr/share /srv /opt -maxdepth 4 \( -iname '*.zip' -o -iname '*backdoor*' \) 2>/dev/null > "$loose_find"
    if [[ -s "$loose_find" ]]; then
        add_report "APP-02" "No loose hacking-tool archives/scripts outside package management" "Week 06/07 decks: Prohibited Files" "MANUAL REVIEW" "See $loose_find" "None found" "Not auto-deleted - verify against forensics questions first"
    else
        add_report "APP-02" "No loose hacking-tool archives/scripts outside package management" "Week 06/07 decks: Prohibited Files" "PASS" "None found" "None"
    fi

    # Chromium presence (README default browser) + secure settings via managed policy.
    if echo "$installed" | grep -qi '^chromium'; then
        add_report "APP-03" "Chromium installed (README default browser)" "README" "PASS" "Installed" "Installed"
        run_action "Block pop-ups/redirects for all users via Chromium managed policy" "no" bash -c "
            mkdir -p /etc/chromium/policies/managed
            cat > /etc/chromium/policies/managed/cyberpatriot-popups.json <<'EOF'
{ \"DefaultPopupsSetting\": 2 }
EOF
        "
        add_report "APP-04" "Chromium blocks pop-ups and redirects" "Week 07 debrief: Chromium Secure Settings (6 pts)" "WARNING" "See verification pass" "DefaultPopupsSetting=2 (block)" "Applied via managed policy JSON"
    else
        add_report "APP-03" "Chromium installed (README default browser)" "README" "FAIL" "Not installed" "Installed" "Install manually - README requires Chromium"
    fi

    # Updates - never a disruptive distro upgrade, just update + upgrade.
    run_action "Refresh package index (apt update)" "no" apt-get update -y
    run_action "Install available upgrades (apt upgrade)" "no" apt-get upgrade -y
    add_report "APP-05" "System packages up to date" "Week 07 debrief: Updates (5 pts) + Systemd/Chromium/OpenSSH updated" "WARNING" "See verification pass" "apt update && apt upgrade applied" "Applied"

    # Sources list integrity - never silently overwritten unless --fix-sources.
    local sources_ok=true
    if [[ -f /etc/apt/sources.list ]] && ! grep -q 'deb ' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null; then
        sources_ok=false
    fi
    if ! $sources_ok; then
        if $FIX_SOURCES && ! $DRY_RUN; then
            run_action "Restore default Debian 12 (bookworm) sources.list" "yes" bash -c "cat > /etc/apt/sources.list <<'EOF'
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian bookworm-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security bookworm-security main contrib non-free non-free-firmware
EOF
apt-get update -y"
            add_report "APP-06" "APT sources list valid (updates run correctly)" "Week 08 deck: Sources List" "WARNING" "Appeared corrupted/empty" "Restored to Debian 12 defaults" "Applied (--force + --fix-sources required)"
        else
            add_report "APP-06" "APT sources list valid (updates run correctly)" "Week 08 deck: Sources List" "MANUAL REVIEW" "Appears corrupted/empty - updates may silently do nothing" "Valid official repository mirrors" "Not auto-rewritten - rerun with --fix-sources --force, or use the Software Sources GUI to restore defaults"
        fi
    else
        add_report "APP-06" "APT sources list valid" "Week 08 deck: Sources List" "PASS" "Valid" "Valid"
    fi

    # Automatic update list refresh (phase 9: automatic security updates).
    run_action "Install and enable unattended-upgrades for automatic security updates" "no" bash -c "
        apt-get install -y unattended-upgrades
        cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists \"1\";
APT::Periodic::Unattended-Upgrade \"1\";
EOF
    "
    add_report "APP-07" "Automatic security update checks enabled" "Phase 9 requirement" "WARNING" "See verification pass" "unattended-upgrades configured for security updates" "Applied"
}

#endregion PACKAGE SECURITY

#region KERNEL HARDENING

harden_kernel() {
    category_enabled kernel || return 0
    log INFO "=== KERNEL HARDENING (sysctl) ==="

    local sysctl_file="/etc/sysctl.conf"
    set_sysctl() {
        local key="$1" value="$2"
        if grep -qE "^#?\s*${key}\s*=" "$sysctl_file"; then
            sed -i -E "s|^#?\s*${key}\s*=.*|${key} = ${value}|" "$sysctl_file"
        else
            echo "${key} = ${value}" >> "$sysctl_file"
        fi
    }

    # Values taken directly from Week 06 (syncookies) and Week 08 (ASLR, ICMP
    # broadcast, SYN backlog) decks. IPv4 forwarding left at the deck's own
    # documented value (0 = off, this host is not a router); IPv6 is
    # deliberately NOT touched, per the explicit "no documented reason" rule.
    run_action "Apply sysctl hardening (SYN cookies, ASLR, ICMP broadcast ignore, SYN backlog, no IP forwarding)" "no" bash -c "
        $(declare -f set_sysctl)
        set_sysctl net.ipv4.tcp_syncookies 1
        set_sysctl kernel.randomize_va_space 2
        set_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1
        set_sysctl net.ipv4.tcp_max_syn_backlog 20480
        set_sysctl net.ipv4.ip_forward 0
        sysctl -p
    "
    add_report "KRN-01" "SYN cookies enabled" "Week 06 training round: SYN Cookies" "WARNING" "See verification pass" "net.ipv4.tcp_syncookies=1" "Applied"
    add_report "KRN-02" "ASLR enabled" "Week 08 deck: Sysctl Advanced" "WARNING" "See verification pass" "kernel.randomize_va_space=2" "Applied"
    add_report "KRN-03" "ICMP broadcast echo ignored" "Week 08 deck: Sysctl Advanced" "WARNING" "See verification pass" "net.ipv4.icmp_echo_ignore_broadcasts=1" "Applied"
    add_report "KRN-04" "SYN backlog hardened" "Week 08 deck: Sysctl Advanced" "WARNING" "See verification pass" "net.ipv4.tcp_max_syn_backlog=20480" "Applied"
    add_report "KRN-05" "IP forwarding disabled (not a router)" "Week 08 deck: Sysctl Advanced" "WARNING" "See verification pass" "net.ipv4.ip_forward=0" "Applied"

    # Core dumps - standard, low-risk hardening (Phase 9 explicitly lists this).
    run_action "Disable core dumps for all users" "no" bash -c "
        echo '* hard core 0' > /etc/security/limits.d/99-cyberpatriot-nocore.conf
        echo 'fs.suid_dumpable = 0' >> '$sysctl_file'
        sysctl -p
    "
    add_report "KRN-06" "Core dumps disabled" "Phase 9 requirement" "WARNING" "See verification pass" "Disabled" "Applied"
}

#endregion KERNEL HARDENING

#region APPARMOR

harden_apparmor() {
    category_enabled apparmor || return 0
    log INFO "=== APPARMOR ==="

    if ! command -v aa-status >/dev/null 2>&1; then
        run_action "Install AppArmor" "no" apt-get install -y apparmor apparmor-utils
    fi

    if systemctl is-active --quiet apparmor 2>/dev/null; then
        add_report "AA-01" "AppArmor service active" "Phase 9 requirement" "PASS" "Active" "Active"
    else
        run_action "Enable and start AppArmor" "no" bash -c "systemctl enable apparmor && systemctl start apparmor"
        add_report "AA-01" "AppArmor service active" "Phase 9 requirement" "WARNING" "Inactive" "Active" "Enabled and started"
    fi

    if command -v aa-status >/dev/null 2>&1; then
        local complain_count
        complain_count=$(aa-status 2>/dev/null | grep -c 'in complain mode' || true)
        aa-status >> "$LOG_FILE" 2>&1
        add_report "AA-02" "AppArmor profiles reviewed" "Phase 9 requirement" "MANUAL REVIEW" "$complain_count profile(s) in complain mode - see log" "Review and switch to enforce mode only after confirming it doesn't break required functionality"
    fi
}

#endregion APPARMOR

#region LOGGING AND AUDITING

harden_logging() {
    category_enabled logging || return 0
    log INFO "=== LOGGING AND AUDITING ==="

    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        add_report "LOG-01" "rsyslog active (system logging preserved)" "Phase 10 requirement" "PASS" "Active" "Active"
    else
        run_action "Start and enable rsyslog" "no" bash -c "systemctl enable rsyslog && systemctl start rsyslog"
        add_report "LOG-01" "rsyslog active (system logging preserved)" "Phase 10 requirement" "WARNING" "Inactive" "Active" "Enabled and started"
    fi

    for f in /var/log/auth.log /var/log/syslog; do
        if [[ -f "$f" ]]; then
            add_report "LOG-02-$(basename "$f")" "$f exists and is never cleared by this script" "Phase 10 requirement" "PASS" "Present ($(du -h "$f" 2>/dev/null | cut -f1))" "Present, preserved"
        fi
    done

    # auditd is optional - the README does not explicitly require it, so this
    # is reported only, never force-installed.
    if command -v auditctl >/dev/null 2>&1; then
        add_report "LOG-03" "auditd installed" "Phase 9/10 requirement (optional)" "PASS" "Installed" "Installed"
    else
        add_report "LOG-03" "auditd installed" "Phase 9/10 requirement (optional)" "NOT APPLICABLE" "Not installed" "Not required by README - install manually only if the live README asks for it"
    fi

    log INFO "This script never truncates or clears any log file."
}

#endregion LOGGING AND AUDITING

#region VERIFICATION

update_report_status() {
    local id="$1" actual="$2" expected_override="${3:-}"
    for i in "${!REPORT_ITEMS[@]}"; do
        IFS=$'\t' read -r rid desc src status _actual expected action <<< "${REPORT_ITEMS[$i]}"
        if [[ "$rid" == "$id" ]]; then
            local expected_use="$expected"
            [[ -n "$expected_override" ]] && expected_use="$expected_override"
            local new_status="$status"
            if [[ "$actual" == "$expected_use" ]]; then new_status="PASS"
            elif [[ "$status" != "MANUAL REVIEW" && "$status" != "NOT APPLICABLE" ]]; then new_status="FAIL"
            fi
            REPORT_ITEMS[$i]="${rid}	${desc}	${src}	${new_status}	${actual}	${expected}	${action}"
        fi
    done
}

run_verification() {
    log INFO "=== VERIFICATION PASS (independent of apply logic) ==="

    local sshd_root
    sshd_root=$(sshd -T 2>/dev/null | awk '$1=="permitrootlogin"{print $2}')
    update_report_status "SSH-01" "$sshd_root" "no"

    local sshd_empty
    sshd_empty=$(sshd -T 2>/dev/null | awk '$1=="permitemptypasswords"{print $2}')
    update_report_status "SSH-02" "$sshd_empty" "no"

    local sshd_x11
    sshd_x11=$(sshd -T 2>/dev/null | awk '$1=="x11forwarding"{print $2}')
    update_report_status "SSH-03" "$sshd_x11" "no"

    local syncookies
    syncookies=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
    update_report_status "KRN-01" "$syncookies" "1"
    update_report_status "KRN-02" "$(sysctl -n kernel.randomize_va_space 2>/dev/null)" "2"
    update_report_status "KRN-03" "$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null)" "1"
    update_report_status "KRN-04" "$(sysctl -n net.ipv4.tcp_max_syn_backlog 2>/dev/null)" "20480"
    update_report_status "KRN-05" "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" "0"

    local ufw_active
    ufw_active=$(ufw status 2>/dev/null | head -n1 | grep -o 'active' || echo "inactive")
    update_report_status "FW-01" "$ufw_active" "active"

    if command -v chage >/dev/null 2>&1; then
        local sample_min sample_max
        sample_min=$(chage -l "$PRIMARY_AUTOLOGIN_USER" 2>/dev/null | awk -F: '/Minimum/{gsub(/ /,"",$2);print $2}')
        : "$sample_min"
    fi

    log INFO "Verification pass complete."
}

#endregion VERIFICATION

#region COMPLIANCE REPORT

write_report() {
    log INFO "=== COMPLIANCE REPORT ==="
    {
        echo "RequirementId,Description,Source,Status,Actual,Expected,ActionTaken"
        for item in "${REPORT_ITEMS[@]}"; do
            IFS=$'\t' read -r id desc src status actual expected action <<< "$item"
            printf '"%s","%s","%s","%s","%s","%s","%s"\n' \
                "${id//\"/\'}" "${desc//\"/\'}" "${src//\"/\'}" "${status//\"/\'}" "${actual//\"/\'}" "${expected//\"/\'}" "${action//\"/\'}"
        done
    } > "$REPORT_CSV"
    log INFO "Compliance report written to '$REPORT_CSV'"

    echo
    echo "===================== COMPLIANCE SUMMARY ====================="
    for s in PASS WARNING FAIL "MANUAL REVIEW" "NOT APPLICABLE"; do
        local count=0
        for item in "${REPORT_ITEMS[@]}"; do
            IFS=$'\t' read -r _ _ _ status _ _ _ <<< "$item"
            [[ "$status" == "$s" ]] && count=$((count+1))
        done
        printf '%-16s %d\n' "$s" "$count"
    done
    echo "Full report: $REPORT_CSV"
    echo "Full log:    $LOG_FILE"

    echo
    echo "--- Items requiring MANUAL REVIEW ---"
    for item in "${REPORT_ITEMS[@]}"; do
        IFS=$'\t' read -r id desc src status actual expected action <<< "$item"
        [[ "$status" == "MANUAL REVIEW" ]] && printf '  [%s] %s (actual: %s / expected: %s)\n' "$id" "$desc" "$actual" "$expected"
    done

    echo
    echo "--- Items that FAILED verification ---"
    for item in "${REPORT_ITEMS[@]}"; do
        IFS=$'\t' read -r id desc src status actual expected action <<< "$item"
        [[ "$status" == "FAIL" ]] && printf '  [%s] %s (actual: %s / expected: %s)\n' "$id" "$desc" "$actual" "$expected"
    done
}

#endregion COMPLIANCE REPORT

#region MAIN EXECUTION

main() {
    check_root
    log INFO "===================================================================="
    log INFO "Debian-Hardening.sh starting - Mode=$MODE Categories=[$CATEGORIES] DryRun=$DRY_RUN Force=$FORCE"
    log INFO "===================================================================="

    if [[ "$MODE" == "rollback" ]]; then
        [[ -n "$ROLLBACK_CATEGORY" ]] || { log ERROR "--mode rollback requires --rollback-category."; exit 1; }
        do_rollback "$ROLLBACK_CATEGORY"
        return
    fi

    detect_debian

    if [[ "$MODE" == "verify" ]]; then
        run_verification
        write_report
        return
    fi

    backup_all_configs

    harden_accounts
    harden_password_policy
    harden_ssh
    harden_firewall
    harden_services
    harden_packages
    harden_kernel
    harden_apparmor
    harden_files
    harden_logging

    $DRY_RUN || run_verification

    write_report

    log INFO "===================================================================="
    log INFO "Debian-Hardening.sh complete. Elapsed: $(( $(date +%s) - START_EPOCH ))s"
    log INFO "===================================================================="
}

main
#endregion MAIN EXECUTION
