#!/usr/bin/env bash
# harden.sh: baseline hardening for the 2026 MWCCDC Invitational Debian 12 Splunk box
# (172.20.240.20). Needs sshd_config and sysctl.conf in the same folder.
#
# Usage:   sudo bash harden.sh              harden, then run post-checks
#          sudo bash harden.sh --check      post-checks only, changes nothing
#          sudo bash harden.sh --no-firewall    harden everything except ufw
#          Run at a real terminal (NETLAB console or SSH), not piped: the firewall
#          step asks for confirmation.
#
# Built around the Team Pack rules:
#   - Scored here: SSH (password login), Ping, Splunk Query, Splunk Management (8089).
#   - ICMP must stay on (Competition Play #12): ping is never blocked.
#   - Public services stay reachable from ALL source IPs (Systems #9): ports are
#     opened to everyone, never limited to scoring-engine addresses.
#   - No hostname / IP / username changes (Systems #7, Play #11).
#   - No snapshots or VM revert (Systems #10): all of /etc is backed up first.
#   - Scored password changes are made in Quotient -> PCR (CSV: username,password).
#     This script changes no passwords.
#
# Safety:  - The SSH config is syntax-checked before use; if ssh does not come back,
#            the old config is restored automatically.
#          - The firewall turns itself back OFF unless SSH and Splunk are confirmed
#            working within CONFIRM_SECONDS.
#          - Safe to run twice: settings are replaced, not appended again.

set -u

# ======================= EDIT BEFORE RUNNING =======================
# Inbound ports allowed through the host firewall (open to every source IP).
#   22 SSH (scored) | 8000 Splunk web | 8089 Splunk management (scored)
#   9997 forwarders from every host | 514/udp Palo Alto syslog
TCP_PORTS="22 8000 8089 9997"
UDP_PORTS="514"

# 1 = also allow every port already listening on a non-localhost address, so an
# unknown scored service is not cut off. Each is printed as WARN; review them,
# since a red team backdoor would also be listening.
ALLOW_CURRENT_LISTENERS=1

ENABLE_UFW=1
CONFIRM_SECONDS=120
# ===================================================================

MODE=apply
for a in "$@"; do
    case "$a" in
        --check) MODE=check ;;
        --no-firewall) ENABLE_UFW=0 ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "Unknown option: $a (try --help)" >&2; exit 5 ;;
    esac
done

# ---------- helpers ----------
say()  { printf '%s\n' "$*"; }
ok()   { say "OK:      $*"; }
chg()  { say "CHANGED: $*"; }
warn() { say "WARN:    $*" >&2; }
fail() { say "FAIL:    $*" >&2; }

[ "$(id -u)" -eq 0 ] || exec sudo -- bash "$0" "$@"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="/var/backups/ccdc/harden-$TS"
export DEBIAN_FRONTEND=noninteractive
SSHD="$(command -v sshd || echo /usr/sbin/sshd)"
SSH_SVC=ssh; systemctl list-unit-files ssh.service >/dev/null 2>&1 || SSH_SVC=sshd

# Replace "KEY anything" with "KEY VALUE" in a file, or append it if the key is missing.
# Example: set_kv /etc/login.defs PASS_MAX_DAYS 90
#   "PASS_MAX_DAYS	99999" -> "PASS_MAX_DAYS 90"
set_kv() {
    local file="$1" key="$2" value="$3"
    if grep -qE "^[[:space:]]*${key}[[:space:]]" "$file"; then
        sed -i -E "s|^[[:space:]]*${key}[[:space:]].*|${key} ${value}|" "$file"
    else
        printf '%s %s\n' "$key" "$value" >> "$file"
    fi
}

# HTTP status code of a local URL, "000" if nothing answers.
http_code() { curl -sk -o /dev/null -m 5 -w '%{http_code}' "$1" 2>/dev/null || true; }

# ---------- post-checks (also the whole of --check) ----------
post_checks() {
    say ""
    say "==== Post-checks (scored: SSH, Ping, Splunk Query, Splunk Management) ===="
    systemctl is-active --quiet "$SSH_SVC" && ok "$SSH_SVC active" || fail "$SSH_SVC NOT active: sudo systemctl restart $SSH_SVC"
    "$SSHD" -T 2>/dev/null | grep -q '^passwordauthentication yes' && ok "SSH password login enabled (scoring logs in with a password)" \
        || warn "SSH password login is OFF: scored SSH check will fail"

    [ "$(sysctl -n net.ipv4.icmp_echo_ignore_all 2>/dev/null)" = 0 ] && ok "ping replies enabled (kernel)" || fail "kernel ignores ping: sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0"
    if command -v ufw >/dev/null && ufw status | grep -q 'Status: active'; then
        grep -qE 'icmp-type echo-request -j ACCEPT' /etc/ufw/before.rules && ok "ufw allows ping" || fail "ufw before.rules does not allow ping"
    fi

    if [ -x /opt/splunk/bin/splunk ]; then
        /opt/splunk/bin/splunk status 2>/dev/null | grep -q "is running" && ok "Splunk running" || fail "Splunk NOT running: sudo /opt/splunk/bin/splunk start"
    else
        warn "/opt/splunk not found (fine on a non-Splunk box)"
    fi
    # 8089 answers 401 (login required) or 200 when splunkd is healthy.
    c="$(http_code https://127.0.0.1:8089/services/server/info)"
    case "$c" in 200|401) ok "Splunk management 8089 answering (HTTP $c)" ;; *) fail "Splunk management 8089 not answering (HTTP $c)" ;; esac
    c="$(http_code http://127.0.0.1:8000/)"; [ "$c" = 000 ] && c="$(http_code https://127.0.0.1:8000/)"
    case "$c" in 200|303|302) ok "Splunk web 8000 answering (HTTP $c)" ;; *) warn "Splunk web 8000 not answering (HTTP $c)" ;; esac

    for p in $TCP_PORTS; do
        ss -Htln | awk '{print $4}' | grep -qE ":$p\$" && ok "port $p/tcp listening" || warn "port $p/tcp NOT listening"
    done
    [ -f /var/log/auth.log ] && ok "/var/log/auth.log present (SSH logins reach Splunk)" || warn "/var/log/auth.log missing: sudo apt install -y rsyslog"
    df -P / /opt 2>/dev/null | awk 'NR>1 && $4 < 5242880 {print $6}' | sort -u | while read -r m; do
        warn "less than 5 GB free on $m: Splunk pauses indexing below 5 GB"
    done
    timedatectl show -p NTPSynchronized --value 2>/dev/null | grep -q yes || warn "clock not NTP-synced: log timestamps may drift"
    say ""
    say "Then confirm in Quotient (https://quotient.ccdc.events) that SSH, Ping, Splunk Query and Splunk Management are green."
}

if [ "$MODE" = check ]; then post_checks; exit 0; fi

for f in sshd_config sysctl.conf; do
    if [ ! -f "$SCRIPT_DIR/$f" ]; then
        fail "$SCRIPT_DIR/$f not found. Put it next to harden.sh."
        exit 3
    fi
done
command -v apt-get >/dev/null || { fail "apt-get missing: this script is for Debian/Ubuntu"; exit 3; }

# ---------- 0. Backup (no VM snapshots in this competition) ----------
mkdir -p "$BACKUP_DIR" && chmod 700 /var/backups/ccdc "$BACKUP_DIR"
if tar czf "$BACKUP_DIR/etc.tgz" -C / etc 2>/dev/null; then
    chg "backup /etc -> $BACKUP_DIR/etc.tgz"
else
    fail "could not back up /etc, stopping before any change"
    exit 1
fi
if [ -d /opt/splunk/etc ]; then
    tar czf "$BACKUP_DIR/splunk-etc.tgz" -C / opt/splunk/etc 2>/dev/null && chg "backup /opt/splunk/etc -> $BACKUP_DIR/splunk-etc.tgz"
fi

# ---------- 1. Packages (competition systems have internet; free/open source only) ----------
PKGS="rsyslog auditd audispd-plugins ufw libpam-pwquality curl"
# shellcheck disable=SC2086  # word splitting of the package list is intended
if apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq $PKGS >/dev/null 2>&1; then
    chg "installed/verified: $PKGS"
else
    warn "apt failed (no internet or full disk?). Continuing with what is installed."
fi

# ---------- 2. Logging: auth/syslog files for Splunk ----------
# Debian 12 logs only to journald by default, so /var/log/auth.log does not exist
# and the Splunk forwarder sees no SSH logins. rsyslog writes those files.
if command -v rsyslogd >/dev/null; then
    systemctl enable --now rsyslog >/dev/null 2>&1 && ok "rsyslog running"
    [ -f /var/log/auth.log ] || { logger -p auth.info "ccdc harden.sh started"; sleep 1; }
else
    warn "rsyslog not installed: SSH logins will NOT reach Splunk from files"
fi

# ---------- 3. SSH (scored: password login must keep working) ----------
mkdir -p /run/sshd
NEW_SSHD="$SCRIPT_DIR/sshd_config"

BANNER="Authorized use only. All activity may be monitored and reported."
for f in /etc/issue /etc/issue.net; do
    if [ "$(cat "$f" 2>/dev/null)" != "$BANNER" ]; then printf '%s\n' "$BANNER" > "$f"; chg "banner $f"; fi
done

if [ -x "$SSHD" ]; then
    # Drop-ins cannot override sshd_config (Include is at the end). They are still
    # listed: an unexpected one is a red team indicator for the incident log.
    for d in /etc/ssh/sshd_config.d/*.conf; do
        [ -e "$d" ] || continue
        warn "sshd drop-in present: $d -> $(grep -vE '^[[:space:]]*(#|$)' "$d" | tr '\n' ';')"
    done
    if "$SSHD" -t -f "$NEW_SSHD"; then
        cp -p /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.prev"
        install -o root -g root -m 600 "$NEW_SSHD" /etc/ssh/sshd_config
        # reload keeps existing SSH sessions open; fall back to restart
        if "$SSHD" -t; then
            systemctl reload "$SSH_SVC" 2>/dev/null || systemctl restart "$SSH_SVC"
        fi
        sleep 1
        if "$SSHD" -t && systemctl is-active --quiet "$SSH_SVC"; then
            chg "sshd_config installed and $SSH_SVC reloaded (existing sessions stay open)"
        else
            fail "$SSH_SVC not healthy after change, restoring old config"
            install -m 600 "$BACKUP_DIR/sshd_config.prev" /etc/ssh/sshd_config
            systemctl restart "$SSH_SVC"
        fi
    else
        fail "new sshd_config failed syntax check: NOT installed"
    fi
else
    warn "sshd not installed, skipping SSH"
fi

# ---------- 4. Kernel parameters ----------
# Undo: sudo rm /etc/sysctl.d/99-ccdc-hardening.conf && sudo sysctl --system
install -o root -g root -m 644 "$SCRIPT_DIR/sysctl.conf" /etc/sysctl.d/99-ccdc-hardening.conf
# -e ignores keys this kernel does not have instead of erroring
sysctl -e -q -p /etc/sysctl.d/99-ccdc-hardening.conf && chg "sysctl hardening applied (/etc/sysctl.d/99-ccdc-hardening.conf)"

# ---------- 5. Privilege escalation quick fixes ----------
# PwnKit (CVE-2021-4034): remove the SUID bit from pkexec.
if [ -u /usr/bin/pkexec ]; then chmod 0755 /usr/bin/pkexec && chg "pkexec SUID removed"; else ok "pkexec not SUID / absent"; fi

# ---------- 6. Password policy (affects NEW passwords only) ----------
# Do NOT add `chage -d 0`: forcing a password change at next login breaks scored logins.
# PCR passwords set through Quotient must still match what is set on the box.
set_kv /etc/login.defs PASS_MAX_DAYS 90
set_kv /etc/login.defs PASS_MIN_DAYS 0   # passwords may need rotating twice in one day
useradd -D -f 30
if [ -d /etc/security ]; then
    mkdir -p /etc/security/pwquality.conf.d
    printf 'minlen = 12\nminclass = 3\n' > /etc/security/pwquality.conf.d/ccdc.conf
    chg "password policy: max 90 days, minlen 12, 3 character classes"
fi

# ---------- 7. Restrict su to the sudo group ----------
# Only applied if the operator running this is in the sudo group (prevents lockout).
OPERATOR="${SUDO_USER:-root}"
if grep -qE '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so' /etc/pam.d/su; then
    ok "su already restricted"
elif [ "$OPERATOR" != root ] && id -nG "$OPERATOR" | grep -qw sudo; then
    printf 'auth required pam_wheel.so use_uid group=sudo\n' >> /etc/pam.d/su
    chg "su restricted to members of group sudo"
else
    warn "skipped su restriction: $OPERATOR is not in group sudo"
fi

# ---------- 8. Cron ----------
for p in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    [ -e "$p" ] && chown root:root "$p" && chmod og-rwx "$p"
done
# Existing user crontabs are evidence: list them before cron.allow blocks new ones.
for c in /var/spool/cron/crontabs/*; do
    [ -e "$c" ] && warn "user crontab exists: $c -> $(grep -vE '^[[:space:]]*(#|$)' "$c" | tr '\n' ';')"
done
# Only root may use `crontab` (blocks red team user crontabs). Other users must use sudo.
[ -f /etc/cron.deny ] && mv /etc/cron.deny "$BACKUP_DIR/cron.deny"
printf 'root\n' > /etc/cron.allow && chmod 600 /etc/cron.allow
chg "cron permissions tightened, cron.allow = root"

# ---------- 9. Bootloader config permissions ----------
for g in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do
    [ -f "$g" ] && chown root:root "$g" && chmod 600 "$g"
done

# ---------- 10. auditd rules (Splunk: index=nix key=<name>) ----------
if command -v auditctl >/dev/null; then
    # Keep logs rotating. KEEP_LOGS can fill the disk, and a full disk stops
    # Splunk, which is a scored service.
    [ -f /etc/audit/auditd.conf ] && set_kv /etc/audit/auditd.conf max_log_file "= 20"
    cat > /etc/audit/rules.d/60-ccdc.rules <<'EOF'
## CCDC watch rules. Search in Splunk:  index=nix key=<name>   (e.g. key=identity)
# Accounts and privilege
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
# SSH config and keys (snoopy misses `echo >> authorized_keys`, this catches it)
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /root/.ssh/ -p wa -k authorized_keys
-w /home/sysadmin/.ssh/ -p wa -k authorized_keys
# Persistence
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd
-w /etc/ld.so.preload -p wa -k preload
-w /etc/pam.d/ -p wa -k pam
# Splunk itself: red team can plant an app with a scripted input that runs as Splunk,
# or edit users/auth to break the scored Splunk Query / Management checks
-w /opt/splunk/etc/apps/ -p wa -k splunk_conf
-w /opt/splunk/etc/system/local/ -p wa -k splunk_conf
-w /opt/splunk/etc/passwd -p wa -k splunk_conf
-w /opt/splunk/etc/auth/ -p wa -k splunk_conf
# Hostname/network changes (not allowed for us, so any hit is red team)
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale
-w /etc/network/ -p wa -k system-locale
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
# Clock changes (break the incident report timeline)
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
EOF
    # Watches on paths that do not exist yet make augenrules fail on some versions,
    # so those lines are dropped instead of failing the whole load.
    # Sample: "-w /home/sysadmin/.ssh/ -p wa -k authorized_keys" removed if the dir is missing.
    tmp="$(mktemp)"
    while IFS= read -r line; do
        case "$line" in
            "-w "*) p="${line#-w }"; p="${p%% *}"; [ -e "$p" ] && printf '%s\n' "$line" ;;
            *) printf '%s\n' "$line" ;;
        esac
    done < /etc/audit/rules.d/60-ccdc.rules > "$tmp" && mv "$tmp" /etc/audit/rules.d/60-ccdc.rules
    chmod 640 /etc/audit/rules.d/60-ccdc.rules
    # Do not add "-e 2" (immutable): it blocks the BYU auditd rules and any later fix until reboot.
    systemctl enable --now auditd >/dev/null 2>&1
    if augenrules --load >/dev/null 2>&1; then chg "audit rules loaded (key=identity, sshd, cron, splunk_conf, ...)"; else warn "augenrules --load failed: check 'auditctl -l'"; fi
else
    warn "auditd not installed, skipping audit rules"
fi

# ---------- 11. Host firewall (ufw) with dead-man timer ----------
# Runs last so the rest is done even if the firewall is turned off again.
# Ports are opened to EVERY source IP (Systems #9 forbids scoring-engine-only rules).
# Blocking one specific malicious IP is allowed:  sudo ufw insert 1 deny from <IP>
if [ "$ENABLE_UFW" = 1 ] && command -v ufw >/dev/null; then
    allow_tcp="$TCP_PORTS"
    if [ "$ALLOW_CURRENT_LISTENERS" = 1 ]; then
        # From `ss -Htln` local address column take the port of non-localhost listeners.
        # Sample: "0.0.0.0:8089" -> 8089 ; "[::]:22" -> 22 ; "127.0.0.1:631" -> skipped
        for port in $(ss -Htln | awk '{print $4}' | grep -vE '^(127\.|\[::1\])' | sed -E 's/.*:([0-9]+)$/\1/' | sort -un); do
            case " $allow_tcp " in *" $port "*) ;; *)
                warn "also allowing currently-listening TCP $port: check it is legitimate (ss -tlnp | grep :$port)"
                allow_tcp="$allow_tcp $port" ;;
            esac
        done
    fi
    # ufw's default before.rules accept ICMP echo-request; make sure nobody removed it.
    if ! grep -qE 'icmp-type echo-request -j ACCEPT' /etc/ufw/before.rules; then
        warn "ufw before.rules has no ping rule: skipping firewall so ping (scored) keeps working"
    else
        ufw default deny incoming >/dev/null
        ufw default allow outgoing >/dev/null
        ufw allow in on lo >/dev/null
        for p in $allow_tcp; do ufw allow "$p/tcp" >/dev/null; done
        for p in $UDP_PORTS; do ufw allow "$p/udp" >/dev/null; done
        ufw logging low >/dev/null   # blocked packets -> /var/log/ufw.log -> Splunk
        ufw --force enable >/dev/null && chg "ufw enabled: tcp [$allow_tcp] udp [$UDP_PORTS], ping allowed"

        if [ -t 0 ]; then
            say ""
            say ">>> From the Ubuntu or Windows workstation, test NOW:"
            say ">>>   ssh sysadmin@172.20.240.20   and   http(s)://172.20.240.20:8000   and   ping 172.20.240.20"
            say ">>> Type yes within ${CONFIRM_SECONDS}s if all work, or the firewall turns OFF."
            if read -r -t "$CONFIRM_SECONDS" answer && [ "$answer" = yes ]; then
                ok "firewall confirmed by operator"
            else
                ufw --force disable >/dev/null
                warn "no confirmation: ufw DISABLED again (rules kept; 'sudo ufw enable' to retry)"
            fi
        else
            warn "not run from a terminal: no dead-man check. Verify SSH, ping and Splunk now."
        fi
    fi
else
    [ "$ENABLE_UFW" = 1 ] && warn "ufw not installed, firewall skipped"
fi

post_checks

say ""
say "Backup:  $BACKUP_DIR/  (etc.tgz, splunk-etc.tgz)"
say "Undo SSH:      sudo tar xzf $BACKUP_DIR/etc.tgz -C / etc/ssh/sshd_config && sudo systemctl restart $SSH_SVC"
say "Undo sysctl:   sudo rm /etc/sysctl.d/99-ccdc-hardening.conf && sudo sysctl --system"
say "Undo firewall: sudo ufw disable"
say "Do NOT untar all of /etc: that would also roll back password changes."
say "Changed a scored password? Submit it in Quotient -> PCR as: username,password"
