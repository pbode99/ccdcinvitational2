#!/usr/bin/env bash
# guard.sh: keep red team out of the Splunk box while keeping scored services up.
#
# Every few seconds it:
#   - kills every process started from a BAD_USERS login, INCLUDING root shells they
#     opened with sudo (matched by audit loginuid, which survives sudo/su)
#   - strips BAD_USERS from privileged groups, locks + expires them, nologin shell,
#     deletes their sudoers entries and SSH keys
#   - finds WHO re-added them (auditd) and stops that process / systemd unit
#   - keeps the SSH DenyUsers drop-in, the attacker IP blocks and the bad units masked
#   - removes firewall-flush cron jobs
#   - restarts scored services if they stop (ssh, Splunk, chrony)
# It never touches PROTECTED_USERS (root, sysadmin, splunk) or AD users.
#
# Usage:
#   sudo bash guard.sh --once          one pass, print what it did
#   sudo bash guard.sh --run           loop in the foreground (Ctrl+C to stop)
#   sudo bash guard.sh --install       install + start as systemd service "ccdc-guard"
#   sudo bash guard.sh --uninstall     stop and remove the service
#   sudo bash guard.sh --lock-files    make passwd/group/shadow immutable (extreme)
#   sudo bash guard.sh --unlock-files  undo --lock-files (needed before any passwd/PCR change)
#   sudo bash guard.sh --status        service state + last 20 log lines
# Log: /var/log/ccdc-guard.log  (add to Splunk: splunk add monitor /var/log/ccdc-guard.log -index nix)

set -u

# ======================= EDIT IF NEEDED =======================
BAD_USERS="svc-chrony docker"            # local accounts to neutralize
DENY_SSH_USERS="svc-chrony docker shadbrown"
BAD_IPS="198.51.100.17"                  # confirmed attacker IPs only (rules allow blocking these)
PROTECTED_USERS="root sysadmin splunk"   # never modified or killed
PRIV_GROUPS="sudo adm root wheel shadow disk lxd docker"
SERVICES="ssh Splunkd chrony rsyslog auditd cron"   # restarted if not active
MASK_UNITS="cgroup-prsd systemd-kworker systemd-helper link-mtud neigh-gcd sssd-sync scoring"
INTERVAL=3                               # seconds between passes
# ==============================================================

LOG=/var/log/ccdc-guard.log
EVID=/root/evidence/guard
SELF="$(readlink -f "$0")"
DENY_FILE=/etc/ssh/sshd_config.d/zz-ccdc-deny.conf
# shellcheck disable=SC2086  # IDENTITY_FILES is a word list on purpose
IDENTITY_FILES="/etc/passwd /etc/group /etc/shadow /etc/gshadow"

[ "$(id -u)" -eq 0 ] || exec sudo -- bash "$0" "$@"
mkdir -p "$EVID" && chmod 700 /root/evidence "$EVID" 2>/dev/null
touch "$LOG" && chmod 600 "$LOG"

log() { printf '%s %s\n' "$(date '+%F %T %Z')" "$*" | tee -a "$LOG"; }

is_protected() { case " $PROTECTED_USERS " in *" $1 "*) return 0 ;; esac; return 1; }

# --- 1. kill every process whose audit loginuid belongs to a bad user ---------------
# /proc/PID/loginuid keeps the UID of the account that logged in, even after sudo -i,
# so this also catches the attacker's root shells and root loops.
kill_bad_sessions() {
    local u uid pid lu comm
    for u in $BAD_USERS; do
        uid="$(id -u "$u" 2>/dev/null)" || continue
        for pid in $(pgrep -u "$u" 2>/dev/null); do
            log "KILL pid=$pid user=$u cmd=$(tr '\0' ' ' < /proc/"$pid"/cmdline 2>/dev/null | cut -c1-120)"
            kill -9 "$pid" 2>/dev/null
        done
        for lu in /proc/[0-9]*/loginuid; do
            [ "$(cat "$lu" 2>/dev/null)" = "$uid" ] || continue
            pid="${lu#/proc/}"; pid="${pid%/loginuid}"
            [ "$pid" = "$$" ] && continue
            comm="$(tr '\0' ' ' < /proc/"$pid"/cmdline 2>/dev/null | cut -c1-120)"
            log "KILL pid=$pid loginuid=$u (ran as $(stat -c %U /proc/"$pid" 2>/dev/null)) cmd=$comm"
            kill -9 "$pid" 2>/dev/null
        done
    done
}

# --- 2. strip privileges from bad users ---------------------------------------------
strip_user() {
    local u="$1" g f shell home
    is_protected "$u" && return
    id "$u" >/dev/null 2>&1 || return
    for g in $PRIV_GROUPS; do
        if id -nG "$u" 2>/dev/null | tr ' ' '\n' | grep -qx "$g"; then
            gpasswd -d "$u" "$g" >/dev/null 2>&1 && log "FIX removed $u from group $g"
        fi
    done
    shell="$(getent passwd "$u" | cut -d: -f7)"
    if [ "$shell" != /usr/sbin/nologin ]; then
        usermod -s /usr/sbin/nologin "$u" && log "FIX $u shell $shell -> nologin"
    fi
    if ! passwd -S "$u" 2>/dev/null | awk '{exit !($2=="L")}'; then
        usermod -L -e 1 "$u" && log "FIX $u locked + expired"
    elif [ "$(getent shadow "$u" | cut -d: -f8)" != 1 ]; then
        usermod -e 1 "$u" && log "FIX $u expired"
    fi
    # sudoers lines naming the user
    for f in /etc/sudoers.d/*; do
        [ -f "$f" ] || continue
        if grep -qw -- "$u" "$f"; then
            cp -a "$f" "$EVID/$(basename "$f").$(date +%s)"; rm -f "$f"
            log "FIX removed sudoers file $f (named $u)"
        fi
    done
    if grep -qE "^[[:space:]]*${u}[[:space:]]" /etc/sudoers; then
        log "WARN /etc/sudoers itself grants $u: edit with 'visudo' (not auto-edited)"
    fi
    # SSH keys in their home
    home="$(getent passwd "$u" | cut -d: -f6)"
    for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
        if [ -s "$f" ]; then
            cp -a "$f" "$EVID/${u}_$(basename "$f").$(date +%s)"; : > "$f"
            log "FIX emptied $f"
        fi
    done
}

# --- 3. find who re-added a bad user to a group and stop it ---------------------------
# auditd logs every write to /etc/group (rule key ccdc_guard). Take the newest writer
# that is not this script, kill it and its parent chain, and mask its systemd unit.
hunt_writer() {
    command -v ausearch >/dev/null || return
    local ev pid ppid exe auid unit
    # newest identity-file write that was NOT made by this script or the operator
    ev="$(ausearch -k ccdc_guard -ts recent -i 2>/dev/null | grep -E '^type=SYSCALL' \
          | grep -v " ppid=$$ " | grep -vE " auid=(sysadmin|splunk) " | tail -1)"
    [ -n "$ev" ] || return
    [ "$ev" = "${LAST_EV:-}" ] && return
    LAST_EV="$ev"
    pid="$(sed -nE 's/.* pid=([0-9]+).*/\1/p' <<<"$ev")"
    ppid="$(sed -nE 's/.* ppid=([0-9]+).*/\1/p' <<<"$ev")"
    exe="$(sed -nE 's/.* exe=([^ ]+).*/\1/p' <<<"$ev")"
    auid="$(sed -nE 's/.* auid=([^ ]+).*/\1/p' <<<"$ev")"
    log "HUNT /etc/group or /etc/passwd written by exe=$exe pid=$pid ppid=$ppid auid=$auid"
    for p in $ppid; do
        [ -d /proc/"$p" ] || continue
        unit="$(grep -oE '[^/]+\.service' /proc/"$p"/cgroup 2>/dev/null | head -1)"
        log "HUNT parent pid=$p exe=$(readlink /proc/"$p"/exe 2>/dev/null) unit=${unit:-none} cmd=$(tr '\0' ' ' < /proc/"$p"/cmdline | cut -c1-120)"
        case "$unit" in
            ""|ssh.service|sshd.service|Splunkd.service|cron.service|systemd-logind.service|user@*.service|session-*) ;;
            *) systemctl disable --now "$unit" >/dev/null 2>&1; systemctl mask "$unit" >/dev/null 2>&1
               log "FIX stopped + masked re-applying unit $unit" ;;
        esac
        # never kill sshd/systemd/cron themselves, only the script/shell they launched
        case "$(basename "$(readlink /proc/"$p"/exe 2>/dev/null)")" in
            sshd|systemd|cron|init) ;;
            *) kill -9 "$p" 2>/dev/null && log "KILL re-applier parent pid=$p" ;;
        esac
    done
}

# --- 4. keep SSH deny list, IP blocks, masked units, clean cron ----------------------
enforce_static() {
    local ip u f
    if [ "$(cat "$DENY_FILE" 2>/dev/null)" != "DenyUsers $DENY_SSH_USERS" ]; then
        echo "DenyUsers $DENY_SSH_USERS" > "$DENY_FILE"
        sshd -t && systemctl reload ssh && log "FIX restored $DENY_FILE"
    fi
    if command -v ufw >/dev/null && ufw status | grep -q 'Status: active'; then
        for ip in $BAD_IPS; do
            ufw status | grep -qE "DENY.*$ip" || { ufw insert 1 deny from "$ip" >/dev/null && log "FIX ufw deny $ip"; }
        done
    fi
    for u in $MASK_UNITS; do
        [ "$(systemctl is-enabled "$u" 2>/dev/null)" = masked ] && continue
        systemctl list-unit-files "$u.service" >/dev/null 2>&1 || continue
        systemctl disable --now "$u" >/dev/null 2>&1; systemctl mask "$u" >/dev/null 2>&1
        log "FIX stopped + masked $u"
    done
    # cron entries that flush the firewall (keeps quotient_scoring)
    for f in /etc/cron.d/* /var/spool/cron/crontabs/*; do
        [ -f "$f" ] || continue
        if grep -qE 'iptables -F|nft flush ruleset|ufw disable' "$f"; then
            mv "$f" "$EVID/$(basename "$f").$(date +%s)" && log "FIX removed firewall-flush cron $f"
        fi
    done
}

# --- 5. scored services stay up -------------------------------------------------------
keep_services() {
    local s
    for s in $SERVICES; do
        systemctl list-unit-files "$s.service" >/dev/null 2>&1 || continue
        systemctl is-active --quiet "$s" || { systemctl start "$s" && log "FIX restarted $s"; }
    done
}

ensure_audit() {
    command -v auditctl >/dev/null || return
    auditctl -l 2>/dev/null | grep -q 'ccdc_guard' && return
    for f in $IDENTITY_FILES /etc/sudoers /etc/sudoers.d; do
        auditctl -w "$f" -p wa -k ccdc_guard 2>/dev/null
    done
}

one_pass() {
    local before after u
    before="$(for u in $BAD_USERS; do id "$u" 2>/dev/null; done)"
    kill_bad_sessions
    for u in $BAD_USERS; do strip_user "$u"; done
    after="$(for u in $BAD_USERS; do id "$u" 2>/dev/null; done)"
    [ "$before" != "$after" ] && hunt_writer
    enforce_static
    keep_services
}

case "${1:---once}" in
    --once)  ensure_audit; one_pass; log "pass complete" ;;
    --run)   ensure_audit; log "guard started (interval ${INTERVAL}s)"; while :; do one_pass; sleep "$INTERVAL"; done ;;
    --install)
        install -m 700 "$SELF" /usr/local/sbin/ccdc-guard
        cat > /etc/systemd/system/ccdc-guard.service <<'EOF'
[Unit]
Description=CCDC blue team guard (strips red team access, keeps scored services up)
After=network.target auditd.service

[Service]
ExecStart=/usr/local/sbin/ccdc-guard --run
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload && systemctl enable --now ccdc-guard
        log "installed ccdc-guard service"; systemctl --no-pager status ccdc-guard | head -5 ;;
    --uninstall)
        systemctl disable --now ccdc-guard 2>/dev/null; rm -f /etc/systemd/system/ccdc-guard.service /usr/local/sbin/ccdc-guard
        systemctl daemon-reload; log "uninstalled ccdc-guard" ;;
    --lock-files)
        # Extreme: nobody (red team or you) can change users, groups or passwords until unlocked.
        chattr +i $IDENTITY_FILES && log "LOCKED $IDENTITY_FILES (run --unlock-files before passwd / PCR changes)" ;;
    --unlock-files)
        chattr -i $IDENTITY_FILES && log "UNLOCKED $IDENTITY_FILES" ;;
    --status)
        systemctl --no-pager status ccdc-guard 2>/dev/null | head -5; lsattr $IDENTITY_FILES 2>/dev/null; tail -20 "$LOG" ;;
    -h|--help) sed -n '2,24p' "$0" ;;
    *) echo "Unknown option $1 (try --help)" >&2; exit 5 ;;
esac
