#!/usr/bin/env bash
# fixall.sh: one-shot cleanup + SSH / Splunk Query repair for the CCDC Splunk box.
# Safe to run repeatedly. Scored services (ssh, Splunk, chrony) are never stopped:
# ssh is only reloaded, Splunk only started if it is down.
#
# Usage:  sudo bash fixall.sh            fix everything, print a summary
#         sudo bash fixall.sh --check    report only, change nothing
#
# Evidence: /root/evidence/fixall-<time>/      Log: /var/log/ccdc-fixall.log

set -u
[ "$(id -u)" -eq 0 ] || exec sudo -- bash "$0" "$@"

MODE=fix; [ "${1:-}" = "--check" ] && MODE=check
TS="$(date +%Y%m%d-%H%M%S)"
EVID="/root/evidence/fixall-$TS"; mkdir -p "$EVID"; chmod 700 /root/evidence "$EVID"
LOG=/var/log/ccdc-fixall.log; touch "$LOG"; chmod 600 "$LOG"
ACTIONS="$EVID/human-actions.txt"; : > "$ACTIONS"

BAD_USERS="svc-chrony docker"
DENY_SSH_USERS="svc-chrony docker shadbrown"
BAD_IPS="198.51.100.17"
KNOWN_BAD_UNITS="cgroup-prsd systemd-kworker systemd-helper link-mtud neigh-gcd sssd-sync scoring systemd-journal-sync"
# services that are fine even though no Debian package owns them
UNIT_ALLOW="Splunkd SplunkForwarder splunk ccdc-guard"
TCP_OPEN="22 8000 8089 9997 5514"
UDP_OPEN="123 514 5514"
AD_IP="172.20.240.100"
SSH_SVC=ssh

log()  { printf '%s %s\n' "$(date '+%T')" "$*" | tee -a "$LOG"; }
fix()  { log "FIX   $*"; }
warn() { log "WARN  $*"; }
todo() { log "TODO  $*"; echo "- $*" >> "$ACTIONS"; }
do_()  { if [ "$MODE" = fix ]; then "$@"; else log "WOULD $*"; fi; }
section() { printf '\n===== %s =====\n' "$*" | tee -a "$LOG"; }

save() { [ -e "$1" ] && cp -a "$1" "$EVID/$(echo "$1" | tr '/' '_')" 2>/dev/null; }

neutralize_unit() {   # stop, disable, move real unit files out, mask
    local u="${1%.service}" f
    log "unit $u: $(systemctl show -p ExecStart --value "$u" 2>/dev/null | sed -nE 's/.*argv\[\]=([^;]*).*/\1/p')"
    [ "$MODE" = fix ] || { log "WOULD neutralize $u"; return; }
    systemctl disable --now "$u" >/dev/null 2>&1
    for f in /etc/systemd/system/"$u".service /lib/systemd/system/"$u".service /usr/lib/systemd/system/"$u".service; do
        if [ -f "$f" ] && [ ! -L "$f" ]; then save "$f"; rm -f "$f"; fi
    done
    systemctl daemon-reload
    systemctl mask "$u" >/dev/null 2>&1
    fix "neutralized unit $u ($(systemctl is-enabled "$u" 2>&1))"
}

disarm_file() {       # keep a copy, then remove so even 'bash file' cannot run it
    [ -e "$1" ] || return
    save "$1"; do_ rm -f "$1" && fix "removed payload $1"
}

# ---------------------------------------------------------------- 1. attacker sessions
section "1. Attacker sessions (incl. root shells opened via sudo)"
for u in $BAD_USERS; do
    uid="$(id -u "$u" 2>/dev/null)" || continue
    for lu in /proc/[0-9]*/loginuid; do
        [ "$(cat "$lu" 2>/dev/null)" = "$uid" ] || continue
        pid="${lu#/proc/}"; pid="${pid%/loginuid}"; [ "$pid" = "$$" ] && continue
        log "attacker process pid=$pid loginuid=$u cmd=$(tr '\0' ' ' < /proc/"$pid"/cmdline 2>/dev/null | cut -c1-100)"
        do_ kill -9 "$pid"
    done
    for pid in $(pgrep -u "$u"); do do_ kill -9 "$pid"; done
done

# ---------------------------------------------------------------- 2. persistence services
section "2. Backdoor services"
for u in $KNOWN_BAD_UNITS; do
    systemctl list-unit-files "$u.service" >/dev/null 2>&1 || [ -e "/etc/systemd/system/$u.service" ] || continue
    [ "$(systemctl is-enabled "$u" 2>/dev/null)" = masked ] && ! systemctl is-active --quiet "$u" && continue
    neutralize_unit "$u"
done
# Any other enabled service whose program (or the script it runs) belongs to no package.
for u in $(systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}'); do
    n="${u%.service}"
    case " $UNIT_ALLOW " in *" $n "*) continue ;; esac
    case "$n" in *@) continue ;; esac
    paths="$(systemctl show -p ExecStart --value "$n" 2>/dev/null | sed -nE 's/.*argv\[\]=([^;]*).*/\1/p' | tr ' ' '\n' | grep '^/' | head -2)"
    for p in $paths; do
        [ -f "$p" ] || continue
        if ! dpkg -S "$p" >/dev/null 2>&1 && ! dpkg -S "$(readlink -f "$p")" >/dev/null 2>&1; then
            case "$p" in /opt/splunk*|/usr/local/sbin/ccdc-guard) continue ;; esac
            warn "service $n runs $p which no package owns"
            neutralize_unit "$n"; disarm_file "$p"; break
        fi
    done
done
# Known payload files
for f in /usr/lib/systemd/systemd-journal-sync /usr/libexec/cgroup-prsd /etc/systemd-helper /bin/scoringengine; do
    disarm_file "$f"
done
# Timers that trigger non-package services
systemctl list-timers --all --no-legend 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i ~ /\.timer$/) print $i}' | while read -r t; do
    svc="$(systemctl show -p Unit --value "$t")"
    p="$(systemctl show -p ExecStart --value "$svc" 2>/dev/null | sed -nE 's/.*path=([^ ;]*).*/\1/p')"
    [ -n "$p" ] && [ -f "$p" ] && ! dpkg -S "$p" >/dev/null 2>&1 && case "$p" in /opt/splunk*) ;; *)
        warn "timer $t -> $svc runs unowned $p"; neutralize_unit "${t%.timer}"; neutralize_unit "$svc" ;; esac
done

# ---------------------------------------------------------------- 3. accounts
section "3. Backdoor accounts"
for u in $BAD_USERS; do
    id "$u" >/dev/null 2>&1 || continue
    for g in sudo adm root wheel shadow disk lxd docker; do
        id -nG "$u" | tr ' ' '\n' | grep -qx "$g" && do_ gpasswd -d "$u" "$g" >/dev/null && fix "$u removed from $g"
    done
    [ "$(getent passwd "$u" | cut -d: -f7)" = /usr/sbin/nologin ] || { do_ usermod -s /usr/sbin/nologin "$u"; fix "$u shell -> nologin"; }
    do_ usermod -L -e 1 "$u"
    home="$(getent passwd "$u" | cut -d: -f6)"
    for f in "$home"/.ssh/authorized_keys "$home"/.ssh/authorized_keys2; do [ -s "$f" ] && save "$f" && do_ truncate -s0 "$f" && fix "emptied $f"; done
done
for f in /etc/sudoers.d/*; do
    [ -f "$f" ] || continue; [ "$(basename "$f")" = README ] && continue
    for u in $BAD_USERS; do grep -qw -- "$u" "$f" && save "$f" && do_ rm -f "$f" && fix "removed sudoers $f"; done
done
awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | while read -r u; do todo "extra UID 0 account '$u': lock it (usermod -L -s /usr/sbin/nologin $u)"; done
log "sudo group: $(getent group sudo)"
if [ -s /root/.ssh/authorized_keys ]; then save /root/.ssh/authorized_keys; do_ truncate -s0 /root/.ssh/authorized_keys; fix "emptied root authorized_keys"; fi

# ---------------------------------------------------------------- 4. cron / preload / PAM
section "4. Cron, ld.so.preload, PAM"
for f in /etc/cron.d/* /var/spool/cron/crontabs/*; do
    [ -f "$f" ] || continue
    if grep -qE 'iptables -F|nft flush|ufw disable|systemd-journal-sync|chpasswd|usermod|useradd|/dev/tcp|nc -e' "$f"; then
        save "$f"; do_ rm -f "$f"; fix "removed malicious cron $f"
    fi
done
if [ ! -f /etc/cron.d/quotient_scoring ]; then
    if [ -f /root/.bk_etc.tgz ] && tar tzf /root/.bk_etc.tgz etc/cron.d/quotient_scoring >/dev/null 2>&1; then
        do_ tar xzf /root/.bk_etc.tgz -C / etc/cron.d/quotient_scoring && fix "restored /etc/cron.d/quotient_scoring (Splunk Query data)"
    else
        todo "/etc/cron.d/quotient_scoring is missing and no backup found: Splunk Query will fail"
    fi
fi
if [ -s /etc/ld.so.preload ]; then save /etc/ld.so.preload; do_ truncate -s0 /etc/ld.so.preload; fix "emptied /etc/ld.so.preload: $(cat "$EVID/_etc_ld.so.preload")"; fi
grep -rnE 'pam_exec|^auth.*pam_permit' /etc/pam.d/ 2>/dev/null | grep -v '^#' | while read -r l; do
    warn "PAM line worth checking: $l"
done
dpkg -V libpam-runtime libpam-modules libpam-modules-bin openssh-server sssd-common 2>/dev/null | grep -E '^..5' | grep -vE '/usr/share/| c /etc/ssh/sshd_config' | while read -r l; do
    warn "modified package file: $l"
done

# ---------------------------------------------------------------- 5. SSH
section "5. SSH (scored)"
DENY_FILE=/etc/ssh/sshd_config.d/zz-ccdc-deny.conf
for f in /etc/ssh/sshd_config.d/*.conf; do
    [ -f "$f" ] || continue; [ "$f" = "$DENY_FILE" ] && continue
    save "$f"; do_ rm -f "$f"; fix "removed unexpected sshd drop-in $f: $(grep -v '^#' "$EVID/$(echo "$f" | tr '/' '_')" | tr '\n' ';')"
done
[ "$(cat "$DENY_FILE" 2>/dev/null)" = "DenyUsers $DENY_SSH_USERS" ] || { do_ sh -c "echo 'DenyUsers $DENY_SSH_USERS' > $DENY_FILE"; fix "DenyUsers set"; }
eff="$(sshd -T 2>&1)"
echo "$eff" | grep -qx 'passwordauthentication yes' || { warn "PasswordAuthentication is off"; do_ sed -i -E 's/^#?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config; }
echo "$eff" | grep -qx 'usepam yes' || { warn "UsePAM is off"; do_ sed -i -E 's/^#?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config; }
echo "$eff" | grep -qx 'port 22' || warn "sshd is not on port 22: $(echo "$eff" | grep '^port ')"
echo "$eff" | grep -E '^(allowusers|allowgroups|denygroups) ' && warn "unexpected allow/deny lists above"
if sshd -t 2>>"$LOG"; then
    do_ systemctl reload "$SSH_SVC"; systemctl is-active --quiet "$SSH_SVC" || do_ systemctl restart "$SSH_SVC"
    fix "sshd config valid, $SSH_SVC $(systemctl is-active $SSH_SVC)"
else
    warn "sshd config INVALID, restoring hardened copy"
    for c in "$HOME/ccdcinvitational2/sshd_config" /home/sysadmin/ccdcinvitational2/sshd_config; do
        [ -f "$c" ] && do_ install -m 600 "$c" /etc/ssh/sshd_config && break
    done
    sshd -t && do_ systemctl restart "$SSH_SVC"
fi

# AD logins (scoring uses domain users through sssd)
log "AD reachability: ldap $(timeout 3 bash -c "</dev/tcp/$AD_IP/389" 2>/dev/null && echo open || echo CLOSED), kerberos $(timeout 3 bash -c "</dev/tcp/$AD_IP/88" 2>/dev/null && echo open || echo CLOSED)"
if systemctl list-unit-files sssd.service >/dev/null 2>&1; then
    if [ -f /etc/sssd/sssd.conf ]; then
        save /etc/sssd/sssd.conf
        grep -nE '^(access_provider|simple_(allow|deny)_(users|groups)|ad_access_filter|ad_gpo_access_control)' /etc/sssd/sssd.conf | while read -r l; do log "sssd access rule: $l"; done
    fi
    do_ sss_cache -E 2>/dev/null
    do_ systemctl restart sssd && fix "sssd cache cleared and restarted"
    sleep 3
    for u in paul.smith svc-splunk; do log "AD lookup $u: $(id "$u" 2>&1 | cut -c1-80)"; done
fi
fails="$(grep -E 'pam_sss\(sshd:auth\).*received for user' /var/log/auth.log 2>/dev/null | tail -200 | sed -nE 's/.*user ([^:]+): ([0-9]+) \((.*)\).*/\1 -> \3/p' | sort | uniq -c | sort -rn | head -8)"
if [ -n "$fails" ]; then
    log "recent AD SSH login failures:"; echo "$fails" | tee -a "$LOG"
    todo "AD users fail SSH with 'Authentication failure' = wrong AD password. AD owner: reset those users (and svc-splunk) to known passwords AND submit them in Quotient PCR as username,password"
fi

# ---------------------------------------------------------------- 6. firewall
section "6. Firewall"
if command -v ufw >/dev/null; then
    for p in $TCP_OPEN; do ufw status | grep -qE "^$p/tcp +ALLOW" || { do_ ufw allow "$p/tcp" >/dev/null; fix "ufw allow $p/tcp"; }; done
    for p in $UDP_OPEN; do ufw status | grep -qE "^$p/udp +ALLOW" || { do_ ufw allow "$p/udp" >/dev/null; fix "ufw allow $p/udp"; }; done
    for ip in $BAD_IPS; do ufw status | grep -qE "DENY.*$ip" || { do_ ufw insert 1 deny from "$ip" >/dev/null; fix "ufw deny $ip"; }; done
    grep -q 'icmp-type echo-request -j ACCEPT' /etc/ufw/before.rules || warn "ufw before.rules lost the ping rule"
    ufw status | grep -q 'Status: active' || warn "ufw is inactive"
fi
[ "$(sysctl -n net.ipv4.icmp_echo_ignore_all)" = 0 ] || { do_ sysctl -w net.ipv4.icmp_echo_ignore_all=0 >/dev/null; fix "ping re-enabled"; }

# ---------------------------------------------------------------- 7. Splunk
section "7. Splunk (Query + Management scored)"
if ! /opt/splunk/bin/splunk status 2>/dev/null | grep -q 'is running'; then
    warn "Splunk not running"; do_ /opt/splunk/bin/splunk start --accept-license --answer-yes --no-prompt
fi
for p in 8000 8089 9997; do ss -Htln | awk '{print $4}' | grep -q ":$p\$" && log "port $p listening" || warn "port $p NOT listening"; done
c="$(curl -sk -o /dev/null -m 5 -w '%{http_code}' https://127.0.0.1:8089/services/server/info)"; log "8089 answers HTTP $c (200/401 = healthy)"
if [ -f /var/log/scoring.log ]; then
    age=$(( $(date +%s) - $(stat -c %Y /var/log/scoring.log) ))
    [ "$age" -lt 180 ] && log "scoring.log updated ${age}s ago" || warn "scoring.log not updated for ${age}s (cron stopped?)"
    getfacl -p /var/log/scoring.log 2>/dev/null | grep -q '^user:splunk:r' || { do_ setfacl -m u:splunk:r /var/log/scoring.log 2>/dev/null || do_ chmod o+r /var/log/scoring.log; fix "splunk can read scoring.log"; }
fi
grep -rqs 'scoring.log' /opt/splunk/etc/apps/*/local/inputs.conf /opt/splunk/etc/system/local/inputs.conf \
    && log "Splunk monitors /var/log/scoring.log" \
    || todo "Splunk does not monitor /var/log/scoring.log: sudo /opt/splunk/bin/splunk add monitor /var/log/scoring.log -index main -auth admin:PASS"
grep -nE '^(authType|authSettings|admin *=)' /opt/splunk/etc/system/local/authentication.conf 2>/dev/null | while read -r l; do log "splunk auth: $l"; done
todo "If Splunk Query is still red: it logs in as an AD account (likely svc-splunk). Its AD password must match the one in Quotient PCR."

# ---------------------------------------------------------------- 8. keep the guard running
section "8. Guard"
if systemctl list-unit-files ccdc-guard.service >/dev/null 2>&1; then
    systemctl is-active --quiet ccdc-guard || { do_ systemctl start ccdc-guard; fix "ccdc-guard started"; }
    log "ccdc-guard: $(systemctl is-active ccdc-guard)"
fi

# ---------------------------------------------------------------- summary
section "SUMMARY"
log "ssh=$(systemctl is-active $SSH_SVC) splunk=$(/opt/splunk/bin/splunk status 2>/dev/null | grep -o 'is running' || echo DOWN) chrony=$(systemctl is-active chrony) guard=$(systemctl is-active ccdc-guard 2>/dev/null)"
log "svc-chrony: $(id svc-chrony 2>&1) | $(passwd -S svc-chrony 2>/dev/null | awk '{print $2}')"
log "evidence saved in $EVID"
if [ -s "$ACTIONS" ]; then echo; echo ">>> NEEDS A HUMAN:"; cat "$ACTIONS"; fi
