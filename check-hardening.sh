#!/bin/bash
# Checker only: PASS/FAIL tanpa clue. Clue ada di clues.md
set -u
PASS=0; FAIL=0; TOTAL=0
GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo -e "  ${RED}[FAIL]${NC} $1"; }
section(){ echo ""; echo "===== $1 ====="; }
get_cfg(){ local f=$1 k=$2; [ -f "$f" ] || { echo ""; return; }; grep -E "^\s*${k}\s+" "$f" 2>/dev/null | grep -vE "^\s*#" | tail -1 | awk '{print $2}'; }
has_cfg(){ local got; got=$(get_cfg "$1" "$2"); [ "$got" = "$3" ]; }
echo "Linux Hardening Checker — $(hostname) — $(date)"

section "1. SSH"
SSHD=/etc/ssh/sshd_config; SSHD_D=$(ls /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tr '\n' ' ')
has_cfg $SSHD PermitRootLogin no && pass "SSH1 PermitRootLogin no" || fail "SSH1 PermitRootLogin no"
has_cfg $SSHD PasswordAuthentication no && pass "SSH2 PasswordAuthentication no" || fail "SSH2 PasswordAuthentication no"
has_cfg $SSHD KbdInteractiveAuthentication no || has_cfg $SSHD ChallengeResponseAuthentication no; [ $? -eq 0 ] && pass "SSH2 KbdInteractive no" || fail "SSH2 KbdInteractive no"
grep -E "^\s*AllowUsers\s+" $SSHD 2>/dev/null | grep -qw ubuntu && pass "SSH3 AllowUsers ubuntu" || fail "SSH3 AllowUsers ubuntu"
BANNER_FILE=$(get_cfg $SSHD Banner); [ -n "$BANNER_FILE" ] && [ -f "$BANNER_FILE" ] && grep -qF "Authorized access only. All activity is monitored by system." "$BANNER_FILE" 2>/dev/null && pass "SSH4 Banner" || fail "SSH4 Banner"
ss -tlnp 2>/dev/null | grep -q ":22 " && pass "SSH Port 22" || fail "SSH Port 22"
[ -f /home/ubuntu/.ssh/authorized_keys ] && [ -s /home/ubuntu/.ssh/authorized_keys ] && [ "$(stat -c %a /home/ubuntu/.ssh 2>/dev/null)" = "700" ] && [ "$(stat -c %a /home/ubuntu/.ssh/authorized_keys 2>/dev/null)" = "600" ] && pass "SSH ubuntu key" || fail "SSH ubuntu key"

section "2. NFS"
EXPORTS=/etc/exports
grep -E "^\s*/" $EXPORTS 2>/dev/null | grep -q "root_squash" && pass "NFS1 root_squash" || fail "NFS1 root_squash"
grep -E "^\s*/" $EXPORTS 2>/dev/null | grep -q "no_root_squash" && fail "NFS1 no no_root_squash" || pass "NFS1 no no_root_squash"
grep -E "^\s*/" $EXPORTS 2>/dev/null | grep -q "/srv/nfs/private" && grep -E "^\s*/" $EXPORTS 2>/dev/null | grep -q "/srv/nfs/public" && pass "NFS2 private & public" || fail "NFS2 private & public"
EXTRA=$(grep -E "^\s*/" $EXPORTS 2>/dev/null | grep -vE "/srv/nfs/(private|public)" || true); [ -z "$EXTRA" ] && pass "NFS2 no extra share" || fail "NFS2 no extra share"

section "3. SMB"
SMB=/etc/samba/smb.conf
if [ -f "$SMB" ]; then
  MINP=$(grep -E "^\s*server min protocol" $SMB | tail -1 | awk '{print $NF}')
  { [ "${MINP:-NT1}" != "NT1" ] && [ "${MINP:-}" != "LANMAN1" ] && [ "${MINP:-}" != "CORE" ]; } && pass "SMB1 min protocol" || fail "SMB1 min protocol"
  grep -E "^\s*map to guest" $SMB | grep -qi "never" && pass "SMB2 map to guest never" || fail "SMB2 map to guest never"
  grep -E "^\s*guest ok|^\s*guest account" $SMB | grep -qi "yes" && fail "SMB2 guest ok no" || pass "SMB2 guest ok no"
  grep -E "^\s*server signing" $SMB | grep -qi "mandatory\|required" && pass "SMB3 signing mandatory" || fail "SMB3 signing mandatory"
  grep -E "^\s*server encrypt" $SMB | grep -qi "mandatory\|required" && pass "SMB4 encrypt mandatory" || fail "SMB4 encrypt mandatory"
  grep -E "^\s*log (level|file|syslog)" $SMB | grep -qi . && pass "SMB5 logging" || fail "SMB5 logging"
else fail "SMB config exists"; fi

section "4. Web"
grep -rqE "server_tokens\s+off" /etc/nginx/ 2>/dev/null && pass "WEB1 server_tokens off" || fail "WEB1 server_tokens off"
grep -rqE "limit_except\s+(GET|POST|HEAD|OPTIONS)" /etc/nginx/sites-enabled/ /etc/nginx/nginx.conf 2>/dev/null && pass "WEB2 block TRACE/PUT/DELETE" || fail "WEB2 block TRACE/PUT/DELETE"
grep -rqE "autoindex\s+off" /etc/nginx/ 2>/dev/null && pass "WEB3 autoindex off" || fail "WEB3 autoindex off"
grep -rqE "access_log\s+" /etc/nginx/ 2>/dev/null && grep -rqE "error_log\s+" /etc/nginx/ 2>/dev/null && pass "WEB4 logs active" || fail "WEB4 logs active"
grep -rqE "location.*\.(passwd|etc)|deny.*etc|try_files" /etc/nginx/ 2>/dev/null || grep -rqE "root\s+/var/www" /etc/nginx/ 2>/dev/null; [ $? -eq 0 ] && pass "WEB5 block outside web root" || fail "WEB5 block outside web root"

section "5. User Management"
USERS="root ubuntu nfsuser guest staff"
if [ -f /etc/security/pwquality.conf ]; then
  MINLEN=$(get_cfg /etc/security/pwquality.conf minlen); [ -z "$MINLEN" ] && MINLEN=$(grep -E "^\s*minlen" /etc/security/pwquality.conf | tail -1 | awk '{print $2}')
  [ "${MINLEN:-0}" -ge 10 ] 2>/dev/null && pass "USER2 minlen" || fail "USER2 minlen"
  for k in dcredit ucredit lcredit ocredit; do V=$(grep -E "^\s*$k\s+" /etc/security/pwquality.conf | grep -vE "^\s*#" | tail -1 | awk '{print $2}'); [ "${V:--0}" -le -1 ] 2>/dev/null && pass "USER2 $k" || fail "USER2 $k"; done
else fail "USER2 pwquality.conf"; fi
grep -rq "pam_pwquality" /etc/pam.d/ 2>/dev/null && pass "USER2 pam_pwquality" || fail "USER2 pam_pwquality"
for U in $USERS; do
  MAX=$(chage -l $U 2>/dev/null | awk -F: '/Maximum number of days/{gsub(/ /,"",$2);print $2}')
  MIN=$(chage -l $U 2>/dev/null | awk -F: '/Minimum number of days/{gsub(/ /,"",$2);print $2}')
  WARN=$(chage -l $U 2>/dev/null | awk -F: '/Number of days of warning/{gsub(/ /,"",$2);print $2}')
  [ -n "$MAX" ] && [ "$MAX" -le 15 ] 2>/dev/null && pass "$U expiry max" || fail "$U expiry max"
  [ "$MIN" = "0" ] && pass "$U expiry min" || fail "$U expiry min"
  [ "$WARN" = "10" ] && pass "$U expiry warn" || fail "$U expiry warn"
done

section "6. Firewall"
if command -v ufw >/dev/null 2>&1; then
  ufw status 2>/dev/null | head -1 | grep -qi "Status: active" && pass "FW1 ufw active" || fail "FW1 ufw active"
  ufw status verbose 2>/dev/null | grep -i "Default:" | head -1 | grep -qi "deny (incoming)" && pass "FW2 default deny incoming" || fail "FW2 default deny incoming"
  for svc in "22" "80" "443" "2049" "445"; do ufw status 2>/dev/null | grep -qE "^\s*$svc" && pass "FW allow $svc" || fail "FW allow $svc"; done
else fail "FW ufw installed"; fi

echo ""; echo "=================================================="
echo -e "SKOR: ${GREEN}$PASS PASS${NC} / ${RED}$FAIL FAIL${NC} / total $TOTAL"
PCT=$(( TOTAL>0 ? PASS*100/TOTAL : 0 )); echo "Progress: $PCT%"
