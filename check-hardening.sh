#!/bin/bash
# ============================================================
# Linux Hardening — Progress Checker
# Jalankan: di dalam container  bash check-hardening.sh
#           dari host           docker exec -i ubuntu-hardening bash < check-hardening.sh
# Tidak mengubah sistem, hanya membaca konfigurasi.
# ============================================================
set -u
PASS=0; FAIL=0; TOTAL=0
GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'

pass(){ TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail(){ TOTAL=$((TOTAL+1)); FAIL=$((FAIL+1)); echo -e "  ${RED}[FAIL]${NC} $1"; }
info(){ echo -e "  ${YELLOW}[INFO]${NC} $1"; }
section(){ echo ""; echo "===== $1 ====="; }

# helper baca key=value pertama di file (abaikan komentar)
get_cfg(){
  local file=$1 key=$2
  [ -f "$file" ] || { echo ""; return; }
  grep -E "^\s*${key}\s+" "$file" 2>/dev/null | grep -vE "^\s*#" | tail -1 | awk '{print $2}'
}
has_cfg(){
  local file=$1 key=$2 val=$3
  local got; got=$(get_cfg "$file" "$key")
  [ "$got" = "$val" ]
}

echo "Linux Hardening Checker — $(hostname) — $(date)"
echo "User: $(whoami) | OS: $(. /etc/os-release 2>/dev/null; echo $PRETTY_NAME)"

# ---------- 1. SSH ----------
section "1. SSH (openssh)"
if ! command -v sshd >/dev/null 2>&1 && ! dpkg -l | grep -q openssh-server; then
  info "openssh-server belum diinstall — semua cek SSH FAIL"
fi
SSHD=/etc/ssh/sshd_config
SSHD_D=$(ls /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tr '\n' ' ')
echo "Config: $SSHD"

# SSH 1: PermitRootLogin no
if has_cfg $SSHD PermitRootLogin no || grep -rqE "^\s*PermitRootLogin\s+no" $SSHD_D 2>/dev/null; then pass "PermitRootLogin no (root dilarang login SSH)"; else fail "PermitRootLogin harus 'no' (cek: grep PermitRootLogin $SSHD)"; fi
# SSH 2: PasswordAuthentication no + ChallengeResponse/KbdInteractive no
if has_cfg $SSHD PasswordAuthentication no; then pass "PasswordAuthentication no"; else fail "PasswordAuthentication harus 'no'"; fi
if has_cfg $SSHD KbdInteractiveAuthentication no || has_cfg $SSHD ChallengeResponseAuthentication no; then pass "KbdInteractive/ChallengeResponseAuthentication no"; else info "Saran: KbdInteractiveAuthentication no (jika masih yes, password bisa)"; fi
# SSH 3: AllowUsers ubuntu
if grep -E "^\s*AllowUsers\s+" $SSHD 2>/dev/null | grep -qw ubuntu; then pass "AllowUsers mengandung ubuntu"; else fail "AllowUsers harus hanya 'ubuntu' (AllowUsers ubuntu)"; fi
# SSH 4: Banner
BANNER_FILE=$(get_cfg $SSHD Banner)
if [ -n "$BANNER_FILE" ] && [ -f "$BANNER_FILE" ] && grep -qF "Authorized access only. All activity is monitored by system." "$BANNER_FILE" 2>/dev/null; then pass "Banner benar + file ada: $BANNER_FILE"; else fail "Banner harus berisi: Authorized access only. All activity is monitored by system. (file: ${BANNER_FILE:-tidak di-set})"; fi
# Tambahan: sshd jalan & port 22
if ss -tlnp 2>/dev/null | grep -q ":22 "; then pass "sshd listening port 22"; else info "sshd belum listening di 22 (service ssh belum jalan?)"; fi
# WAJIB: ubuntu bisa login pakai key .pem
if [ -f /home/ubuntu/.ssh/authorized_keys ] && [ -s /home/ubuntu/.ssh/authorized_keys ] && [ "$(stat -c %a /home/ubuntu/.ssh 2>/dev/null)" = "700" ] && [ "$(stat -c %a /home/ubuntu/.ssh/authorized_keys 2>/dev/null)" = "600" ]; then pass "ubuntu authorized_keys ada + permission 700/600 (login .pem)"; else fail "ubuntu authorized_keys kosong/salah permission (700/600) — nilai bisa 0!"; fi

# ---------- 2. NFS ----------
section "2. NFS"
EXPORTS=/etc/exports
if [ -f "$EXPORTS" ]; then cat "$EXPORTS" | grep -vE "^\s*(#|$)" | sed 's/^/  /'; else info "/etc/exports tidak ada"; fi
# NFS1: root_squash (client tidak bisa tentukan UID/GID) -> root_squash / no_root_squash tidak ada
if grep -E "^\s*/" $EXPORTS 2>/dev/null | grep -q "root_squash"; then pass "root_squash terpasang di exports"; else fail "Exports harus ada root_squash (contoh: /srv/nfs/private 192.168.0.0/24(rw,sync,root_squash,no_subtree_check))"; fi
if grep -E "^\s*/" $EXPORTS 2>/dev/null | grep -q "no_root_squash"; then fail "Ditemukan no_root_squash — harus root_squash!"; else info "Tidak ada no_root_squash (bagus)"; fi
# NFS2: hanya private & public
if grep -E "^\s*/" $EXPORTS 2>/dev/null | grep -q "/srv/nfs/private" && grep -E "^\s*/" $EXPORTS 2>/dev/null | grep -q "/srv/nfs/public"; then pass "Exports private & public ada"; else fail "Harus share /srv/nfs/private dan /srv/nfs/public"; fi
EXTRA=$(grep -E "^\s*/" $EXPORTS 2>/dev/null | grep -vE "/srv/nfs/(private|public)" || true)
if [ -n "$EXTRA" ]; then fail "Ada share di luar private/public: $EXTRA"; else info "Tidak ada share ekstra (hanya private & public)"; fi

# ---------- 3. SMB ----------
section "3. SMB (samba)"
SMB=/etc/samba/smb.conf
if [ -f "$SMB" ]; then
  MINP=$(grep -E "^\s*server min protocol" $SMB | tail -1 | awk '{print $NF}')
  MAXP=$(grep -E "^\s*server max protocol" $SMB | tail -1 | awk '{print $NF}')
  info "min protocol=${MINP:-default} max protocol=${MAXP:-default}"
  if [ "${MINP:-NT1}" != "NT1" ] && [ "${MINP:-}" != "LANMAN1" ] && [ "${MINP:-}" != "CORE" ]; then pass "SMB min protocol aman (>= SMB2, bukan versi 1)"; else fail "server min protocol harus >= SMB2 (bukan NT1/SMB1)"; fi
  # 2. anonymous/guest off
  if grep -E "^\s*map to guest" $SMB | grep -qi "never"; then pass "map to guest = never (anonymous dibatasi)"; else fail "map to guest harus 'never'"; fi
  if grep -E "^\s*guest ok|^\s*guest account" $SMB | grep -qi "yes"; then fail "guest ok = yes ditemukan — harus no"; else info "guest ok tidak yes (bagus)"; fi
  # 3. signing
  if grep -E "^\s*server signing" $SMB | grep -qi "mandatory\|required"; then pass "server signing = mandatory"; else fail "server signing harus 'mandatory' (atau required)"; fi
  # 4. encryption
  if grep -E "^\s*server encrypt" $SMB | grep -qi "mandatory\|required"; then pass "server encrypt = mandatory"; else fail "server encrypt harus 'mandatory'"; fi
  # 5. logging
  if grep -E "^\s*log (level|file|syslog)" $SMB | grep -qi .; then pass "Logging SMB terkonfigurasi"; else fail "Logging SMB belum ada (log level/file)"; fi
else
  fail "smb.conf tidak ditemukan ($SMB) — samba belum diinstall?"
fi

# ---------- 4. WEB (nginx) ----------
section "4. Web (nginx)"
NGINX_CONF=$(nginx -t 2>&1 | grep -oE "/[^ ]*nginx\.conf" | head -1); [ -z "$NGINX_CONF" ] && NGINX_CONF=/etc/nginx/nginx.conf
info "nginx conf: $NGINX_CONF"
# 1. hide version
if grep -rqE "server_tokens\s+off" /etc/nginx/ 2>/dev/null; then pass "server_tokens off (versi disembunyikan)"; else fail "Tambahkan 'server_tokens off;' di http block"; fi
# 2. tolak TRACE PUT DELETE
if grep -rqE "limit_except\s+(GET|POST|HEAD|OPTIONS)" /etc/nginx/sites-enabled/ /etc/nginx/nginx.conf 2>/dev/null || grep -rq "TRACE" /etc/nginx/ 2>/dev/null && grep -rqE "403|444" /etc/nginx/ 2>/dev/null; then pass "Metode TRACE/PUT/DELETE diblokir (limit_except / return 403)"; else fail "Blokir TRACE, PUT, DELETE (limit_except GET POST HEAD OPTIONS)"; fi
# 3. autoindex off
if grep -rqE "autoindex\s+off" /etc/nginx/ 2>/dev/null; then pass "autoindex off (directory listing mati)"; else fail "autoindex harus 'off'"; fi
# 4. access & error log aktif
if grep -rqE "access_log\s+" /etc/nginx/ 2>/dev/null && grep -rqE "error_log\s+" /etc/nginx/ 2>/dev/null; then pass "access_log & error_log aktif"; else fail "access_log & error_log harus aktif"; fi
# 5. cegah akses /etc/passwd (:: / path traversal)
if grep -rqE "location.*\.(passwd|etc)|deny.*etc|try_files" /etc/nginx/ 2>/dev/null || grep -rqE "root\s+/var/www" /etc/nginx/ 2>/dev/null; then info "Cek manual: pastikan root di web root & tidak ada ../ traversal"; else fail "Pastikan root hanya di web root, blokir akses file di luar web root (/etc/passwd)"; fi

# ---------- 5. USER MANAGEMENT ----------
section "5. User Management"
USERS="root ubuntu nfsuser guest staff"
TARGET_PW='XLmwq80C1mhlt7@'
# Policy pwquality
if [ -f /etc/security/pwquality.conf ]; then
  grep -E "^\s*(minlen|dcredit|ucredit|lcredit|ocredit)" /etc/security/pwquality.conf | grep -vE "^\s*#" | sed 's/^/  /'
  MINLEN=$(get_cfg /etc/security/pwquality.conf minlen); [ -z "$MINLEN" ] && MINLEN=$(grep -E "^\s*minlen" /etc/security/pwquality.conf | tail -1 | awk '{print $2}')
  if [ "${MINLEN:-0}" -ge 10 ] 2>/dev/null; then pass "pwquality minlen >=10 ($MINLEN)"; else fail "pwquality minlen harus >=10"; fi
  for k in dcredit ucredit lcredit ocredit; do
    V=$(grep -E "^\s*$k\s+" /etc/security/pwquality.conf | grep -vE "^\s*#" | tail -1 | awk '{print $2}')
    if [ "${V:--0}" -le -1 ] 2>/dev/null; then pass "pwquality $k=$V (<= -1)"; else fail "pwquality $k harus -1 (1 digit/upper/lower/symbol)"; fi
  done
else
  fail "pwquality.conf tidak ada / libpam-pwquality belum terpasang?"
fi
# Cek pam_pwquality di password-auth / common-password
if grep -rq "pam_pwquality" /etc/pam.d/ 2>/dev/null; then pass "pam_pwquality terpasang di PAM"; else fail "pam_pwquality belum aktif di PAM (common-password)"; fi
for U in $USERS; do
  # expiry: MAXDAYS <=15, MINDAYS 0, WARN 10
  MAX=$(chage -l $U 2>/dev/null | awk -F: '/Maximum number of days/{gsub(/ /,"",$2);print $2}')
  MIN=$(chage -l $U 2>/dev/null | awk -F: '/Minimum number of days/{gsub(/ /,"",$2);print $2}')
  WARN=$(chage -l $U 2>/dev/null | awk -F: '/Number of days of warning/{gsub(/ /,"",$2);print $2}')
  if [ -n "$MAX" ] && [ "$MAX" -le 15 ] 2>/dev/null; then pass "$U expiry max $MAX hari (<=15)"; else fail "$U MAXDAYS harus <=15 (sekarang: ${MAX:-?})"; fi
  if [ "$MIN" = "0" ]; then pass "$U expiry min 0 hari"; else fail "$U MINDAYS harus 0 (sekarang: ${MIN:-?})"; fi
  if [ "$WARN" = "10" ]; then pass "$U warning 10 hari"; else fail "$U WARN harus 10 (sekarang: ${WARN:-?})"; fi
  # password sudah diganti? tidak bisa verifikasi hash tanpa root, tandai INFO
  info "$U password harus sudah diganti menjadi: $TARGET_PW (verifikasi manual: sudo -u $U passwd / chage -l | cat)"
done

# ---------- 6. FIREWALL ----------
section "6. Firewall (ufw)"
if command -v ufw >/dev/null 2>&1; then
  ST=$(ufw status 2>/dev/null | head -1)
  info "$ST"
  if echo "$ST" | grep -qi "Status: active"; then pass "ufw aktif"; else fail "ufw belum aktif (sudo ufw enable)"; fi
  DEF=$(ufw status verbose 2>/dev/null | grep -i "Default:" | head -1)
  info "$DEF"
  if echo "$DEF" | grep -qi "deny (incoming)"; then pass "Default incoming deny"; else fail "Default incoming harus deny (ufw default deny incoming)"; fi
  for svc in "22/tcp" "80" "443" "2049/tcp" "445/tcp"; do
    if ufw status 2>/dev/null | grep -qE "^\s*$svc.*ALLOW"; then pass "ufw allow $svc"; else info "ufw allow $svc belum terdeteksi (cek manual jika pakai nama service)"; fi
  done
else
  fail "ufw belum terinstall"
fi

# ---------- RINGKASAN ----------
echo ""; echo "=================================================="
echo -e "SKOR: ${GREEN}$PASS PASS${NC} / ${RED}$FAIL FAIL${NC} / total $TOTAL"
PCT=$(( TOTAL>0 ? PASS*100/TOTAL : 0 )); echo "Progress: $PCT%"
[ "$FAIL" = "0" ] && echo "SELAMAT: semua lolos!" || echo "Lanjutkan konfigurasi manual untuk FAIL di atas, lalu testing ulang."
