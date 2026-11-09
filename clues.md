# Clues — Panduan Pengerjaan Hardening

> File ini TERPISAH dari checker. Checker hanya PASS/FAIL tanpa clue.
> Gunakan file ini sebagai panduan manual.

## 1. SSH
1. Nonaktifkan login SSH untuk user root
   - `sudo nano /etc/ssh/sshd_config` → `PermitRootLogin no`
2. Nonaktifkan autentikasi password
   - `PasswordAuthentication no`
   - `KbdInteractiveAuthentication no` / `ChallengeResponseAuthentication no`
3. Batasi login SSH hanya untuk user ubuntu
   - `AllowUsers ubuntu`
4. Banner SSH
   - File banner, contoh `/etc/issue.net` isi:
     `Authorized access only. All activity is monitored by system.`
   - `Banner /etc/issue.net`
5. WAJIB: login SSH user ubuntu pakai private key `.pem`
   - `mkdir -p ~/.ssh && chmod 700 ~/.ssh`
   - isi `authorized_keys` dari `.pub`, `chmod 600`
   - `sudo systemctl restart ssh`

## 2. NFS
1. Client tidak menentukan UID/GID:
   - `/etc/exports`: `/srv/nfs/private 192.168.0.0/24(rw,sync,root_squash,no_subtree_check)`
   - sama untuk `/srv/nfs/public`
   - jangan pakai `no_root_squash`
   - `sudo exportfs -a && sudo systemctl restart nfs-kernel-server`
2. Hanya share `private` & `public`: `/srv/nfs/private`, `/srv/nfs/public`

## 3. SMB (`/etc/samba/smb.conf` di `[global]`)
1. Versi aman (bukan 1): `server min protocol = SMB2`
2. Anonymous: `map to guest = never`, `guest ok = no` per share
3. Signing: `server signing = mandatory`
4. Encryption: `server encrypt = mandatory`
5. Logging: `log level = 1`, `log file = /var/log/samba/log.%m`

## 4. Web (nginx)
1. Sembunyikan versi: `server_tokens off;` di blok `http`
2. Tolak TRACE/PUT/DELETE:
   ```nginx
   limit_except GET POST HEAD OPTIONS { deny all; }
   ```
3. Directory listing mati: `autoindex off;`
4. Log aktif: `access_log /var/log/nginx/access.log; error_log /var/log/nginx/error.log;`
5. Cegah akses di luar web root: pastikan `root /var/www/html;`, blokir `location ~ /\. { deny all; }` dan traversal `../`

## 5. User Management
1. Ganti semua password user (root, ubuntu, nfsuser, guest, staff) menjadi:
   `XLmwq80C1mhlt7@`
   - `echo "user:PASSWORD" | sudo chpasswd` / `sudo passwd user`
2. Policy di `/etc/security/pwquality.conf`:
   `minlen = 10`, `dcredit = -1`, `ucredit = -1`, `lcredit = -1`, `ocredit = -1`
   - aktifkan di PAM `pam_pwquality.so` (`/etc/pam.d/common-password`)
3. Expiry per user:
   `sudo chage -M 15 -m 0 -W 10 user`
   - MAX 15 hari, MIN 0 hari, WARN 10 hari

## 6. Firewall (ufw)
- `sudo ufw default deny incoming`
- `sudo ufw default allow outgoing`
- `sudo ufw allow 22/tcp` (SSH)
- `sudo ufw allow 80,443/tcp` (Web)
- `sudo ufw allow 2049/tcp` (NFS)
- `sudo ufw allow 445/tcp` (SMB)
- `sudo ufw enable`

## Testing
Setelah konfigurasi: `sudo systemctl restart ssh/smbd/nfs-kernel-server/nginx`,
`sudo ufw status verbose`, `bash /usr/local/bin/check-hardening.sh`
