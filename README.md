# Ubuntu Container (Polos)

Container `ubuntu:latest` polos, bisa install service apapun secara manual.

## Pakai

```bash
docker compose up -d --build
docker exec -it ubuntu-lab bash

# install service manual di dalam container, contoh:
apt update && apt install -y openssh-server nginx samba nfs-kernel-server ufw

# jalankan checker
docker cp check-hardening.sh ubuntu-lab:/usr/local/bin/check-hardening.sh
docker exec ubuntu-lab bash /usr/local/bin/check-hardening.sh
```

## File
- `Dockerfile` — ubuntu polos
- `docker-compose.yml` — jalan container (tanpa ports, privileged untuk firewall)
- `check-hardening.sh` — checker progress hardening (bersih, hanya PASS/FAIL tanpa clue)
- `clues.md` — clue/panduan terpisah (tidak digabung ke checker)
