FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive

# Polos — hanya tools dasar agar bisa install service apapun secara manual
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates sudo curl wget vim nano \
    iproute2 iputils-ping net-tools psmisc procps \
 && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY check-hardening.sh /usr/local/bin/check-hardening.sh
RUN chmod +x /usr/local/bin/check-hardening.sh

WORKDIR /root
CMD ["sleep", "infinity"]
