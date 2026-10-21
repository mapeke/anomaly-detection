# Образ для хостов стенда в GNS3 (SUB-1, SUB-2, EXT-SRV, ISP-SRV, ATTACKER).
# Сборка в GNS3 VM (из корня репозитория):  docker build -t nids-host -f stand/docker/Dockerfile stand
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 iputils-ping net-tools curl dnsutils iperf3 python3 \
        openssh-server dnsmasq hping3 nmap hydra tcpdump ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd && ssh-keygen -A \
    && useradd -m -s /bin/bash admin && echo 'admin:Xk9#vLq2!pR7' | chpasswd
COPY scenarios/ /opt/stand/
RUN chmod +x /opt/stand/*.sh
WORKDIR /opt/stand
CMD ["/bin/bash"]
