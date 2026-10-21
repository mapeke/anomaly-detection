# Маршрутизатор стенда: FRR (OSPF) + softflowd (экспорт NetFlow v9)

# softflowd 1.1.0 из Debian открывает захват с pcap_set_timeout(0): при TPACKET_V3 пакеты отдаются
# программе только целыми блоками, и при слабом трафике записи потоков задерживаются на минуты.
# Собираем тот же тег v1.1.0 с тайм-аутом захвата 100 мс.
FROM debian:bookworm-slim AS softflowd
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf automake libpcap-dev ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN curl -sL https://github.com/irino/softflowd/archive/refs/tags/softflowd-v1.1.0.tar.gz | tar xz --strip-components=1 \
    && sed -i 's/pcap_set_timeout (\*pcap, 0)/pcap_set_timeout (*pcap, 100)/' softflowd.c \
    && grep -q 'pcap_set_timeout (\*pcap, 100)' softflowd.c \
    && autoreconf -i && ./configure --prefix=/usr/local && make -j4 && make install

FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        frr libpcap0.8 iproute2 iputils-ping tcpdump procps \
    && rm -rf /var/lib/apt/lists/*
COPY --from=softflowd /usr/local/sbin/softflowd /usr/local/sbin/softflowctl /usr/local/sbin/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
