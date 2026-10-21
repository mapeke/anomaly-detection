#!/bin/bash
# Переменные окружения:
#   ROUTER_ID   — router-id OSPF (адрес loopback)
#   OSPF_NETS   — сети, объявляемые в OSPF area 0 (через пробел)
#   OSPF_NEIGHBORS — адреса OSPF-соседей на транзитных линках (NBMA)
#   EXPORT_IPS  — адреса интерфейсов, с которых экспортируются потоки (через пробел)
#   COLLECTOR   — адрес:порт коллектора NetFlow
set -e
ip addr add "${ROUTER_ID}/32" dev lo 2>/dev/null || true
# Docker назначает маршрут по умолчанию через свой шлюз — убираем: стенд изолирован
ip route del default 2>/dev/null || true
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do (echo 0 > "$f") 2>/dev/null || true; done

sed -i 's/^ospfd=no/ospfd=yes/' /etc/frr/daemons
# Сеть Docker Desktop не пересылает многоадресные hello OSPF (224.0.0.5), поэтому на транзитных
# линках используется режим NBMA (non-broadcast) с явно заданными соседями — hello идут unicast.
{
  echo "frr defaults traditional"
  echo "hostname $(hostname)"
  for nb in ${OSPF_NEIGHBORS}; do
    dev=$(ip route get "$nb" | awk '{for (i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}')
    echo "interface ${dev}"
    echo " ip ospf network non-broadcast"
    echo " ip ospf hello-interval 5"
    echo " ip ospf dead-interval 20"
    echo "!"
  done
  echo "router ospf"
  echo " ospf router-id ${ROUTER_ID}"
  for n in ${OSPF_NETS}; do echo " network ${n} area 0"; done
  for nb in ${OSPF_NEIGHBORS}; do echo " neighbor ${nb} poll-interval 10"; done
  echo " redistribute connected"
  echo "!"
} > /etc/frr/frr.conf
chown frr:frr /etc/frr/frr.conf
/usr/lib/frr/frrinit.sh start

# ждём, пока OSPF построит маршрут до коллектора
host=${COLLECTOR%%:*}
for i in $(seq 1 90); do ip route get "$host" >/dev/null 2>&1 && break; sleep 1; done
ip route get "$host" || echo "WARNING: нет маршрута до коллектора $host"

for ipaddr in ${EXPORT_IPS}; do
  dev=$(ip -o -4 addr show | awk -v a="${ipaddr}" '{split($4,p,"/"); if (p[1]==a) print $2}')
  echo "softflowd: ${ipaddr} -> ${dev} -> ${COLLECTOR}"
  # тайм-ауты как на маршрутизаторе провайдера: неактивность 15 с, активный поток 60 с
  ( while true; do
      softflowd -i "${dev}" -n "${COLLECTOR}" -v 9 -d -c "/run/softflowd-${dev}.ctl"                 -t tcp=15 -t tcp.rst=15 -t tcp.fin=15 -t udp=15 -t icmp=15 -t general=15                 -t maxlife=60 -t expint=5
      echo "softflowd ${dev} exited, restart"; sleep 2
    done ) &
done
echo "router $(hostname) ready"
exec sleep infinity
