#!/usr/bin/env bash
# Запуск служб на хосте стенда: ./start_services.sh <роль>
case "${1:-}" in
  sub)     /usr/sbin/sshd && echo "sshd запущен (цель подбора пароля)";;
  ext)     (cd /tmp && nohup python3 -m http.server 80 >/dev/null 2>&1 &) ; iperf3 -s -D && echo "HTTP :80 и iperf3 запущены";;
  isp)     dnsmasq --no-resolv --address=/example.lab/203.0.113.10 --log-facility=/tmp/dnsmasq.log && echo "DNS запущен";;
  *)       echo "роль: sub | ext | isp"; exit 1;;
esac
