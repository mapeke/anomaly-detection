#!/usr/bin/env bash
# Фоновый трафик абонента: веб-запросы, DNS, потоковая передача (iperf3). Запуск на SUB-1/SUB-2.
# EXT-SRV: iperf3 -s -D; python3 -m http.server 80
EXT=${EXT:-203.0.113.10}; DNS=${DNS:-10.0.0.53}; DUR=${DUR:-3600}
end=$((SECONDS + DUR))
while [ $SECONDS -lt $end ]; do
  for i in $(seq 1 $((RANDOM % 5 + 1))); do curl -s -o /dev/null "http://$EXT/" & done
  dig +short @"$DNS" "host$((RANDOM % 500)).example.lab" >/dev/null &
  if [ $((RANDOM % 20)) -eq 0 ]; then iperf3 -c "$EXT" -t $((RANDOM % 20 + 5)) -b 5M >/dev/null & fi
  sleep "$(awk -v r=$RANDOM 'BEGIN{print 0.5 + (r % 30) / 10}')"
done
wait
