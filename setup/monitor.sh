#!/usr/bin/env bash
# setup/monitor.sh <file.csv> — ghi ~5 s/lần (ts,kind,key,value): CPU% + RAM từng container, RAM còn dùng được + swap
# của máy ảo WSL (dùng chung với Docker Desktop), PSI (áp lực bộ nhớ/IO/CPU nếu kernel có), Redis đang ghi đĩa nền
# (AOF rewrite / RDB bgsave). Dừng bằng kill. Dùng với: lag_timeline.py --monitor <file.csv>
OUT=${1:?file csv}
echo "ts,kind,key,value" > "$OUT"
while true; do
  ts=$(date +%s.%N)
  docker stats --no-stream --format '{{.Name}},{{.CPUPerc}},{{.MemUsage}}' 2>/dev/null | \
    awk -F, -v t="$ts" '{c=$2; sub(/%/,"",c); split($3,m," "); print t",cpu,"$1","c; print t",mem,"$1","m[1]}' >> "$OUT"
  free -m | awk -v t="$ts" '/^Mem:/{print t",sys,mem_avail_mb,"$7} /^Swap:/{print t",sys,swap_used_mb,"$3}' >> "$OUT"
  docker exec redis redis-cli INFO persistence 2>/dev/null | tr -d '\r' | \
    awk -F: -v t="$ts" '/^(aof_rewrite_in_progress|rdb_bgsave_in_progress|aof_current_size)/{print t",redis,"$1","$2}' >> "$OUT"
  for r in memory io cpu; do
    [ -r /proc/pressure/$r ] && awk -v t="$ts" -v r="$r" '/^some/{split($2,a,"="); print t",psi,"r"_some_avg10,"a[2]}' /proc/pressure/$r >> "$OUT"
  done
  sleep 3
done
