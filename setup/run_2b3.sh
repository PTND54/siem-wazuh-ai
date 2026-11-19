#!/usr/bin/env bash
# setup/run_2b3.sh — bước 2b, vòng 3 (26/10):
#   1. chẩn đoán nhanh (không đổi gì): Redis ghi đĩa nền bao nhiêu lần, RAM/swap của máy ảo WSL;
#   2. THAY luật any N=500 bằng N=600 (đề xuất v3) — chỉ chạy khi gõ đúng "dong y";
#   3. traffic preset dev, batch dev_rules2 (~20 phút) VỪA chạy VỪA giám sát (setup/monitor.sh);
#   4. đối chiếu: luật thật vs mô phỏng chung (bộ mới), check_pipeline, trễ lịch dev1 / dev_rules1 / dev_rules2 + giám sát.
# Chạy từ thư mục project, trên host (WSL). Output: output/run2b3_<giờ>/.   bash setup/run_2b3.sh [phần bắt đầu]
set -u
cd "$(dirname "$0")/.."
FROM=${1:-1}
L="docker compose -p siem10 run --rm -T lab"
AL='/wazuh-logs/alerts/alerts.json /wazuh-logs/alerts/*/*/ossec-alerts-*.json*'
D="output/run2b3_$(date +%Y%m%d-%H%M%S)"; mkdir -p "$D"
step() { echo; echo "================ $* ================"; }
run() { echo "\$ $*" | tee -a "$D/all.log"; eval "$@" 2>&1 | tee -a "$D/all.log"; }

if [ "$FROM" -le 1 ]; then
step "1. Chẩn đoán nhanh (không đổi gì)"
run "for t in wazuh_sim trainer rule_proposer compare_rules; do printf '%s ' \$t; $L python3 tests/test_\$t.py </dev/null 2>&1 | tail -1; done"
run "docker exec redis redis-cli INFO persistence | tr -d '\r' | grep -E 'aof_enabled|aof_rewrites|aof_last_rewrite_time_sec|aof_current_size|aof_base_size|rdb_saves|rdb_last_bgsave_time_sec'"
run "docker exec redis redis-cli INFO memory | tr -d '\r' | grep -E '^used_memory_human|^used_memory_peak_human'"
run "docker exec redis redis-cli INFO stats | tr -d '\r' | grep -E 'total_forks|latest_fork_usec'"
run "docker exec redis redis-cli DBSIZE"
run "docker logs -t redis 2>&1 | grep -i -E 'rewrit|background|saving|fork' | tail -30"
run "free -m; cat /proc/swaps; for r in memory io cpu; do echo \$r; cat /proc/pressure/\$r 2>/dev/null; done"
run "docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}'"
fi

if [ "$FROM" -le 2 ]; then
step "2. Thay luật any: gỡ N=500, áp N=600 (mỗi bước: analysisd -t, restart, sức khỏe, logtest 601 dòng)"
OLD=$(ls proposals | grep -E '^R110030-any-N500-' | sed 's/\.json$\|\.xml$//' | sort -u | tail -1)
NEW=$(ls proposals | grep -E '^R110030-any-N600-' | sed 's/\.json$\|\.xml$//' | sort -u | tail -1)
echo "gỡ: $OLD    áp: $NEW"
read -r -p ">>> Gõ 'dong y' để thay luật (khác -> bỏ qua phần 2): " OK
if [ "$OK" = "dong y" ]; then
  run "python3 scripts/apply_rule.py remove $OLD --yes --by \$USER"
  run "python3 scripts/apply_rule.py apply $NEW --yes --by \$USER"
  run "python3 scripts/apply_rule.py list | tail -4"
  run "python3 scripts/apply_rule.py sync"
else
  echo "BỎ QUA phần 2 — dừng ở đây (phần 3-4 cần bộ luật mới)."; exit 0
fi
fi

if [ "$FROM" -le 3 ]; then
step "3. Traffic preset dev, batch dev_rules2 (~20 phút) + giám sát mỗi ~5 s"
bash setup/monitor.sh "$D/monitor.csv" & MON=$!
run "$L python3 scripts/run_batch.py --preset dev --batch-id dev_rules2 </dev/null | tail -8"
echo "chờ pipeline xả (60 s)..."; sleep 60
kill $MON 2>/dev/null; wait $MON 2>/dev/null
run "wc -l $D/monitor.csv"
fi

if [ "$FROM" -le 4 ]; then
step "4. Đối chiếu"
run "$L python3 scripts/audit_coverage.py --batch data/runs/dev_rules2 --siem-log /apache-logs/siem.log --alerts $AL </dev/null | tail -6"
run "$L python3 scripts/build_dataset.py --batches data/runs/dev_rules2 --alerts $AL --out data/dataset_dev_rules2.csv </dev/null | tail -4"
run "$L python3 scripts/compare_rules.py --data data/dataset_dev_rules2.csv --alerts $AL </dev/null"
run "$L python3 scripts/check_pipeline.py --stage requests live --data data/dataset_dev_rules2.csv </dev/null > $D/check_pipeline.txt 2>&1; grep -n -E 'LỖI|OK|==' $D/check_pipeline.txt | cut -c1-400"
MONARG=""; [ -s "$D/monitor.csv" ] && MONARG="--monitor /workspace/$D/monitor.csv"
run "$L python3 scripts/lag_timeline.py --batches data/runs/dev1 data/runs/dev_rules1 data/runs/dev_rules2 --alerts $AL --bucket 60 $MONARG </dev/null"
run "cp -rv output/compare_dev_rules2 $D/ && cp -v data/dataset_dev_rules2.audit.json proposals/R110*.json $D/"
fi

step "XONG — gửi file zip này"
run "cd output && zip -qr /mnt/d/run2b3_maythat.zip $(basename $D) && ls -l /mnt/d/run2b3_maythat.zip"
