#!/usr/bin/env bash
# setup/run_2b4.sh — bước 2b, vòng 4 (26/10): máy chậm theo đợt có phải do vulnerability detection của Manager không?
#   1. XÁC NHẬN: restart Manager, 5 phút chụp tiến trình ngốn CPU trong container mỗi 15 s + log liên quan;
#   2. TẮT vulnerability detection + syscollector của Manager (setup/manager_tune.sh), TẠO LẠI container, kiểm sức khỏe;
#   3. KIỂM LẠI trong điều kiện xấu nhất: chạy NGAY batch dev_rules3 (preset dev, ~20 phút, cùng kế hoạch dev1/dev_rules1/2)
#      có giám sát; đạt nếu không còn phiên bị loại vì trễ lịch.
# Không đổi luật AI. Chạy từ thư mục project, trên host (WSL). Output: output/run2b4_<giờ>/.  bash setup/run_2b4.sh [phần]
set -u
cd "$(dirname "$0")/.."
FROM=${1:-1}
L="docker compose -p siem10 run --rm -T lab"
AL='/wazuh-logs/alerts/alerts.json /wazuh-logs/alerts/*/*/ossec-alerts-*.json*'
M=siem10-wazuh.manager-1
D="output/run2b4_$(date +%Y%m%d-%H%M%S)"; mkdir -p "$D"
step() { echo; echo "================ $* ================"; }
run() { echo "\$ $*" | tee -a "$D/all.log"; eval "$@" 2>&1 | tee -a "$D/all.log"; }
psm() { docker exec $M sh -c 'ps -eo pid,pcpu,rss,etime,comm --sort=-pcpu 2>/dev/null | head -6 || top -b -n1 | head -14'; }

if [ "$FROM" -le 1 ]; then
step "1. Xác nhận: restart Manager rồi xem tiến trình nào ngốn CPU (5 phút)"
run "docker compose -p siem10 up -d --force-recreate wazuh.manager"   # KHÔNG dùng restart: file gắn từ host đổi inode sau unzip -o
for i in $(seq 1 20); do
  sleep 15
  { echo "--- +$((i*15)) s sau restart  $(date +%T)"; psm; docker stats --no-stream --format '{{.Name}} {{.CPUPerc}}' $M; } 2>&1 | tee -a "$D/all.log"
done
run "docker exec $M sh -c 'du -sh /var/ossec/queue/vd* /var/ossec/queue/indexer 2>/dev/null'"
run "docker exec $M grep -iE 'vulnerab|content|feed|syscollector|indexer-connector' /var/ossec/logs/ossec.log | tail -25"
run "python3 scripts/apply_rule.py health"
fi

if [ "$FROM" -le 2 ]; then
step "2. Tắt vulnerability detection + syscollector của Manager, tạo lại container"
run "bash setup/manager_tune.sh"
run "docker compose -p siem10 up -d --force-recreate wazuh.manager"
echo "chờ manager lên (90 s)..."; sleep 90
run "python3 scripts/apply_rule.py health || { echo 'chưa đạt, chờ thêm 60 s'; sleep 60; python3 scripts/apply_rule.py health; }"
run "python3 scripts/apply_rule.py sync"
run "docker exec $M sh -c \"grep -A1 '<vulnerability-detection>' /var/ossec/etc/ossec.conf; grep -A1 'wodle name=.syscollector' /var/ossec/etc/ossec.conf\""
run "docker exec $M ls /var/ossec/etc/rules/"
fi

if [ "$FROM" -le 3 ]; then
step "3. Kiểm lại NGAY sau khi tạo lại Manager: batch dev_rules3 (~20 phút) + giám sát"
bash setup/monitor.sh "$D/monitor.csv" & MON=$!
run "$L python3 scripts/run_batch.py --preset dev --batch-id dev_rules3 </dev/null | tail -4"
echo "chờ pipeline xả (60 s)..."; sleep 60
{ echo "--- tiến trình Manager sau batch"; psm; } 2>&1 | tee -a "$D/all.log"
kill $MON 2>/dev/null; wait $MON 2>/dev/null
run "$L python3 scripts/audit_coverage.py --batch data/runs/dev_rules3 --siem-log /apache-logs/siem.log --alerts $AL </dev/null | tail -4"
run "$L python3 scripts/build_dataset.py --batches data/runs/dev_rules3 --alerts $AL --out data/dataset_dev_rules3.csv </dev/null | tail -4"
run "$L python3 scripts/check_pipeline.py --stage requests --data data/dataset_dev_rules3.csv </dev/null 2>&1 | grep -E 'LỖI|OK|TỔNG' | cut -c1-400"
run "$L python3 scripts/lag_timeline.py --batches data/runs/dev_rules1 data/runs/dev_rules2 data/runs/dev_rules3 --alerts $AL --bucket 60 --monitor /workspace/$D/monitor.csv </dev/null"
run "cp -v data/dataset_dev_rules3.audit.json $D/"
fi

step "XONG — gửi file zip này"
run "cd output && zip -qr /mnt/d/run2b4_maythat.zip $(basename $D) && ls -l /mnt/d/run2b4_maythat.zip"
