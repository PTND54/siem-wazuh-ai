#!/usr/bin/env bash
# setup/run_2b2.sh — bước 2b, vòng 2 (26/10): kiểm mô phỏng CHUNG (wazuh_sim.joint_fires, đọc từ mã nguồn Wazuh) trên dữ
# liệu dev_rules1 đã có, xem lỗi check_pipeline, tìm nguyên nhân 18 phiên trễ lịch, chạy rule_proposer v3.
# KHÔNG đổi gì trên Manager, KHÔNG sinh traffic. Chạy từ thư mục project, trên host (WSL). Output: output/run2b2_<giờ>/.
#   bash setup/run_2b2.sh        # tất cả;   bash setup/run_2b2.sh 3   # từ phần 3
set -u
cd "$(dirname "$0")/.."
FROM=${1:-1}
L="docker compose -p siem10 run --rm -T lab"
AL='/wazuh-logs/alerts/alerts.json /wazuh-logs/alerts/*/*/ossec-alerts-*.json*'
D="output/run2b2_$(date +%Y%m%d-%H%M%S)"; mkdir -p "$D"
step() { echo; echo "================ $* ================"; }
run() { echo "\$ $*" | tee -a "$D/all.log"; eval "$@" 2>&1 | tee -a "$D/all.log"; }

if [ "$FROM" -le 1 ]; then
step "1. Kiểm thử"
for t in wazuh_sim compare_rules rule_proposer; do run "$L python3 tests/test_$t.py </dev/null | tail -1"; done
run "python3 tests/test_apply_rule.py | tail -1"
run "python3 scripts/apply_rule.py list"
fi

if [ "$FROM" -le 1 ]; then
step "1b. Probe N=2 (mã nguồn: khớp ở MỌI 404 từ thứ 2; mô phỏng cũ: 2, 4, 6, 8). Chỉ logtest, không restart.
     Luật AI đang nạp không ảnh hưởng ca này (404 của 192.0.2.10 vào danh sách sid của luật thăm dò 119901)"
run "python3 scripts/wazuh_probe.py --n 2 --cases fire_index --allow-with-ai-rules"
run "cp -v \$(ls -t output/wazuh_probe_*.json | head -1) $D/"
fi

if [ "$FROM" -le 2 ]; then
step "2. Thật vs mô phỏng CHUNG trên dev_rules1 (luật đang áp: r401 N12, web_scan N15, any N500)"
run "$L python3 scripts/compare_rules.py --data data/dataset_dev_rules1.csv --alerts $AL </dev/null"
run "cp -rv output/compare_dev_rules1 $D/"
fi

if [ "$FROM" -le 3 ]; then
step "3. check_pipeline — đủ output (vòng trước chỉ thấy 'TỔNG: 1 LỖI')"
run "$L python3 scripts/check_pipeline.py --stage requests live --data data/dataset_dev_rules1.csv </dev/null > $D/check_pipeline.txt 2>&1; grep -n -E 'LỖI|==' $D/check_pipeline.txt | cut -c1-600"
fi

if [ "$FROM" -le 4 ]; then
step "4. Vì sao 18 phiên trễ lịch: dev1 (luật tắt) vs dev_rules1 (luật bật), CÙNG kế hoạch"
run "$L python3 scripts/lag_timeline.py --batches data/runs/dev1 data/runs/dev_rules1 --alerts $AL --bucket 60 </dev/null"
run "docker compose -p siem10 ps --format '{{.Service}} {{.Status}}'"
run "nproc; free -g | head -2"
fi

if [ "$FROM" -le 5 ]; then
step "5. rule_proposer v3 (giờ Wazuh làm tròn giây + kiểm tương tác) — chỉ GHI đề xuất, không áp"
run "$L python3 scripts/rule_proposer.py --data data/dataset_full1.csv --eval data/dataset_shift1.csv data/dataset_tools2.csv --metrics models/full1/metrics.json </dev/null | tail -12"
run "python3 scripts/apply_rule.py list"
run "cp -v output/rules_full1/report.md $D/rules_full1_report.md; cp -v proposals/*.json $D/"
fi

step "XONG — gửi file zip này"
run "cd output && zip -qr /mnt/d/run2b2_maythat.zip $(basename $D) && ls -l /mnt/d/run2b2_maythat.zip"
