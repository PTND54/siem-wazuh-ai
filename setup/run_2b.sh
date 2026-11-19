#!/usr/bin/env bash
# setup/run_2b.sh — bước 2b: kiểm chứng luật đề xuất trên Wazuh THẬT. Chạy từ thư mục project, trên host (WSL).
# Mỗi phần dừng lại hỏi Enter; mọi output ghi vào output/run2b_<giờ>/. Không chạy khi đang sinh dữ liệu khác.
#   bash setup/run_2b.sh            # chạy tất cả
#   bash setup/run_2b.sh 4          # chạy từ phần 4
set -u
cd "$(dirname "$0")/.."
FROM=${1:-1}
L="docker compose -p siem10 run --rm -T lab"
AL='/wazuh-logs/alerts/alerts.json /wazuh-logs/alerts/*/*/ossec-alerts-*.json*'
D="output/run2b_$(date +%Y%m%d-%H%M%S)"; mkdir -p "$D"
step() { echo; echo "================ $* ================"; }
pause() { read -r -p ">>> $* — Enter để tiếp (Ctrl+C dừng) " _; }
run() { echo "\$ $*" | tee -a "$D/all.log"; eval "$@" 2>&1 | tee -a "$D/all.log"; }

if [ "$FROM" -le 1 ]; then
step "1. Kiểm thử + điều kiện ban đầu"
run "python3 tests/test_apply_rule.py | tail -1"
for t in compare_rules rule_proposer wazuh_sim; do run "$L python3 tests/test_$t.py </dev/null | tail -1"; done
run "grep -c 'proposals:/workspace/proposals' docker-compose.yml"      # phải >= 1 (lab thấy thư mục proposals)
run "docker exec siem10-wazuh.manager-1 grep -c 'siem10-ai BEGIN' /var/ossec/etc/rules/local_rules.xml"   # phải 0
run "python3 scripts/apply_rule.py list"
run "python3 scripts/apply_rule.py health"
pause "Kiểm: test OK, mount proposals >= 1, khối AI cũ = 0, health ĐẠT"
fi

if [ "$FROM" -le 2 ]; then
step "2. Probe tương tác 2 luật (TRƯỚC khi áp luật AI)"
run "python3 scripts/wazuh_probe.py --cases fire_index interact_scan_first interact_any_first interact_mixed"
run "cp -v \$(ls -t output/wazuh_probe_*.json | head -1) $D/"
pause "Xong probe"
fi

if [ "$FROM" -le 3 ]; then
step "3. Luật AI ở file riêng có sống qua việc TẠO LẠI manager không (canary, chỉ khớp 192.0.2.x)"
run "python3 scripts/apply_rule.py make-canary --rule-id 119830 | tee $D/canary.txt"
C=$(grep -o 'CANARY-[0-9-]*' "$D/canary.txt" | head -1); echo "canary = $C"
run "python3 scripts/apply_rule.py apply $C --yes --by \$USER"
run "docker exec siem10-wazuh.manager-1 ls -l /var/ossec/etc/rules/"
run "docker compose -p siem10 up -d --force-recreate wazuh.manager"
echo "chờ manager lên (90 s)..."; sleep 90
run "python3 scripts/apply_rule.py health"          # nếu agent không Active sau 4 phút: docker compose -p siem10 up -d --force-recreate wazuh-agent, chạy lại health
run "python3 scripts/apply_rule.py verify $C"       # phải KHỚP [3, 6] -> luật còn sau khi tạo lại
run "python3 scripts/apply_rule.py sync"            # phải 'trùng nhau'
run "python3 scripts/apply_rule.py remove $C --yes --by \$USER"
pause "Kiểm: verify KHỚP sau tạo lại, sync trùng, remove OK"
fi

if [ "$FROM" -le 4 ]; then
step "4. Áp 3 luật đề xuất (mỗi luật: analysisd -t, restart, sức khỏe, kiểm chức năng logtest)"
for f in r401 web_scan any; do
  P=$(ls proposals | grep -E "^R1100[0-9]+-$f-" | sed 's/\.json$\|\.xml$//' | sort -u | tail -1)
  run "python3 scripts/apply_rule.py apply $P --yes --by \$USER"
done
run "python3 scripts/apply_rule.py list"
run "python3 scripts/apply_rule.py sync"
pause "Kiểm: 3 luật 'applied' (nếu 'any' rollback vì logtest 501 dòng chậm -> báo lại, KHÔNG ép)"
fi

if [ "$FROM" -le 5 ]; then
step "5. Traffic thật khi luật đang bật: preset dev, batch dev_rules1 (~20 phút, 154 phiên)"
run "$L python3 scripts/run_batch.py --preset dev --batch-id dev_rules1 </dev/null | tail -8"
echo "chờ pipeline xả (60 s)..."; sleep 60
fi

if [ "$FROM" -le 6 ]; then
step "6. Đối chiếu"
run "$L python3 scripts/audit_coverage.py --batch data/runs/dev_rules1 --siem-log /apache-logs/siem.log --alerts $AL </dev/null | tail -6"
run "$L python3 scripts/build_dataset.py --batches data/runs/dev_rules1 --alerts $AL --out data/dataset_dev_rules1.csv </dev/null"
run "$L python3 scripts/compare_rules.py --data data/dataset_dev_rules1.csv --alerts $AL </dev/null"
run "$L python3 scripts/check_pipeline.py --stage requests live --data data/dataset_dev_rules1.csv </dev/null | tail -12"
run "cp -rv output/compare_dev_rules1 $D/ && cp -v data/dataset_dev_rules1.audit.json proposals/*.json $D/"
step "XONG — gửi file zip này"
run "cd output && zip -qr /mnt/d/run2b_maythat.zip $(basename $D) && ls -l /mnt/d/run2b_maythat.zip"
fi
