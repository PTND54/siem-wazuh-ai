#!/usr/bin/env bash
# setup/propose_new.sh <batch> — bước 2c (tối thiểu): đề xuất luật từ một batch MỚI rồi để người duyệt xem.
#   1. build_dataset từ data/runs/<batch> (in alert lạ nếu có);
#   2. rule_proposer --purpose demo --label-source ai: nhãn = KẾT LUẬN CỦA AI (RF fp5) trên mọi phiên không-stress của batch đó
#      (batch mới: RF chưa học), ghi đề xuất 'DEMO-AI-R110xxx-...' (proposed);
#   3. proposal_diff: so với bộ đang áp (bộ CHÍNH THỨC, xem apply_rule.py list);
#   4. apply_rule list.
# Đề xuất từ batch mới CHỈ MINH HỌA quy trình — không thay, không làm lu mờ bộ chính thức; apply_rule.py chặn áp purpose=demo.
# Không đổi gì trên Manager. Chạy từ thư mục project trên host:  bash setup/propose_new.sh dev_rules3
set -u
cd "$(dirname "$0")/.."
B=${1:?"cần tên batch, vd: bash setup/propose_new.sh dev_rules3"}
[ -d "data/runs/$B" ] || { echo "không có data/runs/$B"; exit 1; }
L="docker compose -p siem10 run --rm -T lab"
AL='/wazuh-logs/alerts/alerts.json /wazuh-logs/alerts/*/*/ossec-alerts-*.json*'
echo "== 1. dataset từ $B"
$L python3 scripts/build_dataset.py --batches data/runs/$B --alerts $AL --out data/dataset_$B.csv </dev/null | tail -6
echo "== 2. đề xuất (minh họa)"
$L python3 scripts/rule_proposer.py --data data/dataset_$B.csv --purpose demo --label-source ai --select-splits train,val,test </dev/null | tail -12
echo "== 3. so với bộ đang áp"
$L python3 scripts/proposal_diff.py --rules output/rules_${B}_ai/rules.json </dev/null
echo "== 4. danh sách đề xuất"
python3 scripts/apply_rule.py list
echo "Báo cáo: output/rules_${B}_ai/report.md.  Xem một đề xuất: python3 scripts/apply_rule.py show <pid>"
