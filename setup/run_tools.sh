#!/usr/bin/env bash
# Chạy các công cụ thật, mỗi lần một container có IP riêng (pool .201-.250), cách nhau >= 150 s.
# Dùng: bash setup/run_tools.sh [số_lần_lặp=2]     Kết quả: data/runs/tools/sessions.jsonl (+ siem.log của Apache)
set -uo pipefail
cd "$(dirname "$0")/.."
REPS=${1:-2}; GAP=${GAP:-150}; n=0
SPECS=$(docker compose -p siem10 run --rm lab python3 scripts/tool_run.py --spec nikto --list | awk '{print $1}')
for rep in $(seq 1 "$REPS"); do
  for s in $SPECS; do
    n=$((n+1)); ip="172.30.90.$((200 + (n % 50) + 1))"
    echo ">>> $s rep=$rep từ $ip"
    docker run --rm --network siem10_net --ip "$ip" \
      -v "$PWD/scripts:/workspace/scripts:ro" -v "$PWD/data:/workspace/data" -w /workspace \
      siem-ai-lab:local python3 scripts/tool_run.py --spec "$s" --rep "$rep" || echo "   (lỗi, tiếp tục)"
    sleep "$GAP"
  done
done
