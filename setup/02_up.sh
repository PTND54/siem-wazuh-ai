#!/usr/bin/env bash
# Bước 3: build image (apache, lab) và bật stack. Lần đầu ~10-15 phút (kéo image Wazuh).
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose -p siem10 --profile lab build apache-target lab     # lab nằm trong profile 'lab'
docker compose -p siem10 up -d wazuh.indexer wazuh.manager wazuh.dashboard apache-target wazuh-agent redis
echo "Đợi manager/indexer khởi động (khoảng 2-4 phút)..."
for i in $(seq 1 60); do
  if docker compose -p siem10 exec -T wazuh.manager /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-analysisd is running"; then
    echo "manager sẵn sàng."; break; fi
  sleep 5
done
bash setup/agent_tune.sh            # logcollector.queue_size (xem giải thích trong file)
docker compose -p siem10 ps
echo "Tiếp: bash setup/03_verify.sh   (BẮT BUỘC trước khi sinh dữ liệu)"
