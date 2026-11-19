#!/usr/bin/env bash
# setup/after_unzip.sh — chạy SAU MỖI LẦN `unzip -o` bản mới. Docker Desktop (WSL) gắn từng file host theo inode cũ;
# unzip thay file -> `docker restart` sẽ lỗi "error mounting ... no such file". Cách đúng: TẠO LẠI container (luật AI ở
# volume wazuh_etc, khóa agent ở volume wazuh_agent_etc -> không mất). Không dùng `docker restart` cho manager/agent.
set -u
cd "$(dirname "$0")/.."
docker compose -p siem10 up -d --force-recreate wazuh.manager
echo "chờ manager lên (60 s)..."; sleep 60
docker compose -p siem10 up -d --force-recreate wazuh-agent
echo "chờ agent kết nối (30 s)..."; sleep 30
python3 scripts/apply_rule.py health || { echo "chưa đạt, chờ thêm 60 s"; sleep 60; python3 scripts/apply_rule.py health; }
python3 scripts/apply_rule.py sync
