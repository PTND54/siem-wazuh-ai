#!/usr/bin/env bash
# Nâng hàng đợi của logcollector trên agent (mặc định 1024). Chạy lại bao nhiêu lần cũng được.
#
# Vì sao (đo trên máy thật 21/10/2026, batch tools1): công cụ bắn nhanh (dirb, gobuster, ffuf, nikto, ab) làm hàng đợi
# xuất của logcollector đầy và logcollector ÂM THẦM BỎ DÒNG: 59 404 / 122 656 dòng siem.log không thành alert, khớp
# tuyệt đối với "drops" trong /var/ossec/var/run/wazuh-logcollector.state; agentd/remoted/analysisd đều 0 mất; không có
# cảnh báo, không có alert 202-204, Dashboard không cho thấy gì. Generator (<= 150 rps) chưa bao giờ chạm giới hạn này.
#
# Ghi vào /var/ossec/etc/local_internal_options.conf (nằm trong volume wazuh_agent_etc -> giữ qua --force-recreate).
# 220000 là giá trị tối đa Wazuh chấp nhận cho logcollector.queue_size.
set -euo pipefail
OPT="logcollector.queue_size=220000"
F=/var/ossec/etc/local_internal_options.conf
if docker exec wazuh-agent grep -qx "$OPT" "$F"; then
  echo "[ok] agent đã có $OPT"
else
  docker exec wazuh-agent sh -c "sed -i '/^logcollector.queue_size=/d' $F && echo '$OPT' >> $F"
  echo "đã ghi $OPT vào $F; khởi động lại agent..."
  # KHÔNG dùng docker restart: agent gắn file ./agent/ossec.conf, sau unzip -o restart sẽ lỗi "error mounting"
  (cd "$(dirname "$0")/.." && docker compose -p siem10 up -d --force-recreate wazuh-agent >/dev/null)
  sleep 20
  if docker logs --since 1m wazuh-agent 2>&1 | grep -i "logcollector.queue_size" | grep -qi invalid; then
    echo "[LỖI] agent báo giá trị logcollector.queue_size không hợp lệ"; exit 1
  fi
  echo "[ok] agent đã khởi động lại với $OPT"
fi
