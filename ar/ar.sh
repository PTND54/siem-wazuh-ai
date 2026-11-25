#!/usr/bin/env bash
# ar/ar.sh — Active Response cho siem10. Chạy trong ~/siem-wazuh-ai (WSL). Không sửa file nào ngoài ar/.
#   bash ar/ar.sh up        cài AR trên Manager, dựng agent có iptables dùng chung mạng với Apache, chạy ar-watch
#   bash ar/ar.sh selftest  thử trọn đường đi với IP TEST-NET 192.0.2.99 (không đụng IP nào của lab)
#   bash ar/ar.sh status    trạng thái, các IP đang bị chặn, 5 dòng cuối của ar-watch
#   bash ar/ar.sh flush     xóa mọi IP đang bị chặn (không tắt AR)
#   bash ar/ar.sh down      gỡ sạch: xóa luật iptables, dừng ar-watch, agent về cấu hình luật chữ ký, gỡ AR trên Manager
# Tắt AR (down) trước khi sinh dữ liệu, chạy đánh giá hay chạy công cụ: AR sẽ chặn IP của lab.
set -euo pipefail
cd "$(dirname "$0")/.."
P=(docker compose -p siem10 -f docker-compose.yml -f sig/docker-compose.sig.yml)
PA=("${P[@]}" -f ar/docker-compose.ar.yml)

gen_agent_conf() {
  mkdir -p ar/agent
  python3 - <<'EOF'
src = open("sig/agent/ossec.conf", encoding="utf-8").read()
add = """
  <!-- SIEM10-AR: tín hiệu chặn do ar-watch sinh từ kết luận AI, và nhật ký Active Response của agent -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/ar-watch/ai_block.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>
"""
i = src.rfind("</ossec_config>")
assert i > 0, "sig/agent/ossec.conf không có </ossec_config>"
open("ar/agent/ossec.conf", "w", encoding="utf-8").write(src[:i] + add + src[i:])
print("ar/agent/ossec.conf: dựng từ sig/agent/ossec.conf + 2 localfile")
EOF
}

blocked() {
  docker exec wazuh-agent sh -c 'command -v iptables >/dev/null || { echo "  (agent không có iptables: AR chưa bật)"; exit 0; }
    iptables -S INPUT | grep -- "-j DROP" | sed "s/^/  /" || echo "  (không có IP nào bị chặn)"'
}

flush() {
  if docker exec wazuh-agent sh -c 'command -v iptables' >/dev/null 2>&1; then
    docker exec wazuh-agent sh -c 'iptables -F INPUT; iptables -F FORWARD; echo "  đã xóa mọi luật chặn"'
  elif docker image inspect siem-ai-agent-ar:local >/dev/null 2>&1; then
    docker run --rm --network container:apache-target --cap-add NET_ADMIN --entrypoint sh siem-ai-agent-ar:local \
      -c 'iptables -F INPUT; iptables -F FORWARD; echo "  đã xóa mọi luật chặn (container tạm)"'
  else
    echo "  (chưa từng dựng image AR: không có gì để xóa)"
  fi
}

status() {
  echo "== agent"
  docker inspect wazuh-agent --format '  image={{.Config.Image}} net={{.HostConfig.NetworkMode}} caps={{.HostConfig.CapAdd}}'
  docker exec wazuh-agent sh -c 'echo "  ar.conf có firewall-drop: $(grep -c firewall-drop /var/ossec/etc/shared/ar.conf 2>/dev/null || echo 0) dòng"'
  echo "== IP đang bị chặn (iptables trong mạng của apache-target)"; blocked
  echo "== ar-watch"
  docker ps --filter 'name=^ar-watch$' --format '  {{.Names}} {{.Status}}' | grep . || echo "  (không chạy)"
  docker logs --tail 5 ar-watch 2>/dev/null | sed 's/^/  /' || true
  echo "== manager"; python3 -B ar/tools/ar_manager.py status | sed 's/^/  /'
}

up() {
  test -f sig/agent/ossec.conf || { echo "thiếu sig/agent/ossec.conf"; exit 1; }
  gen_agent_conf
  echo "== 1/4 dựng image agent có iptables"; "${PA[@]}" build wazuh-agent
  echo "== 2/4 cài AR trên Manager"; python3 -B ar/tools/ar_manager.py install --yes
  echo "== 3/4 tạo lại agent (dùng chung mạng với apache-target) và chạy ar-watch"
  "${PA[@]}" up -d --no-deps --force-recreate wazuh-agent ar-watch
  echo "== 4/4 chờ agent nhận danh sách lệnh AR (tối đa 120 s)"
  for i in $(seq 1 24); do
    n=$(docker exec wazuh-agent sh -c 'grep -c firewall-drop /var/ossec/etc/shared/ar.conf 2>/dev/null || echo 0')
    [ "${n:-0}" -gt 0 ] && break; sleep 5
  done
  status
}

selftest() {
  echo "== ghi một dòng tín hiệu giả cho IP TEST-NET 192.0.2.99"
  docker exec ar-watch sh -c 'echo "SIEM10AI srcip=192.0.2.99 flagged=99 window=60 maxscore=0.999" >> /var/log/ar-watch/ai_block.log'
  for i in $(seq 1 12); do
    if docker exec wazuh-agent sh -c 'iptables -S INPUT | grep -q "192.0.2.99"'; then
      echo "✓ SELFTEST ĐẠT sau khoảng $((i * 5)) s: luật 100250 -> firewall-drop -> iptables có 192.0.2.99"
      blocked; echo "  (tự gỡ sau 180 s, hoặc: bash ar/ar.sh flush)"; return 0
    fi
    sleep 5
  done
  echo "✗ SELFTEST KHÔNG ĐẠT sau 60 s. Kiểm: alert 100250 trong alerts.json, /var/ossec/logs/active-responses.log của agent:"
  docker exec siem10-wazuh.manager-1 sh -c 'grep -c "\"id\":\"100250\"" /var/ossec/logs/alerts/alerts.json' | sed 's/^/  alert 100250 trong alerts.json: /'
  docker exec wazuh-agent sh -c 'tail -n 5 /var/ossec/logs/active-responses.log 2>/dev/null' | sed 's/^/  /'
  return 1
}

down() {
  echo "== 1/4 xóa luật iptables"; flush
  echo "== 2/4 dừng ar-watch"; "${PA[@]}" rm -sf ar-watch || true
  echo "== 3/4 agent về cấu hình luật chữ ký (bỏ dùng chung mạng)"; "${P[@]}" up -d --no-deps --force-recreate wazuh-agent
  echo "== 4/4 gỡ AR trên Manager"; python3 -B ar/tools/ar_manager.py remove --yes
}

case "${1:-status}" in
  up) up ;; down) down ;; status) status ;; flush) flush ;; selftest) selftest ;;
  *) echo "dùng: bash ar/ar.sh up|selftest|status|flush|down"; exit 2 ;;
esac
