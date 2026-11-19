#!/usr/bin/env bash
# Bước 4 (BẮT BUỘC): kiểm tra các giả định chưa từng được chạy thử cùng nhau. Dừng ở lỗi đầu tiên.
# Mỗi mục in [ok]/[LỖI]; nếu LỖI thì ĐỪNG sinh dữ liệu — kết quả sẽ không đáng tin.
cd "$(dirname "$0")/.."
DC="docker compose -p siem10"; fail=0
ok(){ echo "  [ok]   $1"; }; bad(){ echo "  [LỖI]  $1"; fail=1; }

echo "1) Apache thật trả đúng mã như mô hình site (check_site.py)"
$DC run --rm lab python3 scripts/check_site.py --host apache-target --port 80 && ok "site khớp mô hình" || bad "site lệch mô hình — xem các dòng LỆCH ở trên"

echo "2) Công cụ trong image lab"
$DC run --rm lab sh -c 'echo "thiếu: $(tr "\n" " " < /opt/missing_tools.txt)"; for t in ip curl nmap hydra dirb nikto gobuster ffuf ab wget; do command -v $t >/dev/null && echo "  có $t" || echo "  KHÔNG có $t"; done'
echo "   (thiếu công cụ nào thì tool_run.py bỏ qua spec đó; không chặn bước tiếp)"

echo "3) Log của Apache ghi ra file trong volume"
docker exec apache-target ls /usr/local/apache2/logs | grep -q siem.log && ok "siem.log tồn tại" || bad "không có siem.log"
docker exec apache-target ls /usr/local/apache2/logs | grep -q access_log && ok "access_log (combined) tồn tại" || bad "không có access_log"

echo "4) IP alias: gửi 1 request từ IP nguồn riêng và thấy đúng IP đó trong siem.log"
TESTIP=172.30.90.31
$DC run --rm lab sh -c "ip addr add $TESTIP/24 dev eth0 && python3 scripts/check_site.py --host apache-target --src-ip $TESTIP --ping"
sleep 2
N=$(docker exec apache-target grep -c " $TESTIP \"GET /about.html HTTP/1.1\" 200" /usr/local/apache2/logs/siem.log 2>/dev/null || echo 0)
[ "${N:-0}" -ge 1 ] && ok "Apache thấy srcip $TESTIP (alias hoạt động)" || bad "Apache KHÔNG thấy $TESTIP — alias không dùng được trên mạng bridge này; phải đổi cách cấp IP (xem README)"

echo "5) Agent đang kết nối manager"
$DC exec -T wazuh.manager /var/ossec/bin/agent_control -l | grep -q "apache-lab-agent.*Active" && ok "agent Active" || bad "agent chưa Active (đợi thêm 1-2 phút rồi chạy lại)"

echo "5b) Hàng đợi logcollector của agent đã nâng (setup/agent_tune.sh)"
docker exec wazuh-agent grep -qx "logcollector.queue_size=220000" /var/ossec/etc/local_internal_options.conf \
  && ok "logcollector.queue_size=220000" || bad "chưa nâng logcollector.queue_size — chạy: bash setup/agent_tune.sh"

echo "6) Decoder/rule: mỗi mã trạng thái đi vào đúng rule (wazuh-logtest)"
check_rule(){ # status rule_expected
  out=$(printf 'SIEMLAB 1790000000000000 10.9.9.9 "GET /x HTTP/1.1" %s 100\n' "$1" | $DC exec -T wazuh.manager /var/ossec/bin/wazuh-logtest 2>&1)
  echo "$out" | grep -q "id: '$2'" && ok "HTTP $1 -> rule $2" || bad "HTTP $1 KHÔNG ra rule $2"; }
check_rule 200 100010; check_rule 301 100014; check_rule 401 100011; check_rule 403 100013
check_rule 404 100012; check_rule 500 100015; check_rule 405 100016; check_rule 418 100016; check_rule 503 100015

echo "7) Cuối-đến-cuối: smoke 2 phiên, rồi coverage tầng 1->2 và 2->3"
$DC run --rm lab python3 scripts/run_batch.py --preset smoke --batch-id verify --max-sessions 2 --cooldown 130 --resume
sleep 20
$DC run --rm lab python3 scripts/audit_coverage.py --batch data/runs/verify --siem-log /apache-logs/siem.log \
   --alerts /wazuh-logs/alerts/alerts.json && ok "coverage >= 99% ở cả 2 tầng" || bad "coverage < 99% — xem số liệu theo kịch bản/mã HTTP ở trên"

echo "8) Alert đi tiếp từ manager (filebeat) vào indexer (index wazuh-alerts-*), dashboard sẽ thấy"
sleep 30
N=$(curl -sk -u admin:SecretPassword "https://127.0.0.1:9200/wazuh-alerts-*/_count?q=rule.groups:siemlab_observed" | sed -n 's/.*"count":\([0-9]*\).*/\1/p')
[ "${N:-0}" -ge 1000 ] && ok "indexer có $N alert siemlab_observed" || bad "indexer chỉ có '${N:-?}' alert siemlab_observed (kỳ vọng >= 1000 sau smoke 2 phiên; filebeat->indexer có vấn đề?)"

echo "9) Bắn nhanh (ab 5000 request, 20 luồng) từ IP riêng: đủ 5000 alert và logcollector không bỏ dòng nào"
BIP=172.30.90.30; TAG="verify$(date +%s)"
$DC run --rm lab sh -c "ip addr add $BIP/24 dev eth0 && ab -q -B $BIP -n 5000 -c 20 'http://apache-target/index.html?$TAG' >/dev/null"
sleep 60      # agent 1000 eps -> ~5 s; chờ thêm cho analysisd + chu kỳ ghi file state của logcollector
NS=$(docker exec apache-target grep -c "$TAG" /usr/local/apache2/logs/siem.log || echo 0)
NA=$($DC run --rm -T lab sh -c "grep -c '$TAG' /wazuh-logs/alerts/alerts.json" 2>/dev/null | tail -1 || echo 0)
[ "${NS:-0}" = 5000 ] && [ "${NA:-0}" = 5000 ] && ok "siem.log $NS dòng, alerts.json $NA alert" \
  || bad "siem.log ${NS:-?} dòng, alerts.json ${NA:-?} alert (kỳ vọng 5000/5000) — xem drops bên dưới"
DROPS=$(docker exec wazuh-agent cat /var/ossec/var/run/wazuh-logcollector.state 2>/dev/null | grep -o '"drops": *[0-9]*' | grep -o '[0-9]*' | sort -n | tail -1)
[ "${DROPS:-0}" = 0 ] && ok "logcollector drops = 0" || bad "logcollector drops = ${DROPS} (hàng đợi logcollector đầy — chạy setup/agent_tune.sh)"

[ $fail = 0 ] && echo "VERIFY OK. Tiếp: README mục 4 (smoke đầy đủ rồi audit)." || { echo "VERIFY CÓ LỖI."; exit 1; }
