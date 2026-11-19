#!/usr/bin/env bash
# Bước 2: kiểm tra TĨNH trước khi bật (chưa chạy container của dự án). Không sửa gì.
cd "$(dirname "$0")/.."
ok=1; chk(){ if eval "$2" >/dev/null 2>&1; then echo "  [ok]   $1"; else echo "  [LỖI]  $1  -> $3"; ok=0; fi; }
echo "== Môi trường =="
chk "docker chạy được"            "docker info"                                  "bật Docker Desktop, bật WSL integration cho distro Ubuntu"
chk "docker compose v2"           "docker compose version"                       "cập nhật Docker Desktop"
MM=$(docker run --rm alpine cat /proc/sys/vm/max_map_count 2>/dev/null || echo 0)
chk "vm.max_map_count >= 262144 (hiện $MM)" "[ ${MM:-0} -ge 262144 ]"            "PowerShell: wsl -d docker-desktop -u root -- sysctl -w vm.max_map_count=262144  (mất khi khởi động lại WSL)"
FREE=$(df -Pm . | awk 'NR==2{print $4}')
chk "ổ đĩa còn >= 15 GB (còn ${FREE} MB)" "[ ${FREE:-0} -ge 15000 ]"              "giải phóng dung lượng (images Wazuh ~4 GB + volume)"
RAM=$(free -m | awk '/Mem:/{print $2}')
chk "RAM >= 7 GB cho WSL (có ${RAM} MB)"  "[ ${RAM:-0} -ge 7000 ]"               "tăng memory trong %UserProfile%\\.wslconfig rồi wsl --shutdown"
echo "== Cổng (bind 127.0.0.1) =="
for p in 8080 8443 9200 45000; do chk "cổng $p rảnh" "! (ss -ltn 2>/dev/null | grep -q ':$p ')" "tắt tiến trình đang dùng cổng $p (còn stack v9 chưa down?)"; done
echo "== Tệp dự án =="
chk "vendor/wazuh-docker"          "[ -d vendor/wazuh-docker/single-node/config ]" "bash setup/00_clone_wazuh.sh"
# thư mục chứng chỉ thuộc root (user thường không đọc được) -> kiểm qua Docker
chk "chứng chỉ TLS"               "docker run --rm -v \"$PWD/vendor/wazuh-docker/single-node/config/wazuh_indexer_ssl_certs:/c:ro\" alpine test -f /c/root-ca.pem" "bash setup/00_clone_wazuh.sh"
chk "docker compose config hợp lệ" "docker compose -p siem10 config --quiet" "sửa lỗi cú pháp compose"
chk "apache/htdocs đã sinh"        "[ -f apache/htdocs/index.html ] && [ -f apache/.htpasswd ]" "python3 apache/gen_site.py"
for c in apache-target wazuh-agent redis ai-service; do
  chk "container cũ '$c' không tồn tại (hoặc thuộc thư mục này)" \
      "! docker inspect $c >/dev/null 2>&1 || [ \"\$(docker inspect -f '{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}' $c)\" = \"$PWD\" ]" \
      "stack v9 còn chạy: vào thư mục v9 chạy 'docker compose -p siem-ai down' (xem README mục 0)"
done
if [ $ok = 1 ]; then echo "PREFLIGHT OK. Tiếp: bash setup/02_up.sh"; else echo "PREFLIGHT CÓ LỖI — sửa rồi chạy lại."; exit 1; fi
