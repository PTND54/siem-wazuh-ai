#!/usr/bin/env bash
# Bước 1 (một lần): lấy cấu hình + sinh chứng chỉ TLS của wazuh-docker v4.14.7 vào vendor/.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ ! -d vendor/wazuh-docker ]; then
  mkdir -p vendor
  git clone --branch v4.14.7 --depth 1 https://github.com/wazuh/wazuh-docker.git vendor/wazuh-docker
else
  echo "vendor/wazuh-docker đã có, bỏ qua clone."
fi
CERTS=vendor/wazuh-docker/single-node/config/wazuh_indexer_ssl_certs
# Generator tạo thư mục chứng chỉ thuộc root, user thường KHÔNG đọc được (nên `[ -f ... ]` luôn sai).
# Kiểm qua Docker (daemon chạy quyền root) để không sinh lại chứng chỉ mỗi lần chạy script.
certs_ok(){ [ -d "$CERTS" ] && docker run --rm -v "$PWD/$CERTS:/c:ro" alpine test -f /c/root-ca.pem; }
if ! certs_ok; then
  ( cd vendor/wazuh-docker/single-node && docker compose -f generate-indexer-certs.yml run --rm generator )
else
  echo "Chứng chỉ đã có trong $CERTS, bỏ qua."
fi
echo "OK. Tiếp theo: bash setup/01_preflight.sh"
