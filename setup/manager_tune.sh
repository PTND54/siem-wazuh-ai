#!/usr/bin/env bash
# setup/manager_tune.sh — TẮT vulnerability detection và syscollector của Wazuh Manager (lab không cần: không agent nào
# gửi danh mục phần mềm để quét lỗ hổng). Lý do (bước 2b, 26/10): sau khi Manager khởi động (và mỗi feed-update-interval
# 60m), tác vụ này ngốn 1-2 nhân CPU + nghẽn đĩa nhiều phút, làm Apache ghi log trễ tới 3 s và generator trễ lịch tới 6 s.
# Sửa file cấu hình gắn vào container (vendor/.../wazuh_manager.conf); idempotent; giữ bản sao .orig lần đầu.
# Có hiệu lực sau khi TẠO LẠI container: docker compose -p siem10 up -d --force-recreate wazuh.manager
set -eu
cd "$(dirname "$0")/.."
F=vendor/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf
[ -f "$F" ] || { echo "không thấy $F (chạy setup/00_clone_wazuh.sh trước)"; exit 1; }
[ -f "$F.orig" ] || cp -v "$F" "$F.orig"
python3 - "$F" <<'P'
import re, sys
p = sys.argv[1]; s = open(p, encoding="utf-8").read(); o = s
s = re.sub(r"(<vulnerability-detection>\s*<enabled>)yes(</enabled>)", r"\1no\2", s)
s = re.sub(r'(<wodle name="syscollector">\s*<disabled>)no(</disabled>)', r"\1yes\2", s)
vd = re.search(r"<vulnerability-detection>\s*<enabled>(\w+)</enabled>", s)
sc = re.search(r'<wodle name="syscollector">\s*<disabled>(\w+)</disabled>', s)
if not vd or not sc:
    sys.exit("không tìm thấy khối vulnerability-detection / syscollector như mong đợi — KHÔNG sửa")
open(p, "w", encoding="utf-8").write(s)
print(f"vulnerability-detection enabled={vd.group(1)}; syscollector disabled={sc.group(1)}; {'đã sửa' if s != o else 'không đổi (đã sửa từ trước)'}")
P
diff "$F.orig" "$F" || true
