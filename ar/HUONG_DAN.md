# Phản ứng tự động bằng Active Response: cài, thử, chạy kịch bản, gỡ

Mọi lệnh chạy trong terminal Ubuntu của WSL, từ thư mục dự án `~/siem-wazuh-ai`, khi stack đã dựng xong theo mục 3.4–3.7 của
README và luật chữ ký đang bật (mục 3.6). Phần này không sửa tệp nào ngoài thư mục `ar/`. Thiết kế và kết quả được trình bày ở
mục 3.8 của báo cáo.

## Cách hoạt động

| Nguồn kích hoạt | Luật | Chặn khi nào |
|---|---|---|
| Luật tương quan từ kết luận AI | 110011 (r401), 110020 (web_scan) | Khi luật khớp. Không nối 110030 vì trên tập đánh giá cuối luật này báo nhầm các phiên `heavy_burst`. |
| Tín hiệu AI | 100250, sinh từ dòng do `ar-watch` ghi | Khi một IP có từ 10 alert `ai.flag=true` trong 60 giây |
| Luật chữ ký | nhóm `siem10_sig` | Từ request đầu tiên làm luật khớp |

- Hành động là `firewall-drop` có sẵn của Wazuh, thời hạn 180 giây rồi tự gỡ. Agent dùng chung không gian mạng với
  `apache-target`, nên luật DROP nằm đúng chỗ request đi vào web server.
- `ar-watch` truy vấn `ai-enriched-alerts-*` mỗi 3 giây và không ghi lại tín hiệu cho cùng IP trong 180 giây.
- Danh sách loại trừ (`manager/whitelist.txt`) gồm `172.30.90.1` (gateway) và `.2`–`.8`. Dịch vụ của stack nhận IP tự động
  trong khoảng `.2`–`.14`, nên trước khi bật, kiểm rằng không dịch vụ nào đang ở `.9` trở lên:
  `docker network inspect siem10_net --format '{{range .Containers}}{{.Name}} {{.IPv4Address}}{{"\n"}}{{end}}'`.

## 1. Cài

```bash
bash ar/ar.sh up
```

Các bước bên trong lệnh:
1. Dựng image agent có cài thêm iptables (`ar/Dockerfile`).
2. Cài phần AR trên Manager bằng `tools/ar_manager.py`, theo trình tự của `scripts/apply_rule.py`: kiểm sức khỏe trước, ghi
   cấu hình, `wazuh-analysisd -t` không có cảnh báo mới, `wazuh-execd -t`, khởi động lại bằng `wazuh-control` bên trong
   container, chờ agent kết nối lại, kiểm sức khỏe bằng request canary, kiểm luật 100250 bằng `wazuh-logtest`. Bước nào không đạt
   thì công cụ ghi lại cấu hình cũ và khởi động lại.
3. Tạo lại agent ở chế độ dùng chung mạng với `apache-target`, rồi chạy `ar-watch`.
4. Chờ agent nhận danh sách lệnh Active Response, rồi in trạng thái.

Kết quả cần thấy:
- `✓ đã cài Active Response trên Manager`;
- `net=container:…` ở dòng agent;
- `ar.conf có firewall-drop` lớn hơn 0;
- `ar-watch Up`.

Nhật ký và bản sao `ossec.conf` của mỗi lần cài, gỡ nằm trong `ar/runs/`.

## 2. Thử trọn đường đi, không đụng IP của lab

```bash
bash ar/ar.sh selftest
bash ar/ar.sh flush
```

`selftest` ghi một dòng tín hiệu cho IP TEST-NET `192.0.2.99` rồi chờ đường đi luật 100250 → firewall-drop → iptables.
Kết quả cần thấy: `✓ SELFTEST ĐẠT`. `flush` gỡ lệnh chặn đó.

## 3. Chạy kịch bản

Mỗi kịch bản dùng một IP chưa có dữ liệu gần đây trong dải `.9`–`.254`. Một IP chỉ dùng lại sau ít nhất 300 giây, vì lệnh chặn
kéo dài 180 giây, `ar-watch` không ghi lại tín hiệu cho cùng IP trong 180 giây, và các cửa sổ đếm của AI và của luật vẫn còn giữ
sự kiện cũ. Danh sách IP đã có alert:

```bash
docker exec siem10-wazuh.manager-1 sh -c 'cat /var/ossec/logs/alerts/alerts.json /var/ossec/logs/alerts/2026/*/ossec-alerts-*.json 2>/dev/null | grep -o "\"srcip\":\"172\.30\.90\.[0-9]*\"" | sort -u' | grep -o '[0-9]*"$' | tr -d '"' > /tmp/used.txt
python3 -c "u={int(x) for x in open('/tmp/used.txt')}; print('IP chưa dùng:', [i for i in range(9,255) if i not in u])"
```

Trong các lệnh dưới, thay `X` bằng IP đã chọn. `tools/demo_send.py` gửi lần lượt từng request, chờ phản hồi tối đa 2 giây, dừng
sau 5 request liên tiếp không có phản hồi và in `==> NGUỒN BỊ CHẶN` kèm request cuối cùng còn nhận được phản hồi. Cửa sổ thứ hai
có thể chạy `watch -n 2 bash ar/ar.sh status` để xem danh sách IP đang bị chặn.

**3a. Dò thư mục nhanh: luật 110020 chặn.**

```bash
docker run --rm --network siem10_net --ip 172.30.90.X -v "$PWD/ar:/workspace/ar:ro" siem-ai-lab:local \
  python3 -I /workspace/ar/tools/demo_send.py --wordlist /usr/share/dirb/wordlists/common.txt --rate 20 --limit 400
```

Nguồn bị chặn vài giây sau alert 110020 đầu tiên. Trên Discover (`wazuh-alerts-*`), `data.srcip:172.30.90.X and rule.level >= 10`
có alert 110020, và thường có thêm alert 100250 khoảng 10 giây sau.

**3b. Payload SQL injection: luật chữ ký chặn.**

```bash
docker run --rm --network siem10_net --ip 172.30.90.X -v "$PWD/ar:/workspace/ar:ro" -v "$PWD/sig:/workspace/sig:ro" siem-ai-lab:local \
  python3 -I /workspace/ar/tools/demo_send.py --cases /workspace/sig/payloads/test2/cases.jsonl --category sqli --encoding E1 --rate 1 --limit 30
```

Payload đầu tiên làm luật chữ ký khớp vẫn tới máy chủ, các request sau không còn phản hồi. Trên Discover,
`data.srcip:172.30.90.X and rule.groups:siem10_sig`.

**3c. Dò thư mục chậm: luật tương quan không khớp, tín hiệu AI chặn.** Một request mỗi giây cho khoảng 10 lỗi trong 10 giây,
dưới ngưỡng 15 của luật 110020.

```bash
docker run --rm --network siem10_net --ip 172.30.90.X -v "$PWD/ar:/workspace/ar:ro" siem-ai-lab:local \
  python3 -I /workspace/ar/tools/demo_send.py --wordlist /usr/share/dirb/wordlists/common.txt --skip 100 --rate 1 --limit 240
docker logs --since 3m ar-watch | grep 172.30.90.X
```

Nguồn bị chặn sau khoảng 20 request. `ar-watch` có dòng `-> SIEM10AI srcip=172.30.90.X flagged=… maxscore=…`, và trên Discover
`data.srcip:172.30.90.X and rule.level >= 10` chỉ có alert 100250. Không tăng nhịp lên 1,5 request mỗi giây, vì khi đó luật
110020 khớp trước tín hiệu AI.

**3d. Thời hạn chặn.** Ngay sau khi một nguồn bị chặn, gửi trang bình thường từ cùng IP mỗi 5 giây:

```bash
docker run --rm --network siem10_net --ip 172.30.90.X -v "$PWD/ar:/workspace/ar:ro" siem-ai-lab:local \
  python3 -I /workspace/ar/tools/demo_send.py --urls $(printf '/index.html %.0s' $(seq 50)) --rate 0.2 --stop-after 1000
```

Trang chủ không có phản hồi cho tới khi lệnh chặn hết hạn, khoảng 180 giây tính từ lệnh chặn cuối cùng cho IP đó. Khi một IP
nhận lệnh chặn từ hai nguồn, ví dụ luật 110020 rồi tín hiệu AI, thời gian bị chặn có thể dài hơn 180 giây tính từ lệnh đầu.

**Trên Dashboard,** nhật ký Active Response của agent được giải mã thành alert rule 651 (`rule.groups:active_response`); trường
`data.parameters.alert` chứa alert đã kích hoạt lệnh chặn.

## 4. Gỡ

```bash
bash ar/ar.sh down
python3 -B sig/tools/sig_rules.py status       # host và Manager cùng sha256
python3 scripts/apply_rule.py sync | tail -1   # ✓ trùng nhau
python3 scripts/apply_rule.py health           # ĐẠT
```

`down` xóa luật iptables, dừng `ar-watch`, tạo lại agent theo cấu hình ở mục 3.6 của README và gỡ phần AR trên Manager. Phải
chạy `down` trước khi sinh traffic, dựng dataset, chạy đánh giá hay chạy công cụ thật, vì phản ứng tự động chặn IP nguồn của các
phiên và làm phiên mất phần request còn lại.

## Lưu ý

- Khi phản ứng tự động đang bật, mọi lệnh tạo lại agent không kèm `ar/docker-compose.ar.yml` đều tắt phần AR phía agent, còn
  Manager vẫn giữ phần AR cho tới khi chạy `down`. Không tự gõ lệnh compose với tệp này, chỉ dùng `ar.sh`.
- Nếu `apache-target` khởi động lại, agent mất mạng theo. Chạy lại `bash ar/ar.sh up`; phần Manager đã cài nên công cụ bỏ qua
  bước đó.
- Phần AR trên Manager được ghi bên trong container (volume `wazuh_etc`). Tạo lại container Manager sẽ chép lại `ossec.conf`
  gốc và mất phần này; chạy lại `bash ar/ar.sh up`.
- Trong lúc Manager khởi động lại, agent mất kết nối vài giây và request gửi trong khoảng đó không thành alert. Vì vậy chỉ cài,
  gỡ phản ứng tự động (và áp, gỡ luật) khi không có traffic.
