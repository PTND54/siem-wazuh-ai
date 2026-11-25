# siem-wazuh-ai — giám sát web bằng Wazuh SIEM kết hợp học máy

Môi trường lab chạy bằng Docker Compose trên WSL2. Apache ghi log, agent Wazuh gửi về Manager, luật SIEMLAB sinh một alert cho
mỗi request. Phía sau Wazuh có hai luồng:

- **Chấm điểm:** `ai-service` đọc alert SIEMLAB, tính đặc trưng theo cửa sổ của từng IP nguồn, chấm điểm bằng Random Forest
  (`models/full1/model.joblib`) và ghi alert đã làm giàu vào index `ai-enriched-alerts-*`. Alert gốc không bị sửa.
- **Đề xuất luật:** `scripts/rule_proposer.py` dùng kết luận của mô hình để chọn tham số cho luật tương quan theo mẫu
  (tần suất, cửa sổ thời gian, cùng IP). Đề xuất chỉ lên Manager khi người duyệt áp bằng `scripts/apply_rule.py`. Ba luật đang
  áp: 110011 (401), 110020 (403/404), 110030 (mọi mã).

Thêm vào đó, thư mục `sig/` có bộ luật chữ ký cho payload trong URL (SQL injection, XSS, path traversal, command injection), chạy
trên access_log song song với luồng trên (xem `sig/README.md`). Thư mục `ar/` nối các luật đã duyệt và tín hiệu của AI với
Active Response của Wazuh để chặn tạm thời IP nguồn; phần này mặc định tắt và chỉ chạy khi bật bằng `bash ar/ar.sh up`
(mục 3.9). Hệ thống không học trực tuyến và không tự áp luật.

Dữ liệu lớn (9 tập `dataset_*.csv`, nhật ký từng request, alert thô và log Apache) nằm trong gói dataset trên
[Google Drive](https://drive.google.com/drive/folders/1Nn4eMfEv4XTgbARFiTwsBgAC2JMp4-Tv), xem mục 3.8.

## 1. Thành phần

| Container | Image | Vai trò | Cổng trên máy |
|---|---|---|---|
| `siem10-wazuh.manager-1` | wazuh/wazuh-manager:4.14.7 | phân tích log, luật, alerts.json | 127.0.0.1:45000 (API) |
| `siem10-wazuh.indexer-1` | wazuh/wazuh-indexer:4.14.7 | lưu alert và index ai-enriched-alerts-* | 127.0.0.1:9200 |
| `siem10-wazuh.dashboard-1` | wazuh/wazuh-dashboard:4.14.7 | giao diện | https://localhost:8443 |
| `apache-target` | siem-ai-apache:local (build `apache/`) | web mục tiêu, ghi `siem.log` và `access_log` | http://localhost:8080 |
| `wazuh-agent` | wazuh/wazuh-agent:4.14.7 | đọc log của Apache, tên `apache-lab-agent` | — |
| `redis` | redis:7-alpine | trạng thái, checkpoint của ai-service | — |
| `ai-service` (profile `ai`) | siem-ai-lab:local (build `Dockerfile`) | chấm điểm alert trực tuyến | — |
| `lab` (profile `lab`, chạy theo lệnh) | siem-ai-lab:local | sinh traffic, dựng dataset, huấn luyện, kiểm thử | — |
| `ar-watch` (khi bật `ar/`) | siem-ai-lab:local | ghi tín hiệu chặn khi một IP có nhiều alert bị AI gắn cờ | — |

Khi bật `ar/`, `wazuh-agent` chạy image `siem-ai-agent-ar:local` (có iptables) và dùng chung mạng với `apache-target`.

Mạng `siem10_net` 172.30.90.0/24; dịch vụ lấy địa chỉ .2–.14, phần còn lại dành cho IP nguồn của các phiên traffic. Mọi cổng
chỉ mở trên 127.0.0.1. Mật khẩu trong `docker-compose.yml` (Dashboard: `admin` / `SecretPassword`) là mật khẩu mặc định của
wazuh-docker, chỉ dùng trong lab.

## 2. Cấu trúc thư mục

```
docker-compose.yml   Dockerfile (image lab)   requirements.txt
setup/      dựng stack (00–03), nâng hàng đợi agent, chạy công cụ thật, theo dõi tài nguyên
apache/     Dockerfile, cấu hình httpd (format siem.log), site tĩnh htdocs/ sinh từ scripts/site_model.py, .htpasswd
agent/      ossec.conf của agent (đọc siem.log)
wazuh/      local_decoder.xml (decoder siemlab), local_rules.xml (luật SIEMLAB 100010–100019),
            ai_rules/zz_siem10_ai_rules.xml (bản sao trên host của ba luật tương quan đang áp)
scripts/    sinh traffic, dựng dataset, đặc trưng, huấn luyện, ai-service, đề xuất và áp luật, đánh giá cuối
tests/      kiểm thử cho từng script (mỗi tệp chạy riêng)
models/full1/   mô hình dùng cho ai-service: model.joblib, metrics.json, report.md, test_predictions.csv
proposals/  hồ sơ đề xuất luật (.json) và luật (.xml); ba hồ sơ AI-R110xxx ở trạng thái applied
docs/       LOCKBOX_PREREG.md (kế hoạch đánh giá cuối), lockbox_manifest.json (bản kê khóa)
sig/        luật chữ ký cho payload trong URL
ar/         phản ứng tự động: Active Response (firewall-drop) theo luật đã duyệt và tín hiệu AI, mặc định tắt (mục 3.9)
pinned/     Dockerfile ghim scikit-learn, numpy, pandas đúng phiên bản của máy gốc
vendor/wazuh-docker/   cấu hình single-node của wazuh-docker v4.14.7 (wazuh_manager.conf đã chỉnh), chưa có chứng chỉ
data/       nhật ký phiên (runs/*/sessions.jsonl) và kết quả đối chiếu độ phủ (dataset_*.audit.json) của 9 tập dữ liệu;
            dataset_*.csv, nhật ký từng request và alert thô nằm trong gói dataset tải riêng (mục 3.8)
output/     kết quả đánh giá: lockbox1/ (đánh giá cuối), rules_full1_ai/ và rules_full1/ (chọn luật), compare_*/ (luật thật so với mô phỏng), monitor_*.csv
```

## 3. Dựng trên máy mới

Mọi lệnh bên dưới chạy trong terminal Ubuntu của WSL, từ thư mục dự án `~/siem-wazuh-ai`, trừ bước 3.3 chạy trong PowerShell.

### 3.1 Yêu cầu

- Windows 10/11, WSL2 với một bản Ubuntu, Docker Desktop đã bật WSL integration cho bản Ubuntu đó (Settings → Resources →
  WSL integration). Trong Ubuntu, `docker version` và `docker compose version` (v2) phải chạy được.
- WSL nhận ít nhất 7 GB RAM và còn ít nhất 15 GB đĩa trống (`setup/01_preflight.sh` kiểm cả hai). Thiếu RAM thì tăng `memory`
  trong `%UserProfile%\.wslconfig` rồi `wsl --shutdown`.
- `python3` trong Ubuntu (có sẵn). Các script chạy trên host chỉ dùng thư viện chuẩn; pandas và scikit-learn nằm trong image lab.
- Internet ở lần dựng đầu: kéo image Wazuh, redis, httpd, python, image sinh chứng chỉ, và cài gói trong image lab.
- Cổng 8080, 8443, 9200, 45000 đang rảnh; không có container khác tên `apache-target`, `wazuh-agent`, `redis`, `ai-service`.

### 3.2 Lấy mã nguồn vào WSL

Clone vào hệ tệp Linux của WSL, không đặt dưới ổ Windows (`/mnt/c`, `/mnt/d`), vì ở đó Docker gắn tệp chậm và dễ lỗi quyền:

```bash
git clone https://github.com/PTND54/siem-wazuh-ai.git ~/siem-wazuh-ai
cd ~/siem-wazuh-ai
grep -rlI $'\r' setup scripts sig/tools sig/rules sig/agent apache agent wazuh docker-compose.yml Dockerfile || echo "không có CRLF"
```

Dòng cuối phải in "không có CRLF". `.gitattributes` giữ xuống dòng LF cho mọi tệp văn bản. Nếu vẫn có tệp bị đổi sang CRLF
(chẳng hạn clone trên Windows rồi chép vào WSL bằng công cụ đổi kiểu xuống dòng), sửa bằng `sed -i 's/\r$//' <tệp>`.

### 3.3 vm.max_map_count (PowerShell)

```powershell
wsl -d docker-desktop -u root -- sysctl -w vm.max_map_count=262144
```

Indexer cần giá trị này. Nó mất sau mỗi lần khởi động lại WSL hoặc Docker Desktop, nên chạy lại trước khi bật stack.

### 3.4 Dựng stack

```bash
bash setup/00_clone_wazuh.sh   # vendor/wazuh-docker đã có nên bỏ qua clone; sinh chứng chỉ TLS (thư mục chứng chỉ thuộc root)
bash setup/01_preflight.sh     # kiểm docker, compose, RAM, đĩa, vm.max_map_count, cổng, chứng chỉ, site, container trùng tên
bash setup/02_up.sh            # build apache + lab, bật 6 dịch vụ, nâng hàng đợi logcollector của agent (lần đầu 10–15 phút)
docker build -t siem-ai-lab:local -f pinned/Dockerfile pinned   # ghim scikit-learn 1.9.1, numpy 1.26.4, pandas 2.3.3
bash setup/03_verify.sh        # 9 phép kiểm; mọi dòng phải [ok]
docker compose -p siem10 --profile ai up -d ai-service
```

- `vendor/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf` trong bản này đã được chỉnh sẵn
  (`setup/manager_tune.sh`), không cần chạy lại.
- `03_verify.sh` kiểm site trả đúng mã, công cụ trong image lab, log của Apache, IP alias, agent kết nối, hàng đợi agent, mỗi mã
  trạng thái vào đúng luật SIEMLAB (wazuh-logtest), hai phiên traffic đi trọn từ Apache tới alert, và một lượt 5.000 request bắn
  nhanh không mất sự kiện nào. Nếu có `[LỖI]`, sửa trước khi đi tiếp.
- `ai-service` bắt đầu ở cuối alerts.json (`--from-end`), không chấm lại lịch sử. Xem log: `docker logs -f ai-service`
  (dòng "thống kê" mỗi 30 giây).

### 3.5 Nạp ba luật tương quan đã duyệt

Manager mới chưa có tệp luật AI. Bản trên host `wazuh/ai_rules/zz_siem10_ai_rules.xml` là đúng tệp đang chạy trên máy gốc.

```bash
python3 scripts/apply_rule.py sync                    # báo KHÁC NHAU: Manager chưa có luật
python3 scripts/apply_rule.py sync --restore --yes    # nạp lên Manager
python3 scripts/apply_rule.py sync                    # ✓ trùng nhau
```

`--restore` kiểm cú pháp bằng `wazuh-analysisd -t`, khởi động lại tiến trình Wazuh bên trong container bằng `wazuh-control`,
gửi một request canary thật qua Apache và chờ nó thành alert (và thành tài liệu ai-enriched khi ai-service đang chạy), rồi tự
khôi phục nếu bước nào không đạt.

### 3.6 Bật luật chữ ký

```bash
python3 -B sig/tools/sig_rules.py install --yes
docker compose -p siem10 -f docker-compose.yml -f sig/docker-compose.sig.yml up -d --no-deps --force-recreate wazuh-agent
```

Dòng đầu cài `sig/rules/zy_siem10_sig_rules.xml` lên Manager theo cùng trình tự an toàn như 3.5. Dòng thứ hai tạo lại agent với
cấu hình đọc thêm access_log.

### 3.7 Kiểm trạng thái cuối

```bash
docker compose -p siem10 --profile ai ps              # 7 container Up
python3 scripts/apply_rule.py health                  # ĐẠT: đủ tiến trình, agent Active, canary thành alert
python3 scripts/apply_rule.py sync                    # ✓ trùng nhau
python3 -B sig/tools/sig_rules.py status              # sha256 tệp luật chữ ký trên host = trên Manager
python3 -B sig/tools/sig_rules.py check               # CHỨC NĂNG ĐẠT
docker exec wazuh-agent grep "Analyzing file" /var/ossec/logs/ossec.log | tail -2   # siem.log và access_log
docker run --rm siem-ai-lab:local python3 -c "import sklearn; print(sklearn.__version__)"   # 1.9.1
python3 scripts/lockbox_manifest.py check             # TRÙNG bản kê đã chốt (394 tệp, digest 5e55b467…)
```

Thử một request SQL injection:

```bash
curl -s -o /dev/null "http://127.0.0.1:8080/products/p-0217.html?item=%27%20or%20%27a%27=%27a"
sleep 10
docker compose -p siem10 exec -T wazuh.manager tail -n 20 /var/ossec/logs/alerts/alerts.json | grep -o '"id":"1001[0-9][0-9]"'
# "id":"100111" — luật chữ ký SQL injection
```

Trên Dashboard (https://localhost:8443, `admin` / `SecretPassword`): alert gốc nằm trong `wazuh-alerts-*` (luật chữ ký lọc theo
`rule.groups: siem10_sig`). Để xem kết quả chấm điểm, tạo index pattern `ai-enriched-alerts-*` với trường thời gian `timestamp`
(Dashboards Management → Index patterns); trường `ai.score`, `ai.flag` là điểm và cờ của mô hình.

### 3.8 Những gì không chuyển sang máy mới

- Lịch sử alert, index, trạng thái Redis và bản đăng ký agent nằm trong volume Docker của máy gốc. Máy mới bắt đầu với các
  volume trống; cấu hình, mô hình và luật thì giống máy gốc sau các bước trên.
- Dữ liệu lớn nằm trong gói dataset tải riêng ([Google Drive](https://drive.google.com/drive/folders/1Nn4eMfEv4XTgbARFiTwsBgAC2JMp4-Tv)): 9 tệp `dataset_*.csv`, nhật ký từng request
  (`data/runs/*/requests/`), `data/.lockbox_seed`, alert thô và log Apache xuất từ volume của máy gốc, nhật ký ai-service.
  Repo chỉ chứa nhật ký phiên, kết quả đối chiếu và kết quả đánh giá. Các bước 3.4–3.7 không cần gói dataset; cách đặt
  các tệp của gói vào repo ghi trong README của gói, và mục 5 có ví dụ chạy lại một phép kiểm trên dữ liệu đó.

### 3.9 Phản ứng tự động (tùy chọn)

```bash
bash ar/ar.sh up         # cài phần AR trên Manager, tạo lại agent có iptables dùng chung mạng với apache-target, chạy ar-watch
bash ar/ar.sh selftest   # thử trọn đường đi với IP TEST-NET 192.0.2.99, không đụng IP của lab
bash ar/ar.sh flush      # gỡ mọi lệnh chặn đang có
bash ar/ar.sh status     # IP đang bị chặn, nhật ký ar-watch, phần AR trên Manager
bash ar/ar.sh down       # gỡ hẳn: agent về cấu hình ở mục 3.6, Manager về cấu hình trước khi cài
```

Lệnh chặn là `firewall-drop` có sẵn của Wazuh, thời hạn 180 giây, kích hoạt bởi luật 110011, 110020, nhóm luật chữ ký
`siem10_sig` và luật 100250. Luật 100250 khớp trên dòng do `ar-watch` ghi khi một IP có từ 10 alert `ai.flag=true` trong 60
giây, nên ai-service không có quyền chặn và mọi lệnh chặn đều bắt đầu từ một alert. Luật 110030 không kích hoạt chặn. Danh sách
loại trừ gồm 172.30.90.1–.8. Cài và gỡ đi theo trình tự an toàn của mục 3.5, thêm bước `wazuh-execd -t` và bước chờ agent kết nối
lại sau khi Manager khởi động lại. Các kịch bản thử (dò thư mục nhanh, payload SQL injection, dò thư mục chậm, thời hạn chặn) và
các lưu ý vận hành nằm trong `ar/HUONG_DAN.md`.

## 4. Vận hành

- Khởi động lại tiến trình Wazuh trên Manager:
  `docker compose -p siem10 exec wazuh.manager /var/ossec/bin/wazuh-control restart`.
  Không dùng `docker restart` hay `docker compose restart` cho Manager và agent: hai container này gắn từng tệp từ host, và sau
  khi tệp bị thay thế, khởi động lại sẽ lỗi "error mounting".
- Sau khi sửa một tệp gắn từ host (`agent/ossec.conf`, `wazuh/local_*.xml`, `wazuh_manager.conf`, `sig/agent/ossec.conf`), tạo
  lại container, Manager trước rồi agent:
  `docker compose -p siem10 up -d --force-recreate wazuh.manager`, chờ khoảng một phút, rồi lệnh tạo lại agent ở mục 3.6.
- Lệnh tạo lại agent phải luôn kèm `-f sig/docker-compose.sig.yml`, nếu không access_log bị tắt. `setup/after_unzip.sh` và
  `setup/agent_tune.sh` tạo lại agent không kèm tệp này, nên sau khi chạy chúng phải chạy lại dòng thứ hai của mục 3.6.
- `docker compose -p siem10 --profile ai down` giữ volume. `down -v` xóa volume, mất cả alert lẫn hai tệp luật trên Manager;
  dựng lại theo 3.4–3.6.
- Sau khi khởi động lại máy: chạy lại 3.3; Docker Desktop tự bật lại các container (restart policy).
- Build lại image lab (ví dụ chạy lại `02_up.sh`) thì chạy lại lệnh `docker build … pinned/Dockerfile`, rồi tạo lại ai-service:
  `docker compose -p siem10 --profile ai up -d --force-recreate ai-service`.
- Khi phản ứng tự động đang bật (mục 3.9), lệnh tạo lại agent ở mục 3.6 sẽ tắt phần AR phía agent; nếu `apache-target` hay
  container Manager được tạo lại, chạy lại `bash ar/ar.sh up`.
- Nếu log agent báo `Duplicate agent name`: xem ID cũ bằng
  `docker compose -p siem10 exec -T wazuh.manager /var/ossec/bin/agent_control -l`, xóa bằng `manage_agents -r <ID>` trong cùng
  container, rồi tạo lại agent.

## 5. Chạy lại thí nghiệm

Trước khi sinh traffic, dựng dataset hay chạy công cụ thật, tắt phản ứng tự động bằng `bash ar/ar.sh down` nếu đang bật, vì nó
chặn IP nguồn của các phiên và làm phiên mất phần request còn lại.

**Trên dữ liệu có sẵn.** Chép nội dung thư mục `data/` của gói dataset vào `data/` của repo, rồi giải nén alert thô và log
Apache vào `data/export/` (thư mục này nằm trong `.gitignore`). Trong các lệnh dưới, `<gói dataset>` là thư mục giải nén từ tệp
tải về:

```bash
cp -r "<gói dataset>/data/." data/
mkdir -p data/export
tar -xzf "<gói dataset>/siem10_export_20261118/apache_logs.tgz" -C data/export
tar -xzf "<gói dataset>/siem10_export_20261118/wazuh_alerts.tgz" -C data/export
python3 scripts/audit_coverage.py --batch data/runs/lockbox1 --siem-log data/export/siem.log \
    --alerts data/export/alerts/2026/Oct/ossec-alerts-28.json
# kết quả mong đợi: TỔNG 154025/154025 = 1.0000 ở cả hai tầng
```

`audit_coverage.py` chỉ cần Python 3 nên chạy được ngay trên host, còn các script dùng mô hình (`trainer.py`, `lockbox_eval.py`,
`rule_proposer.py`, `check_pipeline.py`) chạy trong container lab.

Các lệnh Python chạy trong container lab:

```bash
L="docker compose -p siem10 run --rm lab"
for t in features build_dataset pipeline generator trainer ai_service; do $L python3 tests/test_$t.py 2>&1 | tail -1; done
python3 tests/test_apply_rule.py                  # Manager giả lập, chạy trên host
```

Mỗi tệp test là một script, chạy riêng; không dùng `unittest discover`. Các tệp còn lại trong `tests/` chạy cùng cách.
Nếu `test_ai_service.py` báo thiếu redis-server, chạy nó với Redis của stack (DB 15, tách khỏi dữ liệu của ai-service):
`docker compose -p siem10 run --rm -e REDIS_URL=redis://redis:6379/15 lab python3 tests/test_ai_service.py`.

**Sinh traffic.** Mỗi phiên là một kịch bản (benign, tấn công hoặc stress) từ một IP nguồn riêng.

```bash
$L python3 scripts/run_batch.py --preset smoke --dry-run       # in kế hoạch và ước lượng thời gian, không gửi gì
$L python3 scripts/run_batch.py --preset smoke --batch-id smoke1
$L python3 scripts/audit_coverage.py --batch data/runs/smoke1 --siem-log /apache-logs/siem.log --alerts /wazuh-logs/alerts/alerts.json
```

| preset | phiên | thời gian ước lượng | dùng để |
|---|---|---|---|
| `smoke` | 17 | ~6 phút | kiểm đường ống |
| `dev` | 154 | ~20 phút | phát triển |
| `full` | 522 | ~57 phút | tập chính, chia train/val/test theo thời gian |
| `shift` | 126 | ~22 phút | tập lệch phân phối |
| `lockbox` | 468 | ~55 phút | đánh giá cuối; cần `--confirm-lockbox`, theo `docs/LOCKBOX_PREREG.md`, đã chạy một lần |

`--resume` chạy tiếp batch bị ngắt. Công cụ thật (nmap, hydra, dirb, nikto, gobuster, ffuf, ab): `bash setup/run_tools.sh 2`.

**Dựng dataset và huấn luyện.**

```bash
$L python3 scripts/build_dataset.py --batches data/runs/dev1 \
    --alerts /wazuh-logs/alerts/alerts.json "/wazuh-logs/alerts/*/*/ossec-alerts-*.json*" --out data/dataset_dev1.csv
$L python3 scripts/trainer.py --data data/dataset_dev1.csv --out models/dev1
$L python3 scripts/check_pipeline.py              # kiểm từng chặng trên dữ liệu đã có
```

`trainer.py` không có `--out` sẽ ghi vào `models/<tên dataset>`; huấn luyện lại trên `dataset_full1.csv` sẽ ghi đè
`models/full1` và bản kê khóa không còn TRÙNG.

**Đề xuất và áp luật.**

```bash
$L python3 scripts/rule_proposer.py --data data/dataset_full1.csv --select-extra data/dataset_dev1.csv --label-source ai \
   --eval data/dataset_shift1.csv data/dataset_tools2.csv --metrics models/full1/metrics.json
python3 scripts/apply_rule.py list                # hồ sơ đề xuất và trạng thái
python3 scripts/apply_rule.py show <pid>
python3 scripts/apply_rule.py apply <pid> --by <tên>          # remove / reject / verify tương tự
python3 scripts/apply_rule.py make-canary && python3 scripts/apply_rule.py apply <CANARY-…> --yes   # thử trọn vòng an toàn
```

Luật canary chỉ khớp IP 192.0.2.0/24 nên không ảnh hưởng traffic thật; gỡ bằng `remove <CANARY-…> --yes`.

**Đánh giá cuối.** Trình tự cố định trong `docs/LOCKBOX_PREREG.md`: `lockbox_manifest.py check` → `lockbox_preflight.py` →
`run_batch.py --preset lockbox --confirm-lockbox` → `audit_coverage.py` + `build_dataset.py` → `lockbox_eval.py validate` →
`lockbox_eval.py metrics`.

**Luật chữ ký.** Xem `sig/README.md`.

## 6. Hạn chế đã biết

- Site tĩnh nhỏ, chỉ GET/HEAD; một nguồn log (Apache) và một agent.
- Nhãn gán theo phiên cho mọi sự kiện, kể cả vài sự kiện đầu của phiên tấn công khi cửa sổ còn quá ít sự kiện để phân biệt với
  benign, nên đánh giá chính tính theo phiên.
- Decoder SIEMLAB cần dòng yêu cầu đủ ba phần `METHOD URL PROTO`; request dị dạng không được giải mã.
- Dưới tải rất nhanh, logcollector của agent bỏ dòng âm thầm khi hàng đợi đầy; `setup/agent_tune.sh` nâng hàng đợi lên 220000
  (giá trị tối đa) và `03_verify.sh` kiểm 5.000 request không mất dòng nào.
- ai-service khởi động lại đúng lúc alerts.json vừa xoay vòng thì phần cuối tệp cũ chưa đọc bị bỏ qua (có cảnh báo trong log).
- Luật chữ ký so mẫu trên URL nên không nhận ra payload mã hóa base64 hay lệnh ngoài danh sách (`sig/RESULTS.md`).
- Phản ứng tự động chỉ chặn sau khi có alert, nên các request gửi trước đó vẫn tới máy chủ, và nó kế thừa báo nhầm của các luật
  và tín hiệu AI mà nó dựa vào. Danh sách loại trừ chỉ gồm .1–.8 trong khi dịch vụ có thể nhận địa chỉ tới .14.
