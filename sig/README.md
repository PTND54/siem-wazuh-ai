# sig/ — luật chữ ký cho payload trong URL

Luồng chấm điểm (siem.log, luật SIEMLAB, ai-service) chỉ nhìn nhịp truy cập và mã trạng thái, nên một request SQL injection đơn
lẻ nhận mã 200 trông giống một lượt xem trang. Thư mục này bổ sung một bộ luật chữ ký cho bốn loại payload trong URL
(SQL injection, XSS, path traversal, command injection), chạy trên access_log song song với luồng chấm điểm:

- agent đọc thêm `access_log` (dạng combined), giải mã bằng decoder `web-accesslog` dựng sẵn của Wazuh;
- 20 luật chữ ký level 8 (id 100110–100142, nhóm `siem10_sig_*`), viết thủ công, không do mô hình AI của hệ thống sinh;
- 9 luật dựng sẵn chỉ xét mã trạng thái (31101, 31120–31123, 31151, 31161–31163) được hạ về level 0 bằng `overwrite`, và
  31151 bỏ nhóm `web_scan`, để chúng không sinh alert trùng với luồng SIEMLAB và không lọt vào bộ đếm của luật 110020
  (`ref/NOTES.md` mục 20–21).

Đầu vào của AI không đổi: ai-service chỉ đọc alert SIEMLAB. Mọi tệp của phần này nằm trong `sig/`; không tệp nào trong bản kê
khóa bị sửa (`python3 scripts/lockbox_manifest.py check` vẫn in TRÙNG).

## Cấu trúc

```
rules/zy_siem10_sig_rules.xml        bộ luật (cài lên Manager ở /var/ossec/etc/rules/, nạp sau local_rules.xml)
rules/probe_zy_siem10_sig_rules.xml  biến thể thăm dò: mỗi luật chỉ khớp IP 192.0.2.0/24, dùng cho sig_eval.py
agent/ossec.conf                     bản sao agent/ossec.conf có thêm khối đọc access_log
docker-compose.sig.yml               tệp compose phụ gắn agent/ossec.conf ở trên vào agent
ref/                                 luật và decoder web dựng sẵn chép từ Manager 4.14.7, NOTES.md (hành vi Wazuh đã đo)
payloads/                            tập ca (URL) đã dựng: dev, test, benign_dev, benign_test (phát triển); test2, benign2
                                     (giữ riêng); src/ là tệp nguồn đã tải, sha256 trong src/manifest*.txt
tools/                               sinh luật, cài/gỡ, gửi payload, đo bằng logtest và trên đường thật, khoảng tin cậy
runs/                                kết quả đo:
                                       p6*            tập giữ riêng (gửi một lần), CI ở ci_payload_v2.json
                                       p7*            phát lại hai nguồn xây dựng luật, phép thử tải, phiên gửi chậm
                                       p3b_v1/base_*  bộ luật web nguyên vẹn, trước khi ghi đè (RESULTS.md, mục cuối)
                                       p3a_*, p5_test, p3_regress   dòng access_log thật mà các lần phát lại dùng làm đầu vào
                                       p0, p1_nikto, p1c_*          phép đo hành vi của Wazuh ghi trong ref/NOTES.md
                                       rules_install_*              nhật ký cài bộ luật; tệp …195806 ghi phép đo luật tần suất N = 5 (khớp ở sự kiện 3 và 6)
PREREG.md                            kế hoạch đánh giá cuối, chốt trước khi tải tập giữ riêng
RESULTS.md                           kết quả đánh giá cuối
```

## Bật, tắt, kiểm (trong WSL, từ thư mục dự án)

```bash
# bật: cài tệp luật lên Manager rồi cho agent đọc thêm access_log
python3 -B sig/tools/sig_rules.py install --yes
docker compose -p siem10 -f docker-compose.yml -f sig/docker-compose.sig.yml up -d --no-deps --force-recreate wazuh-agent

# kiểm (không đổi gì)
python3 -B sig/tools/sig_rules.py status       # sha256 tệp luật trên host và trên Manager
python3 -B sig/tools/sig_rules.py check        # logtest: các dòng mẫu phải ra đúng luật
docker exec wazuh-agent grep "Analyzing file" /var/ossec/logs/ossec.log | tail -2   # phải có cả siem.log và access_log
python3 -B sig/tools/check_live.py --no-requests                                    # events/drops của từng tệp log

# tắt hẳn
docker compose -p siem10 up -d --no-deps --force-recreate wazuh-agent
python3 -B sig/tools/sig_rules.py remove --yes
```

`install` và `remove` đi theo đúng trình tự an toàn của `scripts/apply_rule.py`: kiểm sức khỏe trước, ghi tệp,
`wazuh-analysisd -t` (chặn mọi cảnh báo mới), khởi động lại tiến trình Wazuh bên trong container bằng `wazuh-control`, kiểm sức
khỏe bằng một request canary thật, kiểm chức năng bằng logtest, tự khôi phục tệp cũ nếu không đạt. Mỗi lần ghi nhật ký vào
`sig/runs/rules_<lệnh>_<giờ>.json`. Chạy khi không có traffic.

Lưu ý:
- Mọi lệnh `up` cho agent KHÔNG kèm `-f sig/docker-compose.sig.yml`, kể cả trong `setup/after_unzip.sh` và
  `setup/agent_tune.sh`, sẽ tạo lại agent với cấu hình gốc và lặng lẽ tắt access_log. Chạy lại dòng thứ hai của phần "bật".
- `docker compose down -v` xóa volume `wazuh_etc`, mất tệp luật trên Manager; cài lại bằng `install`.
- Khi agent đang gắn `sig/agent/ossec.conf`, không chép đè hay xóa tệp đó (Docker gắn theo inode); sửa xong thì tạo lại agent.

## Mã băm của tệp luật

`PREREG.md` chốt tệp luật sha256 c5a016d3d8b0ef5823ca0e24c96ed169bc4937050c4daf21a104aa3e415ba3c1, là tệp đã cài lên Manager khi
đánh giá. Tệp trong bản nộp (sha256 92fbe38d70006a43d46b1bffe8358071d24b4f9f849792cc2597a8c1052939f3) chỉ khác tệp đó ở 4 dòng
chú thích đầu tệp; từ dòng 5 trở đi hai tệp trùng từng byte:

```bash
tail -n +5 sig/rules/zy_siem10_sig_rules.xml | sha256sum
# fd709efdf3d25383c50692e6bae3bd053cb68c1ceaaf7ba623fa7905a52bc371 (giống phần tương ứng của tệp c5a016d3…)
```

Tương tự, `tools/sig_rules_gen.py` chỉ khác bản đã chốt (67de2498…) ở chú thích, docstring và chữ in ra màn hình; danh sách
luật và mẫu không đổi, và tệp luật nó sinh ra trùng từng byte với tệp trong `rules/`.

## Sửa luật

Luật chỉ sửa trong `tools/sig_rules_gen.py`, rồi sinh lại cả hai tệp:

```bash
python3 -B sig/tools/sig_rules_gen.py --xml sig/rules/zy_siem10_sig_rules.xml
python3 -B sig/tools/sig_rules_gen.py --probe --xml sig/rules/probe_zy_siem10_sig_rules.xml
```

Mọi thay đổi sau ngày chốt làm số liệu trong `RESULTS.md` không còn áp dụng; muốn có số mới phải viết kế hoạch mới và chạy lại
trên một tập giữ riêng mới. Các lệnh mô phỏng (`sig_rules_gen.py --sim`, `sig_sim_all.py`) đọc dòng log thô có sẵn trong `runs/p3a_*` (tập phát
triển), `runs/p5_test/` (SecLists) và `runs/p3_regress/` (traffic generator); dòng log của tập giữ riêng nằm ở
`runs/p6_test2/`. Các lần gửi khác không kèm theo; sinh lại bằng `tools/send_payloads.py` rồi đo bằng `measure_logtest.py`
hoặc `measure_real.py`.

## Quy trình đánh giá đã dùng

1. Dựng tập ca phát triển từ PayloadsAllTheThings và SecLists (`tools/build_payloads.py`), soạn và chỉnh luật trên chúng.
2. Chốt bộ luật bằng mã băm (`PREREG.md`), rồi mới tải FuzzDB và dựng tập giữ riêng cùng tập giá trị bình thường mới
   (`tools/build_payloads_v2.py`, không in nội dung payload).
3. Gửi tập giữ riêng một lần qua Apache và Wazuh thật (`tools/send_payloads.py`, mỗi loại một IP), nối với alert thật và cờ AI
   (`tools/measure_real.py`), đo bộ luật web mặc định bằng phát lại chính các dòng access_log qua logtest với tệp tạm vô hiệu
   hóa luật chữ ký (`tools/sig_eval.py --configs builtin`).
4. Tính khoảng tin cậy (`tools/ci_payload.py`). Kết quả: `RESULTS.md`.
