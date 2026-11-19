# Kết quả đánh giá cuối của bộ luật chữ ký

Kế hoạch đã chốt trước khi chạy: `PREREG.md` (bộ luật sha256 c5a016d3…, chốt 15/11/2026 10:08 UTC).
Tập giữ riêng gửi MỘT lần 15/11/2026 10:12:10–10:19:28 UTC, IP 172.30.90.244–.248 (`runs/p6.txt`, `runs/p6_test2_measure.json`).
Cả 5 phiên đối chiếu đạt (số phản hồi = số dòng access_log = số dòng siem.log = số alert SIEMLAB), drops = 0, tệp tạm dùng để đo
bộ luật web mặc định đã được xóa sau khi đo.

Đơn vị chính là payload (120 mỗi loại; 60 giá trị bình thường). Khoảng tin cậy 95%: bootstrap 1.000 lần theo payload, seed 12345,
phân vị 2,5–97,5; hiệu giữa hai bộ luật tính bằng bootstrap ghép cặp trên cùng danh sách payload
(`tools/ci_payload.py` -> `runs/ci_payload_v2.json`).

## Bảng chính (mã hóa như trình duyệt, E1)

| Loại | Luật chữ ký | Bộ luật web mặc định | Hợp hai bộ | Hiệu ghép cặp (điểm %) |
|---|---|---|---|---|
| SQL injection | 112/120 (93,3%) [88,3; 97,5] | 105/120 (87,5%) [81,7; 93,3] | 115/120 (95,8%) [91,7; 99,2] | +5,8 [0,0; 11,7] |
| XSS | 111/120 (92,5%) [87,5; 96,7] | 86/120 (71,7%) [64,2; 79,2] | 112/120 (93,3%) [88,3; 97,5] | +20,8 [13,3; 28,3] |
| Path traversal | 81/120 (67,5%) [59,2; 75,8] | 25/120 (20,8%) [14,2; 28,3] | 81/120 (67,5%) [59,2; 75,8] | +46,7 [38,3; 55,0] |
| Command injection | 63/120 (52,5%) [43,3; 62,5] | 25/120 (20,8%) [13,3; 27,5] | 75/120 (62,5%) [54,1; 70,9] | +31,7 [20,8; 44,2] |
| Báo nhầm (giá trị bình thường) | 3/60 (5,0%) [0,0; 11,7] | 1/60 (1,7%) [0,0; 5,0] | 3/60 (5,0%) | +3,3 [0,0; 10,0] |

Cận dưới 0,0 ở dòng báo nhầm suy biến vì số giá trị bị báo rất nhỏ.

## Theo kiểu mã hóa (% payload, mỗi ô n = 120)

| Loại | Luật chữ ký E1 / E2 / E3 | Bộ mặc định E1 / E2 / E3 |
|---|---|---|
| SQL injection | 93,3 / 93,3 / 93,3 | 87,5 / 86,7 / 0,8 |
| XSS | 92,5 / 90,0 / 90,0 | 71,7 / 63,3 / 0 |
| Path traversal | 67,5 / 67,5 / 67,5 | 20,8 / 0 / 0 |
| Command injection | 52,5 / 39,2 / 38,3 | 20,8 / 5,0 / 0 |

E1 = như trình duyệt, E2 = mã hóa mọi ký tự đặc biệt, E3 = mã hóa hai lần. Bộ mặc định so chuỗi cố định nên gần như không nhận
ra E3 (1 trên 480 payload). Luật chữ ký chấp nhận ký tự thô, %XX và %25XX nên ổn định qua các kiểu, trừ command injection: nhiều
payload FuzzDB có sẵn `+` hoặc `%0a` dạng chữ, khi mã hóa toàn bộ thì chúng không còn là dấu cách hay ký tự xuống dòng.

## Payload bị bỏ sót (E1; phân loại sau khi chạy, không sửa luật — `runs/p6_test2_miss_causes_E1.json`)

- Path traversal (39): 13 mã hóa base64, 13 viết `..2f` thiếu dấu `%`, 5 đường dẫn tuyệt đối tới tệp ngoài danh sách của luật,
  4 dùng `../` một lần với tên tệp ngoài danh sách, 4 dạng khác.
- Command injection (57): 55 dùng lệnh không có trong danh sách lệnh của luật (53 trong số đó thuộc phần payload dựng bằng cách
  điền lệnh của FuzzDB vào mẫu, xem `PREREG.md` mục 4), 2 có lệnh trong danh sách nhưng sai cú pháp hoặc vị trí.
- XSS (9) và SQL injection (8): không phân loại thêm.

## Báo nhầm

Luật chữ ký báo 3 trên 60 giá trị: câu SQL `SELECT * FROM users WHERE name = 'O''Brien';` (100112), câu hỏi về thẻ `<div>` và
`<span>` (100120), công thức `=SUM(A1:A10)/COUNT(A1:A10)` (100114). Cả ba chứa đúng cú pháp mà luật tìm. Bộ mặc định báo 1
giá trị (cùng câu SQL).

## Cờ AI theo phiên

AI gắn cờ 302 trên 360 alert của phiên path traversal, phiên duy nhất có phản hồi lỗi (180/360 request nhận 404, 400 hoặc 403),
và không gắn cờ alert nào của ba phiên tấn công còn lại hay của phiên bình thường. Luật chữ ký phát alert ở request thứ 1, 4, 1
và 4 của bốn phiên tấn công.

Phiên gửi chậm 16/11/2026 07:54–07:57 UTC (IP 172.30.90.249): 40 payload SQL injection đầu tiên của tập giữ riêng, E1, mỗi
request cách 3 giây, bộ luật không đổi. Luật chữ ký 37/40, hợp hai bộ 38/40, AI gắn cờ 0/40, alert SIEMLAB 40/40
(`runs/p7.txt`, `runs/p7_slow_measure.json`).

## So với hai nguồn xây dựng luật (% payload, E1)

| Nguồn, bộ luật | SQL injection | XSS | Path traversal | Command injection |
|---|---|---|---|---|
| PayloadsAllTheThings, luật chữ ký | 98,3 | 100 | 99,2 | 82,5 |
| PayloadsAllTheThings, bộ mặc định | 55,0 | 44,2 | 24,2 | 9,2 |
| SecLists, luật chữ ký | 73,3 | 100 | 100 | 100 |
| SecLists, bộ mặc định | 34,2 | 19,2 | 39,2 | 28,3 |
| Tập giữ riêng, luật chữ ký | 93,3 | 92,5 | 67,5 | 52,5 |
| Tập giữ riêng, bộ mặc định | 87,5 | 71,7 | 20,8 | 20,8 |

Hai nguồn xây dựng luật đo bằng phát lại các dòng access_log thật qua wazuh-logtest với bộ luật đã chốt (16/11/2026, `runs/p7.txt`; kết quả từng dòng ở `runs/p7_final/` và `runs/p7_builtin/`).
Chúng đã được xem khi soạn mẫu nên kết quả thiên cao và không tính khoảng tin cậy. Trên hai tập giá trị bình thường dùng khi soạn
luật (106 và 96 request), luật chữ ký báo nhầm 2 và 6 request, bộ mặc định 8 và 10 request.

## Tác động lên hệ thống khi bật luật chữ ký

- Phép thử tải 5.000 request: 5.000 dòng siem.log, 5.000 dòng access_log, 5.000 alert SIEMLAB, drops = 0 ở cả hai tệp (`runs/p7.txt`).
- Ba luật tương quan khớp đúng vị trí khi sự kiện SIEMLAB xen với sự kiện access_log của cùng request (`tools/g1c_probe.py`):
  110020 ở SIEMLAB #15 và #30, 110011 ở #12 và #24, 110030 ở #500 và #1000 (`runs/p7.txt`).

## Ghi đè 9 rule chỉ xét mã trạng thái

Đo bằng cách phát lại từng dòng access_log qua wazuh-logtest. Có ba cấu hình:

- bộ luật web nguyên vẹn, chưa ghi đè và chưa có luật chữ ký: `runs/p3b_v1/`;
- sau khi ghi đè, chưa có luật chữ ký: `runs/p7_builtin/`;
- cấu hình cuối: `runs/p7_final/`.

**Traffic của generator.** Dùng 9.356 dòng access_log khác nhau của ngày 20–21/10/2026, nằm trong
`runs/p3_regress/gen_distinct_access_2021.log`. Mỗi dòng được phát lại riêng với một IP trong dải 192.0.2.0/24.

| Cấu hình | Dòng sinh alert | Theo rule |
|---|---|---|
| Bộ luật web nguyên vẹn | 8.910 | 31101: 8.859, 31516: 48, 31122: 3 |
| Sau khi ghi đè, chưa có luật chữ ký | 48 | 31516: 48 |
| Cấu hình cuối | 177 | 100131: 131, 31516: 46 |

Cả ba tệp `base_regress.jsonl` phát lại tệp `runs/p3_regress/gen_distinct_access.log`. Tệp này có 9.482 dòng: 9.356 dòng nói trên
và 126 dòng của ngày 28/10/2026, lấy từ tập đánh giá cuối. Các số trong bảng chỉ tính 9.356 dòng có trong
`gen_distinct_access_2021.log`. Nếu tính cả 9.482 dòng thì ba số lần lượt là 8.990, 48 và 177, vì 126 dòng thêm vào sinh 80
alert 31101 khi bộ luật còn nguyên vẹn và không sinh alert nào sau khi ghi đè. Tính lại bằng lệnh sau, chạy từ gốc dự án:

```bash
python3 - <<'PY'
import json
keep = set(open("sig/runs/p3_regress/gen_distinct_access_2021.log", encoding="latin-1").read().splitlines())
for run in ("p3b_v1", "p7_builtin", "p7_final"):
    rows = [json.loads(l) for l in open(f"sig/runs/{run}/base_regress.jsonl")]
    print(run, sum(r["alert"] for r in rows if r["line"] in keep), "/", sum(r["line"] in keep for r in rows))
PY
```

**1.440 request của PayloadsAllTheThings.** So `runs/p3b_v1/base_dev.jsonl` (bộ nguyên vẹn) với `runs/p7_builtin/base_patt.jsonl`
(sau khi ghi đè). Khi bỏ qua 9 rule bị ghi đè, hai cấu hình cho cùng rule ở cả 1.440 request. Với bộ nguyên vẹn, 163 request chỉ
sinh alert 31101.
