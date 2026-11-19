# PREREG — đăng ký trước cho đánh giá cuối của bộ luật chữ ký

**Chốt: 15/11/2026 17:08 giờ VN (10:08 UTC)**, trước khi tải hay đọc bất kỳ dòng nào của tập giữ riêng FuzzDB và trước khi
đọc nội dung tập bình thường `benign2_raw.txt`.

## 1. Bộ luật đóng băng

- `rules/zy_siem10_sig_rules.xml` sha256 c5a016d3d8b0ef5823ca0e24c96ed169bc4937050c4daf21a104aa3e415ba3c1
  (sinh từ `tools/sig_rules_gen.py` sha256 67de2498625f81da90ad6b918e45ca0dc367adb7d162a69db91c30de4ec6de87).
  Hai mã băm này là của tệp đã cài lên Manager khi đánh giá. Tệp trong bản nộp chỉ khác ở 4 dòng chú thích đầu tệp luật
  và ở chú thích, docstring, chữ in ra màn hình của bộ sinh; phần luật trùng từng byte (xem `README.md`).
- 20 luật đơn level 8 (100110–100118, 100120–100123, 100130–100133, 100140–100142), không có luật tần suất; phần ghi đè
  (9 luật mã trạng thái hạ level 0 bằng overwrite) giữ nguyên.
- Dữ liệu phát triển (được xem khi viết/chỉnh luật): PayloadsAllTheThings (`payloads/dev`), SecLists (`payloads/test`,
  dùng làm tập kiểm tra sơ bộ khi soạn luật nên tính là dữ liệu phát triển), hai tập bình thường dùng khi soạn luật
  (`benign_dev`, `benign_test`).

## 2. Tập giữ riêng (định nghĩa trước khi tải)

- **Tấn công:** FuzzDB (github.com/fuzzdb-project/fuzzdb, nhánh master, raw), 19 file:
  sqli — sql-injection/detect/{xplatform, GenericBlind, MySQL, MSSQL, MSSQL_blind, oracle}.txt,
  sql-injection/exploit/mysql-injection-login-bypass.txt;
  xss — xss/{xss-other, xss-uri, XSSPolyglot, JHADDIX_XSS_WITH_CONTEXT.doc}.txt;
  traversal — path-traversal/path-traversal-windows.txt, lfi/{JHADDIX_LFI, common-unix-httpd-log-locations,
  common-ms-httpd-log-locations}.txt;
  cmdi — os-cmd-execution/{command-injection-template, OSCommandInject.Windows, source-disc-cmd-exec-traversal,
  command-execution-unix}.txt.
- Xử lý (cài sẵn trong `tools/build_payloads_v2.py`, chạy KHÔNG in nội dung): bỏ dòng rỗng, dòng > 400 ký tự, dòng không phải
  UTF-8, dòng bắt đầu bằng "# " (chú thích), dòng chứa chỗ giữ chỗ dạng `{tên}` (2–12 chữ cái/gạch dưới); bỏ trùng trong tập;
  bỏ mọi payload trùng (hạ chữ thường, gộp khoảng trắng) với BẤT KỲ payload nào của PayloadsAllTheThings hay SecLists đã tải;
  lấy ngẫu nhiên 120 payload mỗi loại (seed 20261116). Mã hóa E1/E2/E3, vị trí và trang/tham số như tập phát triển (mục 3).
- **Bình thường khó:** `payloads/src/benign2_raw.txt` (60 dòng, 10 ngữ cảnh × 6, sha256 22e463a3…46ec), soạn độc lập với bộ
  luật, theo một mô tả chỉ nói "mẫu dữ liệu người dùng gõ vào ô tìm kiếm/biểu mẫu trên các website thông thường" — không nhắc
  tới bảo mật, tấn công hay phát hiện; người viết luật không đọc trước. Mã hóa F (form) và E1; tham số theo băm như cũ.

## 3. Định nghĩa và chỉ số

- Một ca = một request. Ca được bộ X nhận ra nếu dòng access_log của nó sinh alert thuộc bộ X.
- Kiểu mã hóa: E1 = như trình duyệt (tập mã hóa WHATWG cho query/path); E2 = mã hóa mọi ký tự ngoài `[A-Za-z0-9-._~]`;
  E3 = E2 rồi mã hóa lại `%`. Giá trị bình thường: F = mã hóa biểu mẫu (khoảng trắng thành `+`) và E1. SQLi/XSS/lệnh nằm trong
  giá trị một tham số query; traversal xen kẽ query và đường dẫn `/static/…`. Trang và tên tham số chọn theo băm payload.
- Bộ luật web mặc định ("dựng sẵn") = các luật xét nội dung: 31103–31106, 31109, 31110, 31115, 31152–31154, 31164–31171,
  315xx (0270). Không tính 9 luật chỉ xét mã trạng thái đã hạ level 0. Đo bằng phát lại CHÍNH các dòng access_log qua
  wazuh-logtest với tệp tạm vô hiệu hóa 20 luật chữ ký (`sig_eval.py --configs builtin`), không gửi lại request.
- "Luật chữ ký" (id 100110–100142) và "hợp" (dựng sẵn HOẶC chữ ký) lấy từ alert thật trên Manager. Luật chữ ký level 8 che
  luật dựng sẵn khi cùng khớp (`ref/NOTES.md` mục 17).
- Đơn vị thống kê chính là **payload** (n = 120 mỗi loại; giá trị bình thường n = 60), vì ba kiểu mã hóa của một payload không độc
  lập. Báo kèm theo ca và theo kiểu mã hóa. Một giá trị bình thường bị tính là báo nhầm khi ít nhất một trong hai request mang nó
  sinh alert.
- Phiên: 4 phiên tấn công theo loại (5 req/s), 1 phiên bình thường (1 req/s), IP 172.30.90.244–.248. Chạy MỘT lần.
- Lần chạy chỉ được làm lại nếu hỏng kỹ thuật (số dòng log lệch, drops > 0, agent mất kết nối, Manager khởi động lại giữa chừng).
- Sau khi chạy: không sửa luật; ca lọt chỉ được phân loại nguyên nhân.

## 4. Sửa đổi trước khi gửi (15/11/2026 10:08–10:09 UTC, sau khi tải, TRƯỚC khi gửi hay đọc nội dung)

Lý do: thống kê hình dạng (không xem nội dung) do `build_payloads_v2.py --stats-only` in ra cho thấy hai vấn đề về chất lượng:
1. `xss/JHADDIX_XSS_WITH_CONTEXT.doc.txt` là tệp TÀI LIỆU: 68% dòng có khoảng trắng nhưng không có ký tự đặc biệt nào (văn xuôi
   mô tả ngữ cảnh), và chiếm 109/120 mẫu XSS. -> BỎ tệp này khỏi tập XSS.
2. Lệnh: sau khi bỏ trùng với dữ liệu phát triển chỉ còn 27 payload (command-execution-unix.txt trùng hoàn toàn với
   PayloadsAllTheThings; command-injection-template.txt có chỗ giữ chỗ `{cmd}` ở cả 57 dòng nên bị bộ lọc loại). -> Điền `{cmd}`
   bằng 2 lệnh lấy ngẫu nhiên (seed 20261117) từ FuzzDB `os-cmd-execution/Commands-Linux.txt` và `Commands-Windows.txt`
   (sha256 trong `payloads/src/manifest_test2_fill.txt`). Lệnh điền lấy từ FuzzDB, không do người viết luật chọn.
Kết quả: sqli 120 (đủ điều kiện 137), xss 120 (134), traversal 120 (538), cmdi 120 (141; 96 từ mẫu đã điền).
`payloads/test2/cases.jsonl` sha256 72a172e9…2e4e (1.440 ca), `payloads/benign2/cases.jsonl` sha256 bdc89b6e…1594 (120 ca).
Payload trùng dữ liệu phát triển đã loại: sqli 173, xss 54, traversal 370, cmdi 62.
