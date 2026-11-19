# LOCKBOX — đăng ký trước (pre-registration)

**Trạng thái: ĐÃ CHỐT 26/10/2026 21:46 (UTC+7).** Nội dung duyệt 21:23; số từ bản kê 21:43; thử `lockbox_eval` trên
dev_rules3 (split test, có kiểm ai-service trực tiếp) 21:44: mục 5 đạt cả 5 điều kiện, metrics chạy (báo cáo "THỬ"). Sau khi chốt:
không sửa nội dung nữa. Mọi thay đổi sau ngày chốt ghi vào mục 9 (Sai lệch), không sửa các mục trên.

## 1. Mục đích và cam kết

Lockbox là batch traffic **mới, chạy một lần, ở cuối**, cho số liệu chính của Chương 4. Test full1 đã được dùng trong
giai đoạn phát triển, nên không còn là dữ liệu "chưa nhìn"; lockbox thay vai trò đó.

**Lockbox dùng để ƯỚC LƯỢNG kèm khoảng tin cậy — không đặt trước ngưỡng đạt/không đạt cho bất kỳ chỉ số nào.**

Cam kết: từ ngày chốt đến khi có kết quả, KHÔNG đổi model, ngưỡng, bộ luật, code, cấu hình stack, quy tắc loại phiên
hay định nghĩa chỉ số. Sau khi thấy kết quả lockbox cũng không đổi rồi báo lại số lockbox như thể chưa nhìn. Nếu buộc
phải sửa (lỗi), ghi vào mục 9 và nói rõ trong báo cáo.

## 2. Những gì được khóa

| Thành phần | Giá trị khóa |
|---|---|
| Model | `models/full1/model.joblib`, sha256 `7b5186008494a265d7dbe800a7cb39e347b011d644c07af64ba11b0aba97474d` |
| Đặc trưng | 15 cột `NO_URL_COLUMNS`; `features.py` sha `2f738e629753c3ba` |
| Điểm vận hành | `fp5`, ngưỡng 0.7573061065 (chọn trên val full1: ≤ 5% phiên benign val bị báo nhầm). Không dùng `f1` cho số chính |
| Bộ luật Wazuh | v3, đúng 3 luật đang `applied`, thứ tự nạp: `R110011-r401-N12-T120-20261022-163955` (if_matched_sid 100011, N=12, T=120 s) -> `R110020-web_scan-N15-T10-20261022-163955` (if_matched_group web_scan, N=15, T=10 s) -> `R110030-any-N600-T10-20261026-110447` (if_matched_group siemlab_observed, N=600, T=10 s); file `wazuh/ai_rules/zz_siem10_ai_rules.xml` sha256 `8744f00b849b82ab0f7d06f898628453266c5e2d1e9e3d9761b2546b5cc444a3`, phải trùng file đang chạy trong manager (`apply_rule.py sync`) |
| Code + cấu hình | bản kê `docs/lockbox_manifest.json` (sha256 từng file theo `PATTERNS` trong `scripts/lockbox_manifest.py`: scripts, setup, tests, Apache/site, rule + decoder, cấu hình agent + manager, compose, model + metrics, file luật AI; cùng danh sách đề xuất `applied`), digest tổng `0b3aa0e5e9438a88d0d4d0a26279bbc9b79a91cc7f2c7db72c3a798bde9232bd` (393 file, ghi 26/10/2026 21:43 trên máy thật; tính lại độc lập từ bản sao máy + bản nén -> trùng); `run_batch.code_digest()` = `ade18b2ad567192d` (trùng các batch dev1/dev_rules1–3: code sinh traffic không đổi) |
| Stack | luật v3 BẬT; ai-service BẬT (model trên, op fp5); vulnerability detection + syscollector của Manager TẮT (`setup/manager_tune.sh`; cấu hình manager sha256 `85d53c193ef455187cc1753875e865ff146f06d1e7595b4147ed21244abff6ca`); agent `logcollector.queue_size=220000` (`setup/agent_tune.sh`) |

## 3. Dữ liệu

- `run_batch.py --preset lockbox --batch-id lockbox1 --confirm-lockbox`. Seed ngẫu nhiên sinh ở lần chạy đầu, lưu
  `data/.lockbox_seed`; không ai xem trước kế hoạch phiên.
- Cùng phân phối với train full1 (không shift): 15 kịch bản × 10 phiên = **150 phiên** (70 tấn công / 80 benign), cộng
  **6 phiên stress** (misconfig_monitor, sso_retry_storm × 3; benign, báo cáo riêng).
- Không chạy traffic nào khác (batch khác, công cụ, canary thủ công) trong suốt batch.

## 4. Điều kiện hợp lệ TRƯỚC khi chạy (kiểm bằng `scripts/lockbox_preflight.py`, ghi kết quả vào hồ sơ)

0. `data/.lockbox_seed` CHƯA tồn tại (chưa ai sinh/xem seed) và `data/runs/lockbox1` chưa có.

1. Bản kê code + cấu hình trùng mục 2 (digest tổng, sha model, sha file luật AI).
2. `apply_rule.py list`: đúng 3 luật v3 `applied`, không luật nào khác; `sync` trùng nhau; `health` ĐẠT.
3. `ossec.conf` ĐANG CHẠY trong manager: vulnerability-detection `enabled no`, syscollector `disabled yes`.
4. ai-service đang chạy, dùng đúng model trên.
5. Manager nhàn rỗi: CPU container manager < 20% ở mọi mẫu trong 5 phút liên tục (mẫu mỗi 10 s), ghi các số đo.
6. Không còn batch nào đang chạy.

Không đạt điều kiện nào -> không chạy; sửa rồi kiểm lại (chưa tốn lockbox).

## 5. Điều kiện hợp lệ SAU khi chạy (lần chạy chỉ hợp lệ khi đạt TẤT CẢ)

1. 0 request lỗi mạng; không phiên mồ côi.
2. Coverage request -> siem.log -> alert: mọi phiên trong [0,98; 1,02] (`audit_coverage.py`, `build_dataset.py`).
3. **Phiên bị loại (coverage / failed / trễ lịch > 2 s) ≤ 3%**, tức ≤ 4 / 156 phiên. Liệt kê TỪNG phiên bị loại
   (session_key, kịch bản, nhãn, lý do) trong hồ sơ và báo cáo.
4. **Không có alert chưa giải thích**: `unknown_in_range` = 0 và `ambiguous` = 0 (`canary_in_range` của bước kiểm sức
   khỏe trước batch được phép, ghi lại).
5. ai-service trực tiếp == offline: thiếu/trùng/thừa 0, đặc trưng và điểm trùng tuyệt đối (`check_pipeline --stage live`).

**Mục 5 được kiểm XONG trước khi tính bất kỳ chỉ số mục 6 nào** (`lockbox_eval.py validate` ->
`output/lockbox1/validity.json`); `lockbox_eval.py metrics` TỪ CHỐI chạy nếu chưa có kết quả mục 5, mục 5 không đạt,
hoặc dataset đổi sau khi kiểm (sha256).

Vượt bất kỳ điều kiện nào -> lần chạy **không hợp lệ**: giữ nguyên dữ liệu + hồ sơ, tìm và sửa nguyên nhân (ghi mục 9),
lưu `data/.lockbox_seed` cũ vào hồ sơ, sinh seed MỚI, chạy `lockbox2`. Báo cáo nêu cả hai lần chạy và lý do. **Tối đa 2 lần chạy**; nếu cả hai
không hợp lệ, báo cáo nguyên trạng (không có số lockbox chính thức, nêu lý do), không chạy lần 3.

## 6. Chỉ số chính (tính theo PHIÊN, trên 150 phiên split `lockbox`)

| Mã | Chỉ số | Định nghĩa |
|---|---|---|
| P1 | RF fp5 — phát hiện / báo nhầm, k=1 | phiên bị bắt nếu ≥ 1 alert có điểm ≥ ngưỡng fp5 |
| P2 | Luật v3 trên Wazuh THẬT — phát hiện / báo nhầm | phiên bị bắt nếu có ≥ 1 alert 110011/110020/110030 thật (không mô phỏng) |
| P3 | Thời gian đến phát hiện (TTD) | CHỈ trên phiên bị bắt, kèm số phiên không bị bắt; báo cả số GIÂY (từ request đầu tiên của phiên đến alert đầu tiên bị gắn cờ / alert 110xxx đầu tiên) lẫn SỐ ALERT đến lần phát hiện đầu; trung vị (+ p90), tổng và theo kịch bản |
| P4 | Hiệu RF − luật | phát hiện và báo nhầm, khoảng tin cậy bootstrap ghép cặp theo phiên |

- Khoảng tin cậy 95%: bootstrap 1000 lần theo phiên, phân tầng theo kịch bản, seed 12345 (như `trainer.py`).
- Dùng chính các hàm của `trainer.py` (`summarize`, `boot_index`, `boot_stats`) để định nghĩa chỉ số giống hệt test full1.
- **P5 (chỉ số phụ, đã quyết 26/10):** "RF HOẶC luật" — phiên bị bắt nếu RF k=1 bắt hoặc có ≥ 1 alert 110xxx thật.
  Báo cáo phát hiện TĂNG THÊM và báo nhầm TĂNG THÊM so với RF một mình (và so với luật một mình), khoảng tin cậy
  bootstrap ghép cặp như P4.

**Chỉ số phụ (báo cáo, không dùng để kết luận chính):** k=3 cho RF; wF1 theo alert của RF (KHÔNG so wF1 với luật —
luật tần suất chỉ bắn ở sự kiện thứ N, 2N…); bảng theo kịch bản; stress (6 phiên): số phiên bị báo nhầm của RF và luật;
luật v3 mô phỏng (`compare_rules.py`, biến thể joint) so với alert thật trên lockbox.

## 7. Phân tích

- `scripts/lockbox_eval.py` (validate -> metrics), `scripts/lockbox_preflight.py`, `scripts/lockbox_manifest.py` viết, có test
  (`tests/test_lockbox.py`) và thử trên dev_rules3 TRƯỚC ngày chốt; nằm trong bản kê mục 2.
- Thứ tự cố định: preflight ĐẠT -> run_batch lockbox -> audit_coverage + build_dataset -> `lockbox_eval.py validate`
  (mục 5) -> chỉ khi đạt: `lockbox_eval.py metrics` (mục 6).
- Kết quả: `output/lockbox1/` (report.md + metrics.json + hồ sơ preflight + audit). Báo cáo mọi chỉ số ở mục 6, kể cả
  khi kết quả xấu. Không chọn lại ngưỡng, không bỏ thêm phiên ngoài quy tắc mục 5.

## 8. Cách đọc trong báo cáo

- Số chính của Chương 4 = mục 6 trên lockbox. Kết quả test/shift/tools/stress/leave-out của full1 là kết quả phát triển
  và độ bền, ghi nhãn rõ; test full1 ghi chú "đã dùng trong giai đoạn phát triển".
- Luôn kèm: dữ liệu do generator sinh (không phải người dùng thật); RF báo nhầm cao trên stress và yếu khi bỏ hẳn một họ
  tấn công (leave-family-out); luật bền hơn với hành vi mới.

## 9. Sai lệch so với bản đăng ký

### 9.1 — 28/10/2026: luật từ kết luận AI (v4-AI) + lockbox 30 phiên/kịch bản. Sửa TRƯỚC khi có dữ liệu lockbox.

**Thời điểm:** `data/.lockbox_seed` và `data/runs/lockbox1` chưa tồn tại (nhóm kiểm 28/10 13:56) — chưa ai sinh, xem
hay chạy phiên lockbox nào. Các mục 1–8 ở trên giữ nguyên làm hồ sơ bản chốt 26/10; nội dung dưới đây THAY các điểm tương ứng.

**Lý do:** thống nhất hệ thống với thiết kế của báo cáo (Chương 1–2: kết luận phân loại của AI là căn cứ đề xuất luật).
Ở bản 26/10, bộ v3 được chọn bằng nhãn thật (ý định kịch bản) và không dùng đầu ra của AI. Lý do cỡ mẫu: 10 phiên/kịch bản
cho khoảng tin cậy rộng; 30 phiên/kịch bản thu hẹp khoảng ~42%. Cỡ mẫu chốt trước khi có dữ liệu, không đổi theo kết quả.

**Thay đổi:**
1. **Bộ luật trên Wazuh thật = v4-AI** (thay v3). `rule_proposer.py --label-source ai`: nhãn để CHỌN = kết luận RF theo phiên
   (model sha256 `7b5186…`, fp5, ngưỡng 0.7573061065, phiên nghi ngờ nếu ≥ 1 alert có điểm ≥ ngưỡng — cùng định nghĩa P1);
   tập chọn = split val của full1 + toàn bộ dev1 trừ stress (240 phiên, đều là phiên RF chưa học; train full1 bị loại vì RF
   đã học, test full1 bị loại vì đã bị nhìn). Họ luật, lưới N/T, dò chung, hạn mức 5% (tính trên số phiên AI cho là sạch),
   cửa sổ xấu nhất theo nhãn, kiểm hồi quy giữ như v3. Thiết kế chốt trước khi chạy; kết quả chọn (chạy thử 28/10 trên dữ
   liệu máy thật, KHÔNG phải dữ liệu lockbox): AI khớp nhãn thật 236/240 phiên (4 phiên benign bị AI gắn cờ, 0 phiên tấn công
   bị bỏ sót); bộ v4-AI = r401 N=12 T=120 + web_scan N=15 T=10 + any N=500 T=10 (v3: any N=600). Ghi nhận trung thực: với dữ
   liệu chọn của v3 (train+val, nhãn thật), any N=500 vượt hạn mức báo nhầm khi tính làm tròn giây xấu nhất (11/192) — đó là
   lý do v3 dùng N=600; v4-AI chọn trên tập khác với nhãn khác và được giữ nguyên như kết quả của thiết kế.
   Đề xuất áp (28/10 ~22:05, gỡ 3 luật v3 trước, áp theo thứ tự id, logtest khớp đúng dòng 12 / 15 / 500, health ĐẠT, sync trùng): `AI-R110011-r401-N12-T120-20261028-150005`, `AI-R110020-web_scan-N15-T10-20261028-150005`, `AI-R110030-any-N500-T10-20261028-150005`; file luật AI `wazuh/ai_rules/zz_siem10_ai_rules.xml` sha256 `dcfdd6edd03626c37becd0b60ac520b7541b5d2262c654473aa41f29b96ecc15`.
   Điều kiện 2 của mục 4 (và dòng "Stack" của mục 2) vì vậy là đúng ba luật v4-AI này ở trạng thái `applied`, thay cho ba luật v3.
2. **v3 thành đối chứng mô phỏng (P6, mới):** 3 hồ sơ v3 (`R110011-r401-N12-T120-20261022-163955`,
   `R110020-web_scan-N15-T10-20261022-163955`, `R110030-any-N600-T10-20261026-110447`, trạng thái `removed` sau khi gỡ) được
   mô phỏng CHUNG (`wazuh_sim.joint_fires`, thứ tự nạp = id, giờ Manager làm tròn giây lấy từ alerts.json) trên đúng các
   phiên lockbox. Mô phỏng chung đã khớp Wazuh thật ở mức phiên trên dev_rules1–3 (153/154 với bộ v3; lệch theo hướng an toàn).
3. **Chỉ số (mục 6):** P2 = luật v4-AI (alert 110xxx THẬT). P4, P5 như cũ với "luật" = v4-AI. **P6 = v4-AI (thật) − v3 (mô
   phỏng)**: phát hiện và báo nhầm theo phiên, CI bootstrap ghép cặp như P4. Phụ: RF − v3 mô phỏng. Không thêm "AI VÀ luật"
   (nhóm quyết 28/10). Báo cáo ghi rõ P6 so sánh luật THẬT với luật MÔ PHỎNG.
   Chỉ số phụ cuối của mục 6 (mô phỏng `compare_rules.py`, biến thể joint, so với alert thật) áp cho chính ba luật v4-AI
   đang chạy.
4. **Dữ liệu (mục 3, 5.3 và 6):** `--preset lockbox` = 30 phiên mỗi kịch bản → **450 phiên** (210 tấn công / 240 benign) + **18 phiên
   stress** (9 mỗi kịch bản stress); ~154.000 request, ~55 phút. Trần phiên bị loại (mục 5.3) = 3% của 468 = **14 phiên**.
   Chỉ số chính ở mục 6 tính trên 450 phiên này thay cho 150 phiên; chỉ số phụ về stress tính trên 18 phiên thay cho 6.
5. **Code + cấu hình:** đổi `scripts/rule_proposer.py`, `scripts/lockbox_eval.py`, `scripts/run_batch.py` (chỉ preset lockbox
   — `scenarios.py`, `traffic.py`, `site_model.py` không đổi, nên `run_batch.code_digest()` đổi), `scripts/proposal_diff.py`,
   `scripts/apply_rule.py` (chỉ thông báo), `setup/propose_new.sh`, `tests/test_lockbox.py`, thêm `tests/test_rule_proposer_ai.py`.
   Bản kê ghi lại (`lockbox_manifest.py write --force`, máy thật 28/10 ~22:07): digest
   `5e55b4673c269d5bb8b66d7ff30fffcfcfa6484a8517339cd1fe8b20bc90ede0` (394 file), `run_batch.code_digest()` = `72db6b75c3791872`
   (tính lại độc lập từ bản nén: trùng). Model, đặc trưng, ngưỡng, cấu hình manager và agent KHÔNG đổi.
6. **Không đổi:** model + ngưỡng fp5, đặc trưng, quy tắc loại phiên, định nghĩa P1/P3/P4/P5, bootstrap (1000, phân tầng theo
   kịch bản, seed 12345), điều kiện mục 4–5, tối đa 2 lần chạy, lockbox chỉ để ước lượng (không ngưỡng đạt/không đạt).
7. Phần A lặp lại trên dev_rules3 (luật v3 thật lúc đó) chỉ để thử đường ống `lockbox_eval` mới (đối chứng mô phỏng, đọc luật
   từ hồ sơ applied), không phải kết quả.

Thử lại phần A trên dev_rules3 (28/10 22:07): mục 5 đạt cả 5 điều kiện (ai-service trực tiếp == offline 47.836/47.836, lệch 0);
metrics chạy với đối chứng v3 mô phỏng theo giờ Manager (thiếu 0 dòng); báo cáo "THỬ" (luật thật của dev_rules3 là v3).

Chốt lại: 28/10/2026 22:15 (UTC+7). Người duyệt: thuan.

---
Ngày chốt: 26/10/2026 21:46 (UTC+7). Người duyệt: thuan.
