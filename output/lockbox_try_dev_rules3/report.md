# THỬ — KHÔNG PHẢI LOCKBOX — dataset_dev_rules3.csv (split test)

Tạo 2026-10-26T14:42:08+0000. Model sha256 `7b5186008494a265…`, op fp5, ngưỡng 0.7573061065. Bootstrap 1000 lần theo phiên, phân tầng theo kịch bản, seed 12345. Mục 5 (hợp lệ): ĐẠT. Lockbox để ƯỚC LƯỢNG kèm khoảng tin cậy — không có ngưỡng đạt/không đạt.

## P1, P2, P5 — theo phiên

| phương pháp | phát hiện k=1 | số phiên bắt / không bắt | báo nhầm k=1 | số phiên báo nhầm | phát hiện k=3 | báo nhầm k=3 |
|---|---|---|---|---|---|---|
| RF (fp5, k=1) | 100.0% [100.0; 100.0] | 21 / 0 (của 21) | 8.3% [0.0; 16.7] | 2 / 24 | 100.0% | 4.2% |
| Luật v3 (alert 110xxx THẬT) | 81.0% [66.7; 95.2] | 17 / 4 (của 21) | 8.3% [0.0; 12.5] | 2 / 24 | 52.4% | 8.3% |
| RF HOẶC luật (P5, phụ) | 100.0% [100.0; 100.0] | 21 / 0 (của 21) | 12.5% [4.2; 20.8] | 3 / 24 | 100.0% | 12.5% |

## P3 — thời gian đến phát hiện (chỉ trên phiên bị bắt)

| phương pháp | phiên bị bắt | không bị bắt | giây: trung vị / p90 | số alert đến lần đầu: trung vị / p90 |
|---|---|---|---|---|
| RF (fp5, k=1) | 21 | 0 | 0.1 / 14.7 | 2 / 12 |
| Luật v3 (alert 110xxx THẬT) | 17 | 4 | 2.5 / 69.9 | 15 / 302 |
| RF HOẶC luật (P5, phụ) | 21 | 0 | 0.1 / 14.7 | 2 / 12 |

## P4, P5 — hiệu ghép cặp (điểm phần trăm, CI 95% bootstrap ghép cặp)

| so sánh | Δ phát hiện | Δ báo nhầm |
|---|---|---|
| RF − luật (P4) | +19.0 [4.8; 33.3] | +0.0 [-8.3; 8.3] |
| (RF HOẶC luật) − RF: tăng thêm so với RF (P5) | +0.0 [0.0; 0.0] | +4.2 [0.0; 12.5] |
| (RF HOẶC luật) − luật (P5) | +19.0 [4.8; 33.3] | +4.2 [0.0; 8.3] |

## Theo kịch bản (tỉ lệ phiên bị bắt k=1; TTD giây trung vị trên phiên bị bắt)

| kịch bản | nhãn | phiên | RF | luật | RF HOẶC luật | TTD RF | TTD luật |
|---|---|---|---|---|---|---|---|
| api_client | 0 | 3 | 0.0% | 0.0% | 0.0% | — | — |
| broken_links | 0 | 3 | 33.3% | 66.7% | 66.7% | — | — |
| browse_human | 0 | 3 | 0.0% | 0.0% | 0.0% | — | — |
| crawler | 0 | 3 | 0.0% | 0.0% | 0.0% | — | — |
| forgot_pw | 0 | 3 | 0.0% | 0.0% | 0.0% | — | — |
| heavy_burst | 0 | 3 | 33.3% | 0.0% | 33.3% | — | — |
| monitor | 0 | 3 | 0.0% | 0.0% | 0.0% | — | — |
| typo_login | 0 | 3 | 0.0% | 0.0% | 0.0% | — | — |
| auth_fast | 1 | 3 | 100.0% | 100.0% | 100.0% | 0.1 | 1.1 |
| auth_slow | 1 | 3 | 100.0% | 100.0% | 100.0% | 10.7 | 10.7 |
| flood | 1 | 3 | 100.0% | 66.7% | 100.0% | 0.1 | 10.5 |
| recon_then_brute | 1 | 3 | 100.0% | 100.0% | 100.0% | 0.0 | 0.4 |
| scan_fast | 1 | 3 | 100.0% | 100.0% | 100.0% | 0.0 | 0.4 |
| scan_pulsed | 1 | 3 | 100.0% | 66.7% | 100.0% | 0.1 | 74.4 |
| scan_stealth | 1 | 3 | 100.0% | 33.3% | 100.0% | 14.7 | 40.3 |

## Stress (benign trông như tấn công; báo cáo riêng)

- RF (fp5, k=1): báo nhầm 2/4 phiên
- Luật v3 (alert 110xxx THẬT): báo nhầm 2/4 phiên
- RF HOẶC luật (P5, phụ): báo nhầm 2/4 phiên

## Mục 5 — hợp lệ

- ĐẠT — 5.1 đủ phiên, 0 lỗi mạng, 0 phiên mồ côi
- ĐẠT — 5.2 coverage mọi phiên trong [0,98; 1,02]
- ĐẠT — 5.3 phiên bị loại <= 4 (3% của 154)
- ĐẠT — 5.4 không có alert chưa giải thích
- ĐẠT — 5.5 ai-service trực tiếp == offline (check_pipeline --stage live)

Phiên bị loại: không có

Phụ: wF1 theo alert của RF = 0.954 (KHÔNG so wF1 với luật — luật tần suất chỉ bắn ở sự kiện thứ N, 2N…).
