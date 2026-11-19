# THỬ — KHÔNG PHẢI LOCKBOX — dataset_dev_rules3.csv (split test)

Tạo 2026-10-28T15:07:33+0000. Model sha256 `7b5186008494a265…`, op fp5, ngưỡng 0.7573061065. Bootstrap 1000 lần theo phiên, phân tầng theo kịch bản, seed 12345. Mục 5 (hợp lệ): ĐẠT. Lockbox để ƯỚC LƯỢNG kèm khoảng tin cậy — không có ngưỡng đạt/không đạt.

Luật đang áp (thật): r401 110011 N=12 T=120s (ai), web_scan 110020 N=15 T=10s (ai), any 110030 N=500 T=10s (ai). Đối chứng mô phỏng: r401 110011 N=12 T=120s, web_scan 110020 N=15 T=10s, any 110030 N=600 T=10s — giờ manager_sec (thiếu 0 dòng -> giờ Apache).

## P1, P2, P5 — theo phiên

| phương pháp | phát hiện k=1 | số phiên bắt / không bắt | báo nhầm k=1 | số phiên báo nhầm | phát hiện k=3 | báo nhầm k=3 |
|---|---|---|---|---|---|---|
| RF (fp5, k=1) | 100.0% [100.0; 100.0] | 21 / 0 (của 21) | 8.3% [0.0; 16.7] | 2 / 24 | 100.0% | 4.2% |
| Luật v4-AI (alert 110xxx THẬT) | 81.0% [66.7; 95.2] | 17 / 4 (của 21) | 8.3% [0.0; 12.5] | 2 / 24 | 52.4% | 8.3% |
| RF HOẶC luật (P5, phụ) | 100.0% [100.0; 100.0] | 21 / 0 (của 21) | 12.5% [4.2; 20.8] | 3 / 24 | 100.0% | 12.5% |
| Luật v3 — nhãn thật (MÔ PHỎNG chung, đối chứng P6) | 76.2% [61.9; 90.5] | 16 / 5 (của 21) | 8.3% [0.0; 12.5] | 2 / 24 | 52.4% | 8.3% |

## P3 — thời gian đến phát hiện (chỉ trên phiên bị bắt)

| phương pháp | phiên bị bắt | không bị bắt | giây: trung vị / p90 | số alert đến lần đầu: trung vị / p90 |
|---|---|---|---|---|
| RF (fp5, k=1) | 21 | 0 | 0.1 / 14.7 | 2 / 12 |
| Luật v4-AI (alert 110xxx THẬT) | 17 | 4 | 2.5 / 69.9 | 15 / 302 |
| RF HOẶC luật (P5, phụ) | 21 | 0 | 0.1 / 14.7 | 2 / 12 |
| Luật v3 — nhãn thật (MÔ PHỎNG chung, đối chứng P6) | 16 | 5 | 1.8 / 79.1 | 15 / 78 |

## P4, P5 — hiệu ghép cặp (điểm phần trăm, CI 95% bootstrap ghép cặp)

| so sánh | Δ phát hiện | Δ báo nhầm |
|---|---|---|
| RF − luật (P4) | +19.0 [4.8; 33.3] | +0.0 [-8.3; 8.3] |
| (RF HOẶC luật) − RF: tăng thêm so với RF (P5) | +0.0 [0.0; 0.0] | +4.2 [0.0; 12.5] |
| (RF HOẶC luật) − luật (P5) | +19.0 [4.8; 33.3] | +4.2 [0.0; 8.3] |
| luật đang áp − luật v3 mô phỏng (P6) | +4.8 [0.0; 14.3] | +0.0 [0.0; 0.0] |
| RF − luật v3 mô phỏng (phụ) | +23.8 [9.5; 38.1] | +0.0 [-8.3; 8.3] |

## Theo kịch bản (tỉ lệ phiên bị bắt k=1; TTD giây trung vị trên phiên bị bắt)

| kịch bản | nhãn | phiên | RF | luật | RF HOẶC luật | v3 mô phỏng | TTD RF | TTD luật |
|---|---|---|---|---|---|---|---|---|
| api_client | 0 | 3 | 0.0% | 0.0% | 0.0% | 0.0% | — | — |
| broken_links | 0 | 3 | 33.3% | 66.7% | 66.7% | 66.7% | — | — |
| browse_human | 0 | 3 | 0.0% | 0.0% | 0.0% | 0.0% | — | — |
| crawler | 0 | 3 | 0.0% | 0.0% | 0.0% | 0.0% | — | — |
| forgot_pw | 0 | 3 | 0.0% | 0.0% | 0.0% | 0.0% | — | — |
| heavy_burst | 0 | 3 | 33.3% | 0.0% | 33.3% | 0.0% | — | — |
| monitor | 0 | 3 | 0.0% | 0.0% | 0.0% | 0.0% | — | — |
| typo_login | 0 | 3 | 0.0% | 0.0% | 0.0% | 0.0% | — | — |
| auth_fast | 1 | 3 | 100.0% | 100.0% | 100.0% | 100.0% | 0.1 | 1.1 |
| auth_slow | 1 | 3 | 100.0% | 100.0% | 100.0% | 100.0% | 10.7 | 10.7 |
| flood | 1 | 3 | 100.0% | 66.7% | 100.0% | 33.3% | 0.1 | 10.5 |
| recon_then_brute | 1 | 3 | 100.0% | 100.0% | 100.0% | 100.0% | 0.0 | 0.4 |
| scan_fast | 1 | 3 | 100.0% | 100.0% | 100.0% | 100.0% | 0.0 | 0.4 |
| scan_pulsed | 1 | 3 | 100.0% | 66.7% | 100.0% | 66.7% | 0.1 | 74.4 |
| scan_stealth | 1 | 3 | 100.0% | 33.3% | 100.0% | 33.3% | 14.7 | 40.3 |

## Stress (benign trông như tấn công; báo cáo riêng)

- RF (fp5, k=1): báo nhầm 2/4 phiên
- Luật v4-AI (alert 110xxx THẬT): báo nhầm 2/4 phiên
- RF HOẶC luật (P5, phụ): báo nhầm 2/4 phiên
- Luật v3 — nhãn thật (MÔ PHỎNG chung, đối chứng P6): báo nhầm 2/4 phiên

## Mục 5 — hợp lệ

- ĐẠT — 5.1 đủ phiên, 0 lỗi mạng, 0 phiên mồ côi
- ĐẠT — 5.2 coverage mọi phiên trong [0,98; 1,02]
- ĐẠT — 5.3 phiên bị loại <= 4 (3% của 154)
- ĐẠT — 5.4 không có alert chưa giải thích
- ĐẠT — 5.5 ai-service trực tiếp == offline (check_pipeline --stage live)

Phiên bị loại: không có

Phụ: wF1 theo alert của RF = 0.954 (KHÔNG so wF1 với luật — luật tần suất chỉ bắn ở sự kiện thứ N, 2N…).
