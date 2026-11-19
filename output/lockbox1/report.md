# LOCKBOX — dataset_lockbox1.csv (split lockbox)

Tạo 2026-10-28T16:46:08+0000. Model sha256 `7b5186008494a265…`, op fp5, ngưỡng 0.7573061065. Bootstrap 1000 lần theo phiên, phân tầng theo kịch bản, seed 12345. Mục 5 (hợp lệ): ĐẠT. Lockbox để ƯỚC LƯỢNG kèm khoảng tin cậy — không có ngưỡng đạt/không đạt.

Luật đang áp (thật): r401 110011 N=12 T=120s (ai), web_scan 110020 N=15 T=10s (ai), any 110030 N=500 T=10s (ai). Đối chứng mô phỏng: r401 110011 N=12 T=120s, web_scan 110020 N=15 T=10s, any 110030 N=600 T=10s — giờ manager_sec (thiếu 0 dòng -> giờ Apache).

## P1, P2, P5 — theo phiên

| phương pháp | phát hiện k=1 | số phiên bắt / không bắt | báo nhầm k=1 | số phiên báo nhầm | phát hiện k=3 | báo nhầm k=3 |
|---|---|---|---|---|---|---|
| RF (fp5, k=1) | 100.0% [100.0; 100.0] | 210 / 0 (của 210) | 4.2% [2.1; 6.7] | 10 / 240 | 100.0% | 0.8% |
| Luật v4-AI (alert 110xxx THẬT) | 84.3% [80.5; 87.6] | 177 / 33 (của 210) | 5.8% [3.3; 8.8] | 14 / 240 | 62.4% | 4.6% |
| RF HOẶC luật (P5, phụ) | 100.0% [100.0; 100.0] | 210 / 0 (của 210) | 8.8% [5.8; 11.7] | 21 / 240 | 100.0% | 5.8% |
| Luật v3 — nhãn thật (MÔ PHỎNG chung, đối chứng P6) | 81.0% [77.1; 84.8] | 170 / 40 (của 210) | 4.2% [2.1; 6.7] | 10 / 240 | 58.1% | 2.9% |

## P3 — thời gian đến phát hiện (chỉ trên phiên bị bắt)

| phương pháp | phiên bị bắt | không bị bắt | giây: trung vị / p90 | số alert đến lần đầu: trung vị / p90 |
|---|---|---|---|---|
| RF (fp5, k=1) | 210 | 0 | 0.1 / 11.5 | 2 / 9 |
| Luật v4-AI (alert 110xxx THẬT) | 177 | 33 | 3.1 / 68.9 | 15 / 500 |
| RF HOẶC luật (P5, phụ) | 210 | 0 | 0.1 / 11.5 | 2 / 9 |
| Luật v3 — nhãn thật (MÔ PHỎNG chung, đối chứng P6) | 170 | 40 | 2.8 / 68.7 | 15 / 600 |

## P4, P5 — hiệu ghép cặp (điểm phần trăm, CI 95% bootstrap ghép cặp)

| so sánh | Δ phát hiện | Δ báo nhầm |
|---|---|---|
| RF − luật (P4) | +15.7 [12.4; 19.5] | -1.7 [-5.0; 2.1] |
| (RF HOẶC luật) − RF: tăng thêm so với RF (P5) | +0.0 [0.0; 0.0] | +4.6 [2.1; 7.5] |
| (RF HOẶC luật) − luật (P5) | +15.7 [12.4; 19.5] | +2.9 [1.2; 5.0] |
| luật đang áp − luật v3 mô phỏng (P6) | +3.3 [1.4; 5.7] | +1.7 [0.4; 3.3] |
| RF − luật v3 mô phỏng (phụ) | +19.0 [15.2; 22.9] | +0.0 [-3.3; 3.3] |

## Theo kịch bản (tỉ lệ phiên bị bắt k=1; TTD giây trung vị trên phiên bị bắt)

| kịch bản | nhãn | phiên | RF | luật | RF HOẶC luật | v3 mô phỏng | TTD RF | TTD luật |
|---|---|---|---|---|---|---|---|---|
| api_client | 0 | 30 | 0.0% | 0.0% | 0.0% | 0.0% | — | — |
| broken_links | 0 | 30 | 23.3% | 26.7% | 46.7% | 26.7% | — | — |
| browse_human | 0 | 30 | 0.0% | 0.0% | 0.0% | 0.0% | — | — |
| crawler | 0 | 30 | 0.0% | 0.0% | 0.0% | 0.0% | — | — |
| forgot_pw | 0 | 30 | 0.0% | 0.0% | 0.0% | 0.0% | — | — |
| heavy_burst | 0 | 30 | 10.0% | 20.0% | 23.3% | 6.7% | — | — |
| monitor | 0 | 30 | 0.0% | 0.0% | 0.0% | 0.0% | — | — |
| typo_login | 0 | 30 | 0.0% | 0.0% | 0.0% | 0.0% | — | — |
| auth_fast | 1 | 30 | 100.0% | 100.0% | 100.0% | 100.0% | 0.1 | 1.1 |
| auth_slow | 1 | 30 | 100.0% | 93.3% | 100.0% | 93.3% | 7.0 | 42.1 |
| flood | 1 | 30 | 100.0% | 83.3% | 100.0% | 63.3% | 0.0 | 6.6 |
| recon_then_brute | 1 | 30 | 100.0% | 100.0% | 100.0% | 100.0% | 0.0 | 0.7 |
| scan_fast | 1 | 30 | 100.0% | 100.0% | 100.0% | 100.0% | 0.1 | 0.8 |
| scan_pulsed | 1 | 30 | 100.0% | 86.7% | 100.0% | 86.7% | 0.1 | 62.6 |
| scan_stealth | 1 | 30 | 100.0% | 26.7% | 100.0% | 23.3% | 6.0 | 11.8 |

## Stress (benign trông như tấn công; báo cáo riêng)

- RF (fp5, k=1): báo nhầm 15/18 phiên
- Luật v4-AI (alert 110xxx THẬT): báo nhầm 13/18 phiên
- RF HOẶC luật (P5, phụ): báo nhầm 15/18 phiên
- Luật v3 — nhãn thật (MÔ PHỎNG chung, đối chứng P6): báo nhầm 13/18 phiên

## Mục 5 — hợp lệ

- ĐẠT — 5.1 đủ phiên, 0 lỗi mạng, 0 phiên mồ côi
- ĐẠT — 5.2 coverage mọi phiên trong [0,98; 1,02]
- ĐẠT — 5.3 phiên bị loại <= 14 (3% của 468)
- ĐẠT — 5.4 không có alert chưa giải thích
- ĐẠT — 5.5 ai-service trực tiếp == offline (check_pipeline --stage live)

Phiên bị loại: không có

Phụ: wF1 theo alert của RF = 0.967 (KHÔNG so wF1 với luật — luật tần suất chỉ bắn ở sự kiện thứ N, 2N…).
