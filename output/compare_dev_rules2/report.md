# Luật thật so với mô phỏng — dataset_dev_rules2.csv

32178 dòng, 128 phiên. Luật đang áp: r401 (110011: N=12, T=120s), web_scan (110020: N=15, T=10s), any (110030: N=600, T=10s)
Alert theo rule trong dataset: {'100010': 14377, '100012': 11015, '100011': 4962, '110020': 745, '110011': 422, '100014': 283, '100013': 266, '100015': 103, '110030': 5}. Dòng không tìm thấy alert: 0.

Trễ Manager − Apache: trung vị 0.357 s, p95 1.683 s, p99 2.446 s, max 6.867 s, min 0.001 s.

| cách tính giờ | luật | phiên khớp từng dòng | phiên khớp bắt/không bắt | phiên thật bắt | phiên mô phỏng bắt | lần khớp thật | lần khớp mô phỏng |
|---|---|---|---|---|---|---|---|
| apache | r401 | 123/128 | 128/128 | 25 | 25 | 422 | 422 |
| apache | web_scan | 118/128 | 127/128 | 31 | 30 | 745 | 735 |
| apache | any | 125/128 | 125/128 | 5 | 4 | 5 | 5 |
| manager | r401 | 123/128 | 128/128 | 25 | 25 | 422 | 422 |
| manager | web_scan | 119/128 | 128/128 | 31 | 31 | 745 | 736 |
| manager | any | 125/128 | 125/128 | 5 | 4 | 5 | 5 |
| manager_sec | r401 | 123/128 | 128/128 | 25 | 25 | 422 | 422 |
| manager_sec | web_scan | 121/128 | 128/128 | 31 | 31 | 745 | 741 |
| manager_sec | any | 125/128 | 125/128 | 5 | 4 | 5 | 5 |
| joint | r401 | 123/128 | 128/128 | 25 | 25 | 422 | 422 |
| joint | web_scan | 121/128 | 128/128 | 31 | 31 | 745 | 741 |
| joint | any | 126/128 | 126/128 | 5 | 3 | 5 | 3 |

Dòng mà mô phỏng độc lập (manager_sec) cho >= 2 luật cùng khớp (Wazuh chỉ sinh 1 alert): 1
Thứ tự nạp dùng cho 'joint': r401 (110011) -> web_scan (110020) -> any (110030)

## Chỗ lệch (joint, tối đa 20 mỗi luật)

Dòng = vị trí trong phiên (0-based). span = giây giữa sự kiện cha thứ 1 và thứ N tính đến dòng đó (so với T).

- r401 · dev_rules2/train_auth_fast_001 (auth_fast, nhãn 1): chỉ thật [562, 864, 876, 888, 900, 912, 924, 936] span [0.0, 1.0, 0.0, 1.0, 1.0]; chỉ mô phỏng [563, 863, 875, 887, 899, 911, 923, 935] span [0.0, 1.0, 0.0, 1.0, 1.0] (T=120, N=12)
- r401 · dev_rules2/train_auth_fast_002 (auth_fast, nhãn 1): chỉ thật [97, 109, 121, 133, 145, 157, 169, 181, 193, 205] span [2.0, 2.0, 3.0, 3.0, 2.0]; chỉ mô phỏng [95, 107, 119, 131, 143, 155, 167, 179, 191, 203] span [2.0, 3.0, 2.0, 4.0, 2.0] (T=120, N=12)
- r401 · dev_rules2/train_auth_fast_003 (auth_fast, nhãn 1): chỉ thật [13, 25, 37, 49, 61, 73, 85, 97, 109, 121] span [1.0, 0.0, 0.0, 1.0, 0.0]; chỉ mô phỏng [11, 23, 35, 47, 59, 71, 83, 95, 107, 119] span [1.0, 0.0, 0.0, 1.0, 0.0] (T=120, N=12)
- r401 · dev_rules2/train_recon_then_brute_000 (recon_then_brute, nhãn 1): chỉ thật [1007] span [0.0]; chỉ mô phỏng [1008] span [0.0] (T=120, N=12)
- r401 · dev_rules2/train_recon_then_brute_001 (recon_then_brute, nhãn 1): chỉ thật [203, 505] span [1.0, 0.0]; chỉ mô phỏng [204, 504] span [1.0, 1.0] (T=120, N=12)
- web_scan · dev_rules2/test_recon_then_brute_000 (recon_then_brute, nhãn 1): chỉ thật [62, 187, 280, 617, 632, 647, 662, 679, 694, 710] span [1.0, 1.0, 1.0, 1.0, 0.0]; chỉ mô phỏng [61, 186, 281, 616, 631, 646, 661, 678, 693, 709] span [1.0, 1.0, 1.0, 1.0, 0.0] (T=10, N=15)
- web_scan · dev_rules2/test_recon_then_brute_001 (recon_then_brute, nhãn 1): chỉ thật [16, 17, 32, 48, 63, 78, 93, 111, 127, 142] span [0.0, 0.0, 0.0, 1.0, 0.0]; chỉ mô phỏng [14, 29, 45, 60, 75, 90, 108, 124, 139, 154] span [0.0, 0.0, 1.0, 0.0, 1.0] (T=10, N=15)
- web_scan · dev_rules2/test_scan_fast_001 (scan_fast, nhãn 1): chỉ thật [445, 569, 584, 600, 615, 630, 646, 662, 677, 692] span [1.0, 1.0, 0.0, 0.0, 1.0]; chỉ mô phỏng [446, 568, 583, 599, 614, 629, 645, 660, 676, 691] span [1.0, 1.0, 0.0, 0.0, 1.0] (T=10, N=15)
- web_scan · dev_rules2/test_scan_fast_002 (scan_fast, nhãn 1): chỉ thật [55, 68, 80, 95, 110, 126, 141, 142, 157, 172] span [0.0, 0.0, 0.0, 0.0, 1.0]; chỉ mô phỏng [47, 62, 78, 93, 108, 123, 139, 154, 169, 184] span [1.0, 0.0, 0.0, 0.0, 1.0] (T=10, N=15)
- web_scan · dev_rules2/test_scan_stealth_002 (scan_stealth, nhãn 1): chỉ thật [272] span [11.0]; chỉ mô phỏng [274] span [10.0] (T=10, N=15)
- web_scan · dev_rules2/train_recon_then_brute_000 (recon_then_brute, nhãn 1): chỉ thật [310, 326, 340, 357, 372, 387, 404, 420, 435, 450] span [0.0, 0.0, 0.0, 1.0, 0.0]; chỉ mô phỏng [309, 324, 339, 356, 371, 386, 403, 419, 434, 449] span [1.0, 0.0, 0.0, 1.0, 0.0] (T=10, N=15)
- web_scan · dev_rules2/val_scan_fast_001 (scan_fast, nhãn 1): chỉ thật [31] span [2.0]; chỉ mô phỏng [30] span [2.0] (T=10, N=15)
- any · dev_rules2/test_flood_000 (flood, nhãn 1): chỉ thật [684] span [11.0]; chỉ mô phỏng [] span [] (T=10, N=600)
- any · dev_rules2/val_flood_000 (flood, nhãn 1): chỉ thật [645] span [11.0]; chỉ mô phỏng [] span [] (T=10, N=600)
