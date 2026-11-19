# Luật thật so với mô phỏng — dataset_dev_rules1.csv

37188 dòng, 136 phiên. Luật đang áp: r401 (110011: N=12, T=120s), web_scan (110020: N=15, T=10s), any (110030: N=500, T=10s)
Alert theo rule trong dataset: {'100010': 16333, '100012': 11334, '100011': 7376, '110020': 767, '110011': 643, '100013': 323, '100014': 301, '100015': 105, '110030': 6}. Dòng không tìm thấy alert: 0.

Trễ Manager − Apache: trung vị 0.483 s, p95 1.667 s, p99 1.985 s, max 5.533 s, min 0.001 s.

| cách tính giờ | luật | phiên khớp từng dòng | phiên khớp bắt/không bắt | phiên thật bắt | phiên mô phỏng bắt | lần khớp thật | lần khớp mô phỏng |
|---|---|---|---|---|---|---|---|
| apache | r401 | 125/136 | 136/136 | 28 | 28 | 643 | 640 |
| apache | web_scan | 122/136 | 136/136 | 31 | 31 | 767 | 754 |
| apache | any | 134/136 | 134/136 | 5 | 7 | 6 | 12 |
| manager | r401 | 125/136 | 136/136 | 28 | 28 | 643 | 640 |
| manager | web_scan | 121/136 | 136/136 | 31 | 31 | 767 | 754 |
| manager | any | 132/136 | 134/136 | 5 | 7 | 6 | 12 |
| manager_sec | r401 | 125/136 | 136/136 | 28 | 28 | 643 | 640 |
| manager_sec | web_scan | 124/136 | 136/136 | 31 | 31 | 767 | 758 |
| manager_sec | any | 134/136 | 134/136 | 5 | 7 | 6 | 12 |
| joint | r401 | 125/136 | 136/136 | 28 | 28 | 643 | 640 |
| joint | web_scan | 124/136 | 136/136 | 31 | 31 | 767 | 758 |
| joint | any | 136/136 | 136/136 | 5 | 5 | 6 | 6 |

Dòng mà mô phỏng độc lập (manager_sec) cho >= 2 luật cùng khớp (Wazuh chỉ sinh 1 alert): 0
Thứ tự nạp dùng cho 'joint': r401 (110011) -> web_scan (110020) -> any (110030)

## Chỗ lệch (joint, tối đa 20 mỗi luật)

Dòng = vị trí trong phiên (0-based). span = giây giữa sự kiện cha thứ 1 và thứ N tính đến dòng đó (so với T).

- r401 · dev_rules1/test_auth_fast_000 (auth_fast, nhãn 1): chỉ thật [216, 228, 240, 252, 264] span [1.0, 1.0, 0.0, 2.0, 0.0]; chỉ mô phỏng [215, 227, 239, 251, 263] span [1.0, 1.0, 0.0, 2.0, 0.0] (T=120, N=12)
- r401 · dev_rules1/test_auth_fast_001 (auth_fast, nhãn 1): chỉ thật [142] span [1.0]; chỉ mô phỏng [143] span [1.0] (T=120, N=12)
- r401 · dev_rules1/train_auth_fast_000 (auth_fast, nhãn 1): chỉ thật [73, 84, 97, 99, 109, 121, 133, 145, 157, 169] span [0.0, 0.0, 1.0, 1.0, 0.0]; chỉ mô phỏng [83, 95, 107, 119, 131, 143, 155, 167, 179, 191] span [0.0, 1.0, 0.0, 1.0, 0.0] (T=120, N=12)
- r401 · dev_rules1/train_auth_fast_001 (auth_fast, nhãn 1): chỉ thật [121, 132, 144, 156, 168, 180, 192, 204, 216, 228] span [0.0, 0.0, 1.0, 1.0, 0.0]; chỉ mô phỏng [119, 131, 143, 155, 167, 179, 191, 203, 215, 227] span [1.0, 0.0, 1.0, 1.0, 0.0] (T=120, N=12)
- r401 · dev_rules1/train_auth_fast_002 (auth_fast, nhãn 1): chỉ thật [144] span [4.0]; chỉ mô phỏng [143] span [4.0] (T=120, N=12)
- r401 · dev_rules1/train_auth_fast_003 (auth_fast, nhãn 1): chỉ thật [481, 682, 960] span [0.0, 1.0, 1.0]; chỉ mô phỏng [479, 683, 959] span [0.0, 1.0, 1.0] (T=120, N=12)
- r401 · dev_rules1/train_recon_then_brute_000 (recon_then_brute, nhãn 1): chỉ thật [1045, 1057, 1069, 1081, 1093, 1105, 1117] span [0.0, 2.0, 0.0, 2.0, 0.0]; chỉ mô phỏng [1044, 1056, 1068, 1080, 1092, 1104, 1116] span [0.0, 2.0, 0.0, 2.0, 0.0] (T=120, N=12)
- r401 · dev_rules1/train_recon_then_brute_002 (recon_then_brute, nhãn 1): chỉ thật [269] span [0.0]; chỉ mô phỏng [267] span [2.0] (T=120, N=12)
- r401 · dev_rules1/train_recon_then_brute_003 (recon_then_brute, nhãn 1): chỉ thật [688, 700, 713, 725, 737, 749, 761, 773, 785, 797] span [4.0, 4.0, 3.0, 3.0, 2.0]; chỉ mô phỏng [699, 711, 723, 735, 747, 759, 771, 783, 795, 807] span [2.0, 2.0, 4.0, 2.0, 2.0] (T=120, N=12)
- r401 · dev_rules1/train_recon_then_brute_004 (recon_then_brute, nhãn 1): chỉ thật [1961, 1976, 1988, 2012, 2024, 2036, 2048, 2060, 2072, 2084] span [1.0, 0.0, 0.0, 0.0, 2.0]; chỉ mô phỏng [1960, 1972, 1984, 2008, 2020, 2032, 2044, 2056, 2068, 2080] span [2.0, 0.0, 0.0, 0.0, 2.0] (T=120, N=12)
- r401 · dev_rules1/val_auth_fast_000 (auth_fast, nhãn 1): chỉ thật [180, 193, 205, 217, 229, 241, 253, 265, 277, 289] span [1.0, 0.0, 1.0, 1.0, 0.0]; chỉ mô phỏng [179, 191, 203, 215, 227, 239, 251, 263, 275, 287] span [1.0, 0.0, 1.0, 0.0, 0.0] (T=120, N=12)
- web_scan · dev_rules1/test_recon_then_brute_002 (recon_then_brute, nhãn 1): chỉ thật [239, 253, 268, 284, 300, 317, 332, 348, 364, 379] span [0.0, 1.0, 0.0, 1.0, 0.0]; chỉ mô phỏng [237, 252, 267, 283, 299, 316, 331, 346, 363, 378] span [0.0, 1.0, 0.0, 1.0, 0.0] (T=10, N=15)
- web_scan · dev_rules1/test_scan_fast_000 (scan_fast, nhãn 1): chỉ thật [95, 110, 125, 140, 155, 170, 185, 201, 216, 231] span [0.0, 1.0, 0.0, 1.0, 1.0]; chỉ mô phỏng [94, 109, 124, 139, 154, 169, 184, 200, 215, 230] span [1.0, 1.0, 0.0, 1.0, 1.0] (T=10, N=15)
- web_scan · dev_rules1/test_scan_fast_001 (scan_fast, nhãn 1): chỉ thật [16, 32, 47, 62, 80, 93, 109, 124, 139, 154] span [0.0, 1.0, 0.0, 1.0, 0.0]; chỉ mô phỏng [14, 30, 45, 60, 76, 91, 107, 122, 137, 152] span [0.0, 1.0, 0.0, 1.0, 0.0] (T=10, N=15)
- web_scan · dev_rules1/test_scan_fast_002 (scan_fast, nhãn 1): chỉ thật [462, 483, 485, 497, 511, 512, 527, 542, 557, 572] span [1.0, 0.0, 0.0, 0.0, 0.0]; chỉ mô phỏng [461, 478, 494, 509, 524, 539, 554, 569, 584, 599] span [1.0, 0.0, 0.0, 0.0, 1.0] (T=10, N=15)
- web_scan · dev_rules1/test_scan_stealth_002 (scan_stealth, nhãn 1): chỉ thật [272] span [11.0]; chỉ mô phỏng [286] span [10.0] (T=10, N=15)
- web_scan · dev_rules1/train_recon_then_brute_000 (recon_then_brute, nhãn 1): chỉ thật [31, 46, 61, 62, 74, 93, 108, 125, 140, 156] span [0.0, 0.0, 1.0, 1.0, 0.0]; chỉ mô phỏng [30, 45, 60, 75, 90, 105, 122, 137, 153, 168] span [1.0, 0.0, 1.0, 0.0, 0.0] (T=10, N=15)
- web_scan · dev_rules1/train_recon_then_brute_003 (recon_then_brute, nhãn 1): chỉ thật [32, 46, 61, 77, 92, 107, 122, 137, 152, 167] span [1.0, 2.0, 2.0, 1.0, 2.0]; chỉ mô phỏng [30, 45, 60, 75, 91, 106, 121, 136, 151, 166] span [1.0, 2.0, 2.0, 1.0, 2.0] (T=10, N=15)
- web_scan · dev_rules1/train_recon_then_brute_004 (recon_then_brute, nhãn 1): chỉ thật [161, 177, 184, 196, 221, 237, 238, 250, 266, 281] span [2.0, 0.0, 0.0, 0.0, 0.0]; chỉ mô phỏng [157, 172, 187, 202, 217, 232, 247, 263, 278, 293] span [2.0, 0.0, 0.0, 0.0, 0.0] (T=10, N=15)
- web_scan · dev_rules1/train_scan_fast_003 (scan_fast, nhãn 1): chỉ thật [63, 78, 98, 114, 130, 145, 160, 175, 190, 206] span [1.0, 1.0, 1.0, 1.0, 1.0]; chỉ mô phỏng [62, 77, 97, 113, 129, 144, 159, 174, 189, 205] span [1.0, 1.0, 1.0, 1.0, 1.0] (T=10, N=15)
- web_scan · dev_rules1/val_recon_then_brute_001 (recon_then_brute, nhãn 1): chỉ thật [135] span [2.0]; chỉ mô phỏng [134] span [2.0] (T=10, N=15)
- web_scan · dev_rules1/val_scan_fast_000 (scan_fast, nhãn 1): chỉ thật [92, 108, 123, 138, 153, 168] span [1.0, 4.0, 2.0, 3.0, 1.0]; chỉ mô phỏng [91, 107, 122, 137, 152, 167] span [1.0, 3.0, 2.0, 3.0, 2.0] (T=10, N=15)
- web_scan · dev_rules1/val_scan_stealth_001 (scan_stealth, nhãn 1): chỉ thật [55] span [11.0]; chỉ mô phỏng [] span [] (T=10, N=15)
