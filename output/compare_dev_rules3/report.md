# Luật thật so với mô phỏng — dataset_dev_rules3.csv

47836 dòng, 154 phiên. Luật đang áp: r401 (110011: N=12, T=120s), web_scan (110020: N=15, T=10s), any (110030: N=600, T=10s)
Alert theo rule trong dataset: {'100010': 20735, '100012': 15289, '100011': 9004, '110020': 1049, '110011': 786, '100013': 438, '100014': 420, '100015': 108, '110030': 7}. Dòng không tìm thấy alert: 0.

Trễ Manager − Apache: trung vị 0.355 s, p95 0.737 s, p99 0.796 s, max 0.831 s, min 0.004 s.

| cách tính giờ | luật | phiên khớp từng dòng | phiên khớp bắt/không bắt | phiên thật bắt | phiên mô phỏng bắt | lần khớp thật | lần khớp mô phỏng |
|---|---|---|---|---|---|---|---|
| apache | r401 | 143/154 | 154/154 | 33 | 33 | 786 | 785 |
| apache | web_scan | 136/154 | 154/154 | 38 | 38 | 1049 | 1035 |
| apache | any | 149/154 | 150/154 | 6 | 6 | 7 | 8 |
| manager | r401 | 143/154 | 154/154 | 33 | 33 | 786 | 785 |
| manager | web_scan | 136/154 | 154/154 | 38 | 38 | 1049 | 1035 |
| manager | any | 149/154 | 150/154 | 6 | 6 | 7 | 8 |
| manager_sec | r401 | 143/154 | 154/154 | 33 | 33 | 786 | 785 |
| manager_sec | web_scan | 136/154 | 154/154 | 38 | 38 | 1049 | 1039 |
| manager_sec | any | 149/154 | 151/154 | 6 | 7 | 7 | 10 |
| joint | r401 | 143/154 | 154/154 | 33 | 33 | 786 | 785 |
| joint | web_scan | 136/154 | 154/154 | 38 | 38 | 1049 | 1039 |
| joint | any | 151/154 | 153/154 | 6 | 5 | 7 | 6 |

Dòng mà mô phỏng độc lập (manager_sec) cho >= 2 luật cùng khớp (Wazuh chỉ sinh 1 alert): 1
Thứ tự nạp dùng cho 'joint': r401 (110011) -> web_scan (110020) -> any (110030)

## Chỗ lệch (joint, tối đa 20 mỗi luật)

Dòng = vị trí trong phiên (0-based). span = giây giữa sự kiện cha thứ 1 và thứ N tính đến dòng đó (so với T).

- r401 · dev_rules3/test_recon_then_brute_002 (recon_then_brute, nhãn 1): chỉ thật [1582, 1594, 1606] span [1.0, 2.0, 2.0]; chỉ mô phỏng [1581, 1593, 1605] span [2.0, 2.0, 2.0] (T=120, N=12)
- r401 · dev_rules3/train_auth_fast_000 (auth_fast, nhãn 1): chỉ thật [300] span [0.0]; chỉ mô phỏng [299] span [0.0] (T=120, N=12)
- r401 · dev_rules3/train_auth_fast_001 (auth_fast, nhãn 1): chỉ thật [72, 120, 132, 144, 156, 168, 180, 192, 204, 216] span [1.0, 0.0, 1.0, 1.0, 0.0]; chỉ mô phỏng [71, 119, 131, 143, 155, 167, 179, 191, 203, 215] span [1.0, 0.0, 1.0, 1.0, 0.0] (T=120, N=12)
- r401 · dev_rules3/train_auth_fast_003 (auth_fast, nhãn 1): chỉ thật [25, 39, 50, 62, 74, 86, 98, 110, 122, 134] span [0.0, 0.0, 1.0, 0.0, 0.0]; chỉ mô phỏng [23, 35, 47, 59, 71, 83, 95, 107, 119, 131] span [1.0, 0.0, 0.0, 1.0, 0.0] (T=120, N=12)
- r401 · dev_rules3/train_auth_slow_004 (auth_slow, nhãn 1): chỉ thật [166, 179] span [9.0, 9.0]; chỉ mô phỏng [165, 178] span [8.0, 11.0] (T=120, N=12)
- r401 · dev_rules3/train_recon_then_brute_000 (recon_then_brute, nhãn 1): chỉ thật [1006] span [1.0]; chỉ mô phỏng [1008] span [1.0] (T=120, N=12)
- r401 · dev_rules3/train_recon_then_brute_001 (recon_then_brute, nhãn 1): chỉ thật [213, 241, 253, 265, 277, 289, 301, 313, 325, 337] span [1.0, 0.0, 1.0, 0.0, 1.0]; chỉ mô phỏng [216, 240, 252, 264, 276, 288, 300, 312, 324, 336] span [1.0, 0.0, 1.0, 0.0, 1.0] (T=120, N=12)
- r401 · dev_rules3/train_recon_then_brute_003 (recon_then_brute, nhãn 1): chỉ thật [821, 833] span [2.0, 3.0]; chỉ mô phỏng [819, 831] span [3.0, 2.0] (T=120, N=12)
- r401 · dev_rules3/train_recon_then_brute_004 (recon_then_brute, nhãn 1): chỉ thật [1889, 1903, 1914, 1926, 1938, 1950, 1962, 1974, 1986, 1998] span [1.0, 0.0, 0.0, 1.0, 0.0]; chỉ mô phỏng [1888, 1900, 1912, 1924, 1936, 1948, 1960, 1972, 1984, 1996] span [1.0, 0.0, 0.0, 0.0, 1.0] (T=120, N=12)
- r401 · dev_rules3/val_auth_fast_000 (auth_fast, nhãn 1): chỉ thật [288, 300, 312, 325, 336, 348, 360, 372, 384, 396] span [1.0, 0.0, 1.0, 1.0, 0.0]; chỉ mô phỏng [287, 299, 311, 323, 335, 347, 359, 371, 383, 395] span [1.0, 0.0, 1.0, 1.0, 0.0] (T=120, N=12)
- r401 · dev_rules3/val_recon_then_brute_000 (recon_then_brute, nhãn 1): chỉ thật [404, 416, 428, 440, 452, 464, 476, 488, 500, 512] span [0.0, 1.0, 0.0, 1.0, 0.0]; chỉ mô phỏng [415, 427, 439, 451, 463, 475, 487, 499, 511, 523] span [0.0, 0.0, 1.0, 0.0, 0.0] (T=120, N=12)
- web_scan · dev_rules3/test_recon_then_brute_000 (recon_then_brute, nhãn 1): chỉ thật [315, 330, 345, 361, 379, 396, 411, 429, 444, 459] span [0.0, 1.0, 0.0, 1.0, 0.0]; chỉ mô phỏng [314, 329, 344, 360, 378, 395, 410, 428, 443, 458] span [0.0, 1.0, 0.0, 1.0, 0.0] (T=10, N=15)
- web_scan · dev_rules3/test_recon_then_brute_001 (recon_then_brute, nhãn 1): chỉ thật [31, 434, 451, 466, 482, 499, 515, 530, 545, 560] span [0.0, 1.0, 0.0, 0.0, 1.0]; chỉ mô phỏng [29, 433, 448, 464, 480, 497, 513, 528, 543, 558] span [0.0, 1.0, 0.0, 0.0, 1.0] (T=10, N=15)
- web_scan · dev_rules3/test_recon_then_brute_002 (recon_then_brute, nhãn 1): chỉ thật [156, 473, 503, 518, 534, 550, 565, 580, 598, 613] span [0.0, 1.0, 0.0, 1.0, 1.0]; chỉ mô phỏng [158, 471, 502, 517, 532, 548, 563, 578, 595, 611] span [0.0, 1.0, 0.0, 1.0, 1.0] (T=10, N=15)
- web_scan · dev_rules3/test_scan_fast_000 (scan_fast, nhãn 1): chỉ thật [35, 48, 63, 80, 95, 110, 125, 140, 155, 170] span [0.0, 0.0, 1.0, 1.0, 0.0]; chỉ mô phỏng [32, 47, 62, 79, 94, 109, 124, 139, 154, 169] span [1.0, 0.0, 1.0, 1.0, 0.0] (T=10, N=15)
- web_scan · dev_rules3/test_scan_fast_001 (scan_fast, nhãn 1): chỉ thật [324, 537, 553, 569, 584, 600, 615, 630, 646, 665] span [0.0, 0.0, 1.0, 0.0, 1.0]; chỉ mô phỏng [325, 536, 551, 568, 583, 599, 614, 629, 645, 660] span [0.0, 0.0, 1.0, 0.0, 1.0] (T=10, N=15)
- web_scan · dev_rules3/test_scan_fast_002 (scan_fast, nhãn 1): chỉ thật [354, 768, 938, 954, 971, 985, 1001, 1016, 1031, 1047] span [0.0, 1.0, 1.0, 0.0, 0.0]; chỉ mô phỏng [353, 767, 952, 967, 983, 998, 1013, 1028, 1044, 1060] span [0.0, 1.0, 0.0, 0.0, 0.0] (T=10, N=15)
- web_scan · dev_rules3/test_scan_stealth_002 (scan_stealth, nhãn 1): chỉ thật [103] span [11.0]; chỉ mô phỏng [117] span [10.0] (T=10, N=15)
- web_scan · dev_rules3/train_broken_links_000 (broken_links, nhãn 0): chỉ thật [186] span [11.0]; chỉ mô phỏng [199] span [10.0] (T=10, N=15)
- web_scan · dev_rules3/train_broken_links_002 (broken_links, nhãn 0): chỉ thật [20, 43, 99, 118] span [11.0, 11.0, 11.0, 10.0]; chỉ mô phỏng [34, 106, 125] span [10.0, 10.0, 10.0] (T=10, N=15)
- web_scan · dev_rules3/train_recon_then_brute_000 (recon_then_brute, nhãn 1): chỉ thật [355, 695, 710, 725, 741, 757, 772, 787, 804, 820] span [0.0, 1.0, 0.0, 1.0, 0.0]; chỉ mô phỏng [356, 694, 709, 724, 740, 756, 771, 786, 802, 819] span [0.0, 1.0, 0.0, 1.0, 0.0] (T=10, N=15)
- web_scan · dev_rules3/train_recon_then_brute_003 (recon_then_brute, nhãn 1): chỉ thật [488, 562, 579, 594, 609, 624, 640, 656] span [2.0, 2.0, 1.0, 1.0, 2.0]; chỉ mô phỏng [487, 563, 578, 593, 608, 623, 639, 655] span [2.0, 1.0, 1.0, 1.0, 2.0] (T=10, N=15)
- web_scan · dev_rules3/train_recon_then_brute_004 (recon_then_brute, nhãn 1): chỉ thật [259, 279, 281, 296, 313, 329, 344, 359, 375, 391] span [1.0, 0.0, 0.0, 0.0, 0.0]; chỉ mô phỏng [263, 278, 293, 308, 324, 339, 354, 370, 386, 401] span [1.0, 0.0, 0.0, 0.0, 0.0] (T=10, N=15)
- web_scan · dev_rules3/train_scan_pulsed_003 (scan_pulsed, nhãn 1): chỉ thật [16] span [1.0]; chỉ mô phỏng [14] span [2.0] (T=10, N=15)
- web_scan · dev_rules3/train_scan_stealth_001 (scan_stealth, nhãn 1): chỉ thật [144, 162, 179, 203, 222, 242, 263, 283, 304] span [11.0, 8.0, 6.0, 10.0, 8.0]; chỉ mô phỏng [150, 169, 195, 212, 231, 251, 273, 290] span [10.0, 8.0, 10.0, 6.0, 9.0] (T=10, N=15)
- web_scan · dev_rules3/val_scan_fast_000 (scan_fast, nhãn 1): chỉ thật [31, 92, 108, 123, 138, 153, 168] span [3.0, 2.0, 3.0, 2.0, 3.0]; chỉ mô phỏng [30, 91, 107, 122, 137, 152, 167] span [4.0, 2.0, 3.0, 3.0, 3.0] (T=10, N=15)
- web_scan · dev_rules3/val_scan_fast_001 (scan_fast, nhãn 1): chỉ thật [31] span [2.0]; chỉ mô phỏng [30] span [2.0] (T=10, N=15)
- web_scan · dev_rules3/val_scan_stealth_000 (scan_stealth, nhãn 1): chỉ thật [125, 141, 161, 180] span [11.0, 7.0, 6.0, 5.0]; chỉ mô phỏng [126, 142, 162, 181] span [9.0, 7.0, 5.0, 6.0] (T=10, N=15)
- web_scan · dev_rules3/val_scan_stealth_001 (scan_stealth, nhãn 1): chỉ thật [54] span [11.0]; chỉ mô phỏng [] span [] (T=10, N=15)
- any · dev_rules3/test_flood_000 (flood, nhãn 1): chỉ thật [599] span [11.0]; chỉ mô phỏng [] span [] (T=10, N=600)
- any · dev_rules3/test_flood_002 (flood, nhãn 1): chỉ thật [600] span [10.0]; chỉ mô phỏng [599] span [10.0] (T=10, N=600)
- any · dev_rules3/val_flood_000 (flood, nhãn 1): chỉ thật [599] span [11.0]; chỉ mô phỏng [664] span [10.0] (T=10, N=600)
