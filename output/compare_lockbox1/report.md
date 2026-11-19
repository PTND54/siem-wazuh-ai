# Luật thật so với mô phỏng — dataset_lockbox1.csv

154025 dòng, 468 phiên. Luật đang áp: r401 (110011: N=12, T=120s), web_scan (110020: N=15, T=10s), any (110030: N=500, T=10s)
Alert theo rule trong dataset: {'100010': 77294, '100012': 46933, '100011': 21761, '110020': 3188, '110011': 1877, '100013': 1265, '100014': 1187, '100015': 430, '110030': 90}. Dòng không tìm thấy alert: 0.

Trễ Manager − Apache: trung vị 1.076 s, p95 1.909 s, p99 1.983 s, max 2.011 s, min 0.007 s.

| cách tính giờ | luật | phiên khớp từng dòng | phiên khớp bắt/không bắt | phiên thật bắt | phiên mô phỏng bắt | lần khớp thật | lần khớp mô phỏng |
|---|---|---|---|---|---|---|---|
| apache | r401 | 420/468 | 468/468 | 103 | 103 | 1877 | 1874 |
| apache | web_scan | 408/468 | 465/468 | 102 | 99 | 3188 | 3132 |
| apache | any | 442/468 | 453/468 | 31 | 30 | 90 | 62 |
| manager | r401 | 420/468 | 468/468 | 103 | 103 | 1877 | 1874 |
| manager | web_scan | 408/468 | 465/468 | 102 | 99 | 3188 | 3133 |
| manager | any | 437/468 | 453/468 | 31 | 32 | 90 | 64 |
| manager_sec | r401 | 420/468 | 468/468 | 103 | 103 | 1877 | 1874 |
| manager_sec | web_scan | 414/468 | 467/468 | 102 | 101 | 3188 | 3143 |
| manager_sec | any | 440/468 | 455/468 | 31 | 40 | 90 | 82 |
| joint | r401 | 420/468 | 468/468 | 103 | 103 | 1877 | 1874 |
| joint | web_scan | 414/468 | 467/468 | 102 | 101 | 3188 | 3143 |
| joint | any | 451/468 | 466/468 | 31 | 29 | 90 | 56 |

Dòng mà mô phỏng độc lập (manager_sec) cho >= 2 luật cùng khớp (Wazuh chỉ sinh 1 alert): 1
Thứ tự nạp dùng cho 'joint': r401 (110011) -> web_scan (110020) -> any (110030)

## Chỗ lệch (joint, tối đa 20 mỗi luật)

Dòng = vị trí trong phiên (0-based). span = giây giữa sự kiện cha thứ 1 và thứ N tính đến dòng đó (so với T).

- r401 · lockbox1/lockbox_auth_fast_000 (auth_fast, nhãn 1): chỉ thật [12, 24, 36, 48, 60, 72, 84, 96, 108, 120] span [0.0, 2.0, 0.0, 1.0, 1.0]; chỉ mô phỏng [11, 23, 35, 47, 59, 71, 83, 95, 107, 119] span [1.0, 1.0, 0.0, 2.0, 1.0] (T=120, N=12)
- r401 · lockbox1/lockbox_auth_fast_001 (auth_fast, nhãn 1): chỉ thật [110, 121, 253, 266, 276, 290, 302, 314, 326, 338] span [0.0, 0.0, 2.0, 0.0, 0.0]; chỉ mô phỏng [107, 119, 251, 263, 275, 287, 299, 311, 323, 335] span [0.0, 0.0, 2.0, 0.0, 0.0] (T=120, N=12)
- r401 · lockbox1/lockbox_auth_fast_002 (auth_fast, nhãn 1): chỉ thật [36, 48, 60, 72] span [2.0, 5.0, 1.0, 3.0]; chỉ mô phỏng [35, 47, 59, 71] span [3.0, 4.0, 2.0, 2.0] (T=120, N=12)
- r401 · lockbox1/lockbox_auth_fast_003 (auth_fast, nhãn 1): chỉ thật [132] span [2.0]; chỉ mô phỏng [131] span [2.0] (T=120, N=12)
- r401 · lockbox1/lockbox_auth_fast_004 (auth_fast, nhãn 1): chỉ thật [13, 14, 25, 37, 49, 61, 73, 85, 98, 109] span [2.0, 2.0, 2.0, 0.0, 2.0]; chỉ mô phỏng [11, 23, 35, 47, 59, 71, 83, 95, 107, 119] span [2.0, 0.0, 0.0, 2.0, 2.0] (T=120, N=12)
- r401 · lockbox1/lockbox_auth_fast_005 (auth_fast, nhãn 1): chỉ thật [106, 132, 144, 156, 168, 180, 192, 204, 216] span [1.0, 0.0, 1.0, 1.0, 0.0]; chỉ mô phỏng [107, 131, 143, 155, 167, 179, 191, 203, 215] span [1.0, 0.0, 1.0, 1.0, 0.0] (T=120, N=12)
- r401 · lockbox1/lockbox_auth_fast_009 (auth_fast, nhãn 1): chỉ thật [120, 252, 264, 276, 288, 300, 312, 324, 336, 348] span [0.0, 1.0, 1.0, 1.0, 2.0]; chỉ mô phỏng [119, 251, 263, 275, 287, 299, 311, 323, 335, 347] span [1.0, 1.0, 1.0, 1.0, 2.0] (T=120, N=12)
- r401 · lockbox1/lockbox_auth_fast_011 (auth_fast, nhãn 1): chỉ thật [146, 156, 168, 180] span [1.0, 2.0, 4.0, 1.0]; chỉ mô phỏng [143, 155, 167, 179] span [2.0, 2.0, 3.0, 1.0] (T=120, N=12)
- r401 · lockbox1/lockbox_auth_fast_013 (auth_fast, nhãn 1): chỉ thật [170, 185, 197, 210, 221, 233, 245, 257, 269, 281] span [2.0, 0.0, 0.0, 0.0, 2.0]; chỉ mô phỏng [167, 179, 191, 203, 215, 227, 239, 251, 263, 275] span [2.0, 0.0, 0.0, 0.0, 0.0] (T=120, N=12)
- r401 · lockbox1/lockbox_auth_fast_014 (auth_fast, nhãn 1): chỉ thật [156, 169, 180, 192] span [1.0, 1.0, 0.0, 0.0]; chỉ mô phỏng [155, 167, 179, 191] span [1.0, 1.0, 0.0, 1.0] (T=120, N=12)
- r401 · lockbox1/lockbox_auth_fast_017 (auth_fast, nhãn 1): chỉ thật [132, 144, 156, 168, 180, 192, 204, 216, 228, 240] span [1.0, 1.0, 1.0, 1.0, 0.0]; chỉ mô phỏng [131, 143, 155, 167, 179, 191, 203, 215, 227, 239] span [1.0, 1.0, 1.0, 1.0, 0.0] (T=120, N=12)
- r401 · lockbox1/lockbox_auth_fast_018 (auth_fast, nhãn 1): chỉ thật [372, 384, 396, 408, 420, 432, 444, 456, 468, 480] span [1.0, 0.0, 2.0, 0.0, 1.0]; chỉ mô phỏng [371, 383, 395, 407, 419, 431, 443, 455, 467, 479] span [1.0, 0.0, 1.0, 0.0, 1.0] (T=120, N=12)
- r401 · lockbox1/lockbox_auth_fast_019 (auth_fast, nhãn 1): chỉ thật [109, 121, 134, 146, 158, 170, 182, 194, 206] span [0.0, 1.0, 1.0, 0.0, 1.0]; chỉ mô phỏng [107, 119, 131, 143, 155, 167, 179, 191, 203] span [0.0, 1.0, 0.0, 1.0, 0.0] (T=120, N=12)
- r401 · lockbox1/lockbox_auth_fast_020 (auth_fast, nhãn 1): chỉ thật [51, 62, 77, 87, 99, 111, 124, 136, 148, 160] span [2.0, 0.0, 0.0, 0.0, 0.0]; chỉ mô phỏng [47, 59, 71, 83, 95, 107, 119, 131, 143, 155] span [1.0, 1.0, 0.0, 0.0, 0.0] (T=120, N=12)
- r401 · lockbox1/lockbox_auth_fast_022 (auth_fast, nhãn 1): chỉ thật [96, 108, 120, 133, 144, 156, 168, 180, 204, 216] span [2.0, 2.0, 2.0, 4.0, 2.0]; chỉ mô phỏng [95, 107, 119, 131, 143, 155, 167, 179, 203, 215] span [0.0, 2.0, 2.0, 4.0, 0.0] (T=120, N=12)
- r401 · lockbox1/lockbox_auth_fast_023 (auth_fast, nhãn 1): chỉ thật [252] span [1.0]; chỉ mô phỏng [251] span [1.0] (T=120, N=12)
- r401 · lockbox1/lockbox_auth_fast_024 (auth_fast, nhãn 1): chỉ thật [12, 156] span [2.0, 2.0]; chỉ mô phỏng [11, 155] span [4.0, 2.0] (T=120, N=12)
- r401 · lockbox1/lockbox_auth_fast_025 (auth_fast, nhãn 1): chỉ thật [204, 216, 232, 243, 254, 266, 278, 290, 302, 314] span [1.0, 0.0, 1.0, 0.0, 1.0]; chỉ mô phỏng [203, 227, 239, 251, 263, 275, 287, 299, 311, 323] span [1.0, 1.0, 0.0, 1.0, 0.0] (T=120, N=12)
- r401 · lockbox1/lockbox_auth_fast_026 (auth_fast, nhãn 1): chỉ thật [36, 48, 60, 72, 84, 96, 108] span [2.0, 2.0, 0.0, 2.0, 2.0]; chỉ mô phỏng [35, 47, 59, 71, 83, 95, 107] span [2.0, 2.0, 0.0, 2.0, 2.0] (T=120, N=12)
- r401 · lockbox1/lockbox_auth_fast_027 (auth_fast, nhãn 1): chỉ thật [50, 61, 70, 193, 204, 216, 228, 240, 252, 264] span [1.0, 0.0, 0.0, 0.0, 2.0]; chỉ mô phỏng [47, 59, 71, 191, 203, 215, 227, 239, 251, 263] span [2.0, 0.0, 0.0, 0.0, 2.0] (T=120, N=12)
- web_scan · lockbox1/lockbox_broken_links_001 (broken_links, nhãn 0): chỉ thật [97, 121, 148] span [11.0, 11.0, 10.0]; chỉ mô phỏng [100, 142] span [10.0, 9.0] (T=10, N=15)
- web_scan · lockbox1/lockbox_broken_links_008 (broken_links, nhãn 0): chỉ thật [39, 54, 77, 97, 116, 141, 163, 180, 205, 225] span [7.0, 6.0, 9.0, 6.0, 5.0]; chỉ mô phỏng [38, 53, 75, 96, 115, 139, 160, 179, 201, 223] span [7.0, 4.0, 9.0, 8.0, 7.0] (T=10, N=15)
- web_scan · lockbox1/lockbox_broken_links_010 (broken_links, nhãn 0): chỉ thật [88] span [11.0]; chỉ mô phỏng [] span [] (T=10, N=15)
- web_scan · lockbox1/lockbox_broken_links_012 (broken_links, nhãn 0): chỉ thật [263, 282] span [11.0, 8.0]; chỉ mô phỏng [265, 284] span [9.0, 7.0] (T=10, N=15)
- web_scan · lockbox1/lockbox_recon_then_brute_000 (recon_then_brute, nhãn 1): chỉ thật [189, 205, 221, 237, 252, 269, 284, 299, 314, 329] span [0.0, 1.0, 1.0, 0.0, 0.0]; chỉ mô phỏng [186, 204, 219, 236, 251, 268, 283, 298, 313, 328] span [0.0, 1.0, 0.0, 0.0, 0.0] (T=10, N=15)
- web_scan · lockbox1/lockbox_recon_then_brute_002 (recon_then_brute, nhãn 1): chỉ thật [122, 137, 152, 167, 182, 197, 212, 228, 243, 258] span [2.0, 2.0, 2.0, 2.0, 4.0]; chỉ mô phỏng [121, 136, 151, 166, 181, 196, 211, 227, 242, 257] span [2.0, 2.0, 4.0, 2.0, 4.0] (T=10, N=15)
- web_scan · lockbox1/lockbox_recon_then_brute_005 (recon_then_brute, nhãn 1): chỉ thật [218, 239, 253, 272, 285, 298, 314, 329, 344, 359] span [0.0, 0.0, 0.0, 0.0, 0.0]; chỉ mô phỏng [219, 234, 249, 266, 281, 296, 311, 327, 342, 357] span [0.0, 1.0, 0.0, 0.0, 0.0] (T=10, N=15)
- web_scan · lockbox1/lockbox_recon_then_brute_006 (recon_then_brute, nhãn 1): chỉ thật [145, 161, 177, 190, 225, 240, 255, 270, 286, 301] span [2.0, 0.0, 0.0, 0.0, 0.0]; chỉ mô phỏng [159, 174, 189, 222, 237, 252, 267, 283, 298, 313] span [0.0, 0.0, 0.0, 0.0, 1.0] (T=10, N=15)
- web_scan · lockbox1/lockbox_recon_then_brute_007 (recon_then_brute, nhãn 1): chỉ thật [387, 388, 398, 415, 432, 450, 469, 481, 485, 496] span [0.0, 0.0, 0.0, 0.0, 0.0]; chỉ mô phỏng [384, 399, 414, 430, 445, 461, 476, 491, 506, 521] span [1.0, 0.0, 0.0, 0.0, 1.0] (T=10, N=15)
- web_scan · lockbox1/lockbox_recon_then_brute_008 (recon_then_brute, nhãn 1): chỉ thật [64, 81, 97, 112, 127, 143, 158, 173, 188, 204] span [1.0, 0.0, 1.0, 0.0, 1.0]; chỉ mô phỏng [79, 95, 110, 125, 141, 156, 171, 186, 202, 217] span [0.0, 1.0, 0.0, 1.0, 0.0] (T=10, N=15)
- web_scan · lockbox1/lockbox_recon_then_brute_009 (recon_then_brute, nhãn 1): chỉ thật [124, 311, 325, 342, 358, 373, 388, 403, 418, 434] span [1.0, 1.0, 1.0, 1.0, 1.0]; chỉ mô phỏng [123, 309, 324, 341, 357, 372, 387, 402, 417, 433] span [1.0, 1.0, 1.0, 1.0, 1.0] (T=10, N=15)
- web_scan · lockbox1/lockbox_recon_then_brute_010 (recon_then_brute, nhãn 1): chỉ thật [46, 276] span [2.0, 2.0]; chỉ mô phỏng [45, 274] span [2.0, 2.0] (T=10, N=15)
- web_scan · lockbox1/lockbox_recon_then_brute_011 (recon_then_brute, nhãn 1): chỉ thật [302, 318, 333, 348, 363, 378, 393, 410, 426, 441] span [1.0, 1.0, 0.0, 0.0, 0.0]; chỉ mô phỏng [317, 332, 347, 362, 377, 392, 409, 425, 440, 455] span [1.0, 0.0, 0.0, 0.0, 0.0] (T=10, N=15)
- web_scan · lockbox1/lockbox_recon_then_brute_014 (recon_then_brute, nhãn 1): chỉ thật [20, 31, 49, 65, 80, 95, 111, 126, 142, 157] span [0.0, 0.0, 1.0, 1.0, 0.0]; chỉ mô phỏng [15, 30, 46, 62, 77, 92, 108, 123, 139, 154] span [1.0, 0.0, 1.0, 1.0, 0.0] (T=10, N=15)
- web_scan · lockbox1/lockbox_recon_then_brute_015 (recon_then_brute, nhãn 1): chỉ thật [136, 168, 183, 199, 215, 231, 245, 246, 262, 277] span [1.0, 0.0, 0.0, 0.0, 0.0]; chỉ mô phỏng [137, 167, 182, 198, 213, 228, 243, 259, 274, 289] span [1.0, 0.0, 0.0, 0.0, 0.0] (T=10, N=15)
- web_scan · lockbox1/lockbox_recon_then_brute_016 (recon_then_brute, nhãn 1): chỉ thật [332, 347, 363, 378, 393, 408, 424, 439, 454, 469] span [0.0, 0.0, 0.0, 1.0, 1.0]; chỉ mô phỏng [346, 362, 377, 392, 407, 423, 438, 453, 468, 483] span [0.0, 0.0, 1.0, 1.0, 0.0] (T=10, N=15)
- web_scan · lockbox1/lockbox_recon_then_brute_018 (recon_then_brute, nhãn 1): chỉ thật [243, 258, 289, 304, 319, 334, 349, 366, 381, 396] span [1.0, 1.0, 1.0, 1.0, 0.0]; chỉ mô phỏng [257, 288, 303, 318, 333, 348, 365, 380, 395, 410] span [1.0, 1.0, 1.0, 0.0, 1.0] (T=10, N=15)
- web_scan · lockbox1/lockbox_recon_then_brute_020 (recon_then_brute, nhãn 1): chỉ thật [30, 197, 212, 227, 243, 256, 277, 292, 307, 323] span [2.0, 2.0, 0.0, 0.0, 2.0]; chỉ mô phỏng [29, 196, 211, 226, 242, 257, 273, 288, 303, 319] span [2.0, 2.0, 0.0, 0.0, 2.0] (T=10, N=15)
- web_scan · lockbox1/lockbox_recon_then_brute_021 (recon_then_brute, nhãn 1): chỉ thật [15, 32, 47, 62, 78, 93, 108, 124, 139, 154] span [0.0, 2.0, 0.0, 0.0, 0.0]; chỉ mô phỏng [31, 46, 61, 77, 92, 107, 123, 138, 153, 168] span [2.0, 0.0, 0.0, 0.0, 0.0] (T=10, N=15)
- web_scan · lockbox1/lockbox_recon_then_brute_022 (recon_then_brute, nhãn 1): chỉ thật [77, 95, 109, 125, 140, 155, 171, 187, 202, 217] span [0.0, 0.0, 2.0, 0.0, 0.0]; chỉ mô phỏng [76, 93, 108, 124, 139, 154, 169, 185, 201, 216] span [0.0, 0.0, 2.0, 0.0, 0.0] (T=10, N=15)
- any · lockbox1/lockbox_flood_000 (flood, nhãn 1): chỉ thật [503, 504, 505, 506, 507, 508, 509, 510, 511, 1011] span [5.0, 5.0, 5.0, 5.0, 5.0]; chỉ mô phỏng [499, 999, 1499] span [5.0, 6.0, 5.0] (T=10, N=500)
- any · lockbox1/lockbox_flood_001 (flood, nhãn 1): chỉ thật [1004, 1007] span [6.0, 6.0]; chỉ mô phỏng [999] span [6.0] (T=10, N=500)
- any · lockbox1/lockbox_flood_002 (flood, nhãn 1): chỉ thật [497, 500, 502, 503] span [None, 9.0, 9.0, 9.0]; chỉ mô phỏng [499] span [9.0] (T=10, N=500)
- any · lockbox1/lockbox_flood_003 (flood, nhãn 1): chỉ thật [998, 1001, 1002, 1003] span [7.0, 7.0, 7.0, 7.0]; chỉ mô phỏng [999] span [7.0] (T=10, N=500)
- any · lockbox1/lockbox_flood_004 (flood, nhãn 1): chỉ thật [552, 553] span [11.0, 11.0]; chỉ mô phỏng [] span [] (T=10, N=500)
- any · lockbox1/lockbox_flood_005 (flood, nhãn 1): chỉ thật [499] span [11.0]; chỉ mô phỏng [515] span [10.0] (T=10, N=500)
- any · lockbox1/lockbox_flood_007 (flood, nhãn 1): chỉ thật [500, 501, 502, 506, 507, 1004] span [6.0, 6.0, 6.0, 6.0, 6.0]; chỉ mô phỏng [499, 999] span [6.0, 6.0] (T=10, N=500)
- any · lockbox1/lockbox_flood_008 (flood, nhãn 1): chỉ thật [498, 1506, 1507, 1509] span [None, 4.0, 4.0, 4.0]; chỉ mô phỏng [499, 1499] span [5.0, 5.0] (T=10, N=500)
- any · lockbox1/lockbox_flood_009 (flood, nhãn 1): chỉ thật [1000, 1500] span [4.0, 5.0]; chỉ mô phỏng [1499] span [6.0] (T=10, N=500)
- any · lockbox1/lockbox_flood_010 (flood, nhãn 1): chỉ thật [1501] span [5.0]; chỉ mô phỏng [1499] span [5.0] (T=10, N=500)
- any · lockbox1/lockbox_flood_012 (flood, nhãn 1): chỉ thật [525] span [11.0]; chỉ mô phỏng [] span [] (T=10, N=500)
- any · lockbox1/lockbox_flood_016 (flood, nhãn 1): chỉ thật [502, 504, 1001] span [7.0, 7.0, 7.0]; chỉ mô phỏng [499, 999] span [7.0, 7.0] (T=10, N=500)
- any · lockbox1/lockbox_flood_017 (flood, nhãn 1): chỉ thật [506, 507, 508, 509, 510, 511, 512, 1012] span [7.0, 7.0, 7.0, 7.0, 7.0]; chỉ mô phỏng [499, 999] span [7.0, 7.0] (T=10, N=500)
- any · lockbox1/lockbox_flood_022 (flood, nhãn 1): chỉ thật [499] span [11.0]; chỉ mô phỏng [588] span [10.0] (T=10, N=500)
- any · lockbox1/lockbox_heavy_burst_009 (heavy_burst, nhãn 0): chỉ thật [1070, 1594] span [11.0, 11.0]; chỉ mô phỏng [] span [] (T=10, N=500)
- any · lockbox1/lockbox_heavy_burst_018 (heavy_burst, nhãn 0): chỉ thật [1000] span [8.0]; chỉ mô phỏng [999] span [8.0] (T=10, N=500)
- any · lockbox1/lockbox_heavy_burst_026 (heavy_burst, nhãn 0): chỉ thật [999, 1515] span [11.0, 10.0]; chỉ mô phỏng [1043, 1543] span [10.0, 10.0] (T=10, N=500)
