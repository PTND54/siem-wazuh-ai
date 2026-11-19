#!/usr/bin/env python3
"""Kiểm wazuh_sim.freq_fires trên ĐÚNG 5 ca đã đo bằng scripts/wazuh_probe.py trên Wazuh 4.14.7 thật (22/10/2026,
frequency=3, timeframe=8; output/wazuh_probe_20261022-210432.json). Mỗi ca: chuỗi (giây, IP, URL) và vị trí luật khớp.
  python3 tests/test_wazuh_sim.py"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
from wazuh_sim import freq_fires

fails = []
def check(c, m):
    if not c: fails.append(m); print("  LỖI:", m)

def run(evs, N=3, T=8, du=False):
    """evs: list (t, ip, url) -> chỉ số (1-based) các sự kiện luật khớp; mô phỏng same_srcip bằng cách tách theo IP."""
    fired = set()
    for ip in {e[1] for e in evs}:
        idx = [k for k, e in enumerate(evs) if e[1] == ip]
        f = freq_fires([evs[k][0] for k in idx], N, T, urls=[evs[k][2] for k in idx], different_url=du)
        fired |= {idx[j] + 1 for j, x in enumerate(f) if x}
    return sorted(fired)

A, B = "192.0.2.10", "192.0.2.20"
# 1. fire_index: 8 x 404 liền nhau, cùng IP, URL khác -> Wazuh: 3, 6
check(run([(0.1 * i, A, f"/p{i}") for i in range(8)]) == [3, 6], "fire_index")
# 2. same_srcip: xen kẽ A,B -> Wazuh: 5, 6
check(run([(0.1 * i, A if i % 2 == 0 else B, f"/q{i}") for i in range(8)]) == [5, 6], "same_srcip")
# 3. timeframe: 2 sự kiện, chờ 11 s (> 8), thêm 4 -> Wazuh: 5
ev = [(0.0, A, "/t0"), (0.1, A, "/t1"), (11.1, A, "/t100"), (11.2, A, "/t101"), (11.3, A, "/t102"), (11.4, A, "/t103")]
check(run(ev) == [5], f"timeframe: {run(ev)}")
# 4. different_url, cùng một URL x8 -> Wazuh: không khớp
check(run([(0.1 * i, A, "/private/") for i in range(8)], du=True) == [], "different_url_same")
# 5. different_url, 2 URL xoay vòng x10 -> Wazuh: 4, 7, 10 (KHÔNG đòi URL khác nhau đôi một)
check(run([(0.1 * i, A, f"/u{i % 2}") for i in range(10)], du=True) == [4, 7, 10], f"different_url_cycle: {run([(0.1 * i, A, f'/u{i % 2}') for i in range(10)], du=True)}")
# mô hình "cửa sổ trượt" cũ (khớp ở mọi sự kiện có >= N trong T) sẽ cho 3..8 ở ca 1 — phải KHÁC
check(run([(0.1 * i, A, f"/p{i}") for i in range(8)]) != list(range(3, 9)), "không được là cửa sổ trượt")
# thành viên rule cha: sự kiện không khớp cha không được đếm
f = freq_fires([0, 1, 2, 3, 4], 3, 8, member=[True, False, True, False, True])
check(f == [False, False, False, False, True], f"member: {f}")
# biên cửa sổ [t-T, t] gồm hai đầu
check(freq_fires([0, 4, 8], 3, 8) == [False, False, True] and freq_fires([0, 4, 8.001], 3, 8) == [False, False, False], "biên T")

# ---------------------------------------------------------------- joint_fires (mô phỏng chung, theo mã nguồn 4.14)
from wazuh_sim import joint_fires
import ipaddress
def net(c): return lambda ip, n=ipaddress.ip_network(c): ipaddress.ip_address(ip) in n
# đúng file luật thăm dò của wazuh_probe.py (26/10): thứ tự nạp 119901..119904, 119906, 119905
PROBE = [dict(id=119901, level=3, N=3, T=8, sid=100012, src=net("192.0.2.0/27"), groups="siem10_probe,"),
         dict(id=119902, level=3, N=3, T=8, sid=100011, src=net("192.0.2.0/27"), groups="siem10_probe,"),
         dict(id=119903, level=10, N=3, T=8, group="web_scan", src=net("192.0.2.64/28"), groups="siem10_probe,"),
         dict(id=119904, level=10, N=5, T=8, group="siemlab_observed", src=net("192.0.2.64/28"), groups="siem10_probe,"),
         dict(id=119906, level=10, N=5, T=8, group="siemlab_observed", src=net("192.0.2.96/28"), groups="siem10_probe,"),
         dict(id=119905, level=10, N=3, T=8, group="web_scan", src=net("192.0.2.96/28"), groups="siem10_probe,")]
def jrun(ip, sts, rules=PROBE):
    f = joint_fires([0.0] * len(sts), sts, rules, ips=[ip] * len(sts))
    return {r: [k + 1 for k, x in enumerate(f) if x == r] for r in {x for x in f if x >= 110000}}
# 26/10 (output/wazuh_probe_20261026-181932.json):
check(jrun("192.0.2.10", [404] * 8) == {119901: [3, 6]}, f"joint fire_index: {jrun('192.0.2.10', [404] * 8)}")
check(jrun("192.0.2.70", [404] * 22) == {}, f"joint interact_scan_first (Wazuh: không luật nào khớp): {jrun('192.0.2.70', [404] * 22)}")
check(jrun("192.0.2.100", [404] * 22) == {}, f"joint interact_any_first (Wazuh: không luật nào khớp): {jrun('192.0.2.100', [404] * 22)}")
mixed = [404 if i % 2 else 200 for i in range(20)]
check(jrun("192.0.2.71", mixed) == {119904: [8, 16]}, f"joint interact_mixed (Wazuh: 119904 ở 8, 16): {jrun('192.0.2.71', mixed)}")
# vì sao: 119901 (if_matched_sid 100012) làm sự kiện 404 vào danh sách sid -> KHÔNG vào danh sách nhóm. Bỏ 119901 thì
# luật nhóm phải khớp được trên chuỗi 404 (đối chứng: mô hình không được "tình cờ" ra rỗng)
noprobe = [r for r in PROBE if r["id"] != 119901]
check(jrun("192.0.2.70", [404] * 22, noprobe) != {}, "không có 119901 thì luật nhóm phải khớp trên chuỗi 404")
# dấu khớp nằm trên SỰ KIỆN, chặn cả luật khác cùng level: web_scan N=3 trước, any N=5 sau, chuỗi 404 (không có 119901)
r = jrun("192.0.2.70", [404] * 22, noprobe)
check(r == {119903: [3, 6, 9, 12, 15, 18, 21]}, f"any bị web_scan chặn hoàn toàn: {r}")
# luật AI thật v10: r401 làm 401 rời danh sách nhóm -> luật any không đếm 401
AI = [dict(id=110011, level=10, N=3, T=10, sid=100011, groups="ai_generated,siem10_r401,attack,ai_generated,"),
      dict(id=110030, level=10, N=4, T=10, group="siemlab_observed", groups="ai_generated,siem10_any,attack,ai_generated,")]
f = joint_fires([0.0] * 6, [401] * 6, AI)
check(f == [100011, 100011, 110011, 100011, 100011, 110011], f"401 chỉ do r401 đếm: {f}")
f = joint_fires([0.0] * 6, [401] * 6, AI[1:])
check(f == [100011, 100011, 100011, 110030, 100011, 100011], f"không có r401 thì any đếm 401: {f}")
# 110020 có group chứa chuỗi 'web_scan' -> sự kiện nó khớp vẫn vào danh sách web_scan nhưng đã đánh dấu (chặn)
WS = [dict(id=110020, level=10, N=3, T=10, group="web_scan", groups="ai_generated,siem10_web_scan,attack,ai_generated,")]
f = joint_fires([0.0] * 9, [404] * 9, WS)
check([k + 1 for k, x in enumerate(f) if x == 110020] == [3, 6, 9], f"web_scan tự thân như freq_fires: {f}")
# luật con đầu tiên khớp thắng; dấu level 10 không chặn luật level 12 (theo mã nguồn: matched >= level mới dừng)
TWO = [dict(id=110020, level=10, N=3, T=10, group="web_scan", groups="ai_generated,siem10_web_scan,attack,ai_generated,"),
       dict(id=110030, level=12, N=3, T=10, group="siemlab_observed", groups="ai_generated,siem10_any,attack,ai_generated,")]
f = joint_fires([0.0] * 6, [404] * 6, TWO)
check(f == [100012, 100012, 110020, 110030, 100012, 100012], f"thứ tự luật con / level: {f}")
# 110020 N=2: sự kiện nó khớp vào lại danh sách web_scan (group chứa chuỗi 'web_scan') và chặn -> khớp ở 2, 4, 6
f = joint_fires([0.0] * 6, [404] * 6, [dict(TWO[0], N=2)])
check([k + 1 for k, x in enumerate(f) if x == 110020] == [2, 4, 6], f"web_scan N=2 (so khớp chuỗi con): {f}")
# N=2 theo mã nguồn: không có sự kiện trước nào bị đánh dấu -> khớp ở mọi sự kiện cha từ thứ 2
# ĐO THẬT 26/10 (output/wazuh_probe_20261026-220357.json, --n 2, 404 x6): 100012, 119901 x5
P2 = [dict(PROBE[0], N=2)] + PROBE[1:]
check(jrun("192.0.2.10", [404] * 6, P2) == {119901: [2, 3, 4, 5, 6]}, f"joint probe N=2: {jrun('192.0.2.10', [404] * 6, P2)}")
check(run([(0.1 * i, A, f"/p{i}") for i in range(6)], N=2) == [2, 3, 4, 5, 6], f"freq_fires probe N=2: {run([(0.1 * i, A, f'/p{i}') for i in range(6)], N=2)}")
# N=2 và hết hạn: sự kiện cha chưa khớp gần nhất quá T -> sự kiện hiện tại thành "neo" mới
check(freq_fires([0, 1, 20, 21, 22], 2, 8) == [False, True, False, True, True], f"N=2 hết hạn: {freq_fires([0, 1, 20, 21, 22], 2, 8)}")
f = joint_fires([0.0] * 4, [401] * 4, [dict(id=110011, level=10, N=2, T=10, sid=100011)])
check(f == [100011, 110011, 110011, 110011], f"N=2: {f}")
# tương đương freq_fires với một luật sid, N>=3 (ngẫu nhiên)
import random
rr = random.Random(5); bad = 0
for _ in range(2000):
    n = rr.randint(1, 50); t = sorted(float(int(i * rr.choice([0, .3, 1, 3]))) for i in range(n)); t.sort()
    st = [rr.choice([401, 401, 200, 404]) for _ in range(n)]; N = rr.randint(2, 8); T = rr.choice([1, 2, 5, 10])
    a = freq_fires(t, N, T, member=[s == 401 for s in st])
    b = [x == 110011 for x in joint_fires(t, st, [dict(id=110011, level=10, N=N, T=T, sid=100011)])]
    bad += a != b
check(bad == 0, f"joint != freq_fires ở {bad} chuỗi (N 2..8)")
print("OK" if not fails else f"THẤT BẠI {len(fails)}"); sys.exit(1 if fails else 0)
