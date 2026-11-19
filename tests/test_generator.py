#!/usr/bin/env python3
"""Kiểm tra generator mà không cần Docker: tính xác định, tính hợp lệ, vùng chồng lấn benign/malicious,
site_model <-> htdocs, và kế hoạch lập lịch (IP không đụng nhau, không vượt ngân sách rps).  python3 tests/test_generator.py"""
import os, sys, statistics as st
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import scenarios as SC, site_model as S, run_batch as RB

fails = []
def check(c, msg):
    if not c: fails.append(msg); print("  LỖI:", msg)

# 1. xác định + hợp lệ
for n in SC.SCEN:
    a, b = SC.build_session(n, 1, "t", 0), SC.build_session(n, 1, "t", 0)
    c = SC.build_session(n, 2, "t", 0)
    check(SC.session_digest(a) == SC.session_digest(b), f"{n}: không xác định theo seed")
    check(SC.session_digest(a) != SC.session_digest(c), f"{n}: đổi seed không đổi phiên")
    ts = [q.t for q in a["reqs"]]
    check(ts == sorted(ts) and (not ts or ts[0] == 0.0), f"{n}: thời gian không tăng/không bắt đầu từ 0")
    check(all(q.url.startswith("/") and q.method in ("GET", "HEAD") for q in a["reqs"]), f"{n}: url/method sai")
    check(len(a["reqs"]) >= 1 and a["duration"] <= 900, f"{n}: rỗng hoặc quá dài ({a['duration']:.0f}s)")
    check(a["label"] == (0 if a["family"] == "benign" else 1), f"{n}: nhãn không khớp họ")

# 2. chồng lấn: dải tốc độ trung bình benign vs malicious phải giao nhau (không tách được bằng 1 ngưỡng tốc độ)
def mean_rate(n, k):
    s = SC.build_session(n, 9, "ov", k); return len(s["reqs"]) / max(s["duration"], 1)
r = {n: [mean_rate(n, k) for k in range(40)] for n in ("heavy_burst", "crawler", "monitor", "scan_fast", "scan_stealth", "auth_slow", "flood")}
check(min(r["heavy_burst"]) < max(r["scan_stealth"]) or min(r["scan_fast"]) < max(r["heavy_burst"]), "tốc độ heavy_burst không chồng với scan")
check(max(r["heavy_burst"]) > min(r["scan_fast"]), "heavy_burst không chạm dải scan_fast")
check(max(r["crawler"]) > min(r["scan_stealth"]) and min(r["crawler"]) < max(r["scan_stealth"]), "crawler không chồng dải scan_stealth")
check(max(r["monitor"]) > min(r["auth_slow"]), "monitor không chồng dải auth_slow")
print("  tốc độ TB (req/s) min/median/max:", {k: (round(min(v), 2), round(st.median(v), 2), round(max(v), 2)) for k, v in r.items()})

# 3. shift thật sự đổi phân phối
def rates(shift): return [SC.build_session("scan_fast", 4, "x", k, shift)["params"]["rate"] for k in range(60)]
base = st.median(rates(False)); far = sum(1 for x in rates(True) if x < .7 * base or x > 1.4 * base) / 60
check(far >= .7, f"shift chỉ đẩy {far:.0%} phiên ra khỏi dải thường (cần >=70%)")

# 4. site_model <-> htdocs, conf
htd = os.path.join(ROOT, "apache", "htdocs")
if not os.path.isdir(htd):
    sys.exit("Không thấy thư mục apache/ (container lab bản cũ chưa gắn ./apache). Cập nhật docker-compose.yml hoặc chạy ngoài container.")
for u in S.OK_SET:
    check(os.path.exists(os.path.join(htd, u.lstrip("/"))), f"thiếu file htdocs{u}")
check(os.path.exists(os.path.join(htd, "private", "index.html")), "thiếu private/index.html")
conf = open(os.path.join(ROOT, "apache", "httpd-siemlab.conf"), encoding="utf-8").read()
check(conf == S.apache_conf(), "httpd-siemlab.conf không khớp site_model (chạy python3 apache/gen_site.py)")
check("-Indexes" in conf and "RedirectMatch 301" in conf and "R=500" in conf, "conf thiếu thành phần")
check(S.status_of("/old") == 301 and S.status_of("/old/x.html") == 404 and S.status_of("/private/", "good") == 200
      and S.status_of("/private/", None) == 401 and S.status_of("/static/") == 403 and S.status_of("/api/flaky") == 500, "status_of sai ca cơ bản")

# 5. lập lịch
for preset in ("smoke", "dev", "full"):
    ss = RB.make_sessions(preset)
    ids = [s["run_id"] for s in ss]
    check(len(ids) == len(set(ids)), f"{preset}: run_id trùng")
    ips = RB.parse_ips("172.30.90.32-172.30.90.200")
    check(len(ips) == 169 and ips[0] == "172.30.90.32", "parse_ips sai")
    plan = RB.plan_schedule(ss, ips, 300.0, 150.0, 40)
    byip = {}
    for s, ip, st0 in plan: byip.setdefault(ip, []).append((st0, st0 + s["duration"] + 3))
    for ip, iv in byip.items():
        iv.sort()
        for (a0, a1), (b0, b1) in zip(iv, iv[1:]):
            check(b0 >= a1 + 300.0 - 1e-6, f"{preset}: IP {ip} dùng lại trước cooldown")
    ev = sorted([(st0, 1, s["peak_rps"]) for s, ip, st0 in plan] + [(st0 + s["duration"] + 3, -1, s["peak_rps"]) for s, ip, st0 in plan], key=lambda x: (x[0], x[1]))
    cur = mx = 0
    for t, d, pk in ev:
        cur += d * pk; mx = max(mx, cur)
    over = [s["run_id"] for s in ss if s["peak_rps"] > 150]
    check(not over, f"{preset}: phiên vượt ngân sách một mình: {over}")
    check(mx <= 150.0 + 1e-6, f"{preset}: tổng peak_rps chạy chồng = {mx} > ngân sách")
    sp = [s["split"] for s, _, _ in plan]
    order = [x for i, x in enumerate(sp) if i == 0 or x != sp[i - 1]]
    check(order == sorted(set(order), key=order.index) and len(order) == len(set(order)), f"{preset}: các split bị xen kẽ {order}")
    print(f"  {preset}: {len(plan)} phiên, mức tải chồng tối đa {mx:.0f} rps")
import tempfile, json as _j, time as _t
# sổ IP chung giữa các batch: IP vừa dùng phải chờ đủ cooldown; thứ tự IP theo số, không theo chuỗi
td = tempfile.mkdtemp(); now = _t.time()
open(os.path.join(td, RB.LEDGER), "w").write(_j.dumps({"ip": "10.0.0.100", "t_end": now - 100}) + "\n" +
                                            _j.dumps({"ip": "10.0.0.5", "t_end": now - 1000}) + "\nrác\n")
ips = RB.parse_ips("10.0.0.5-10.0.0.120"); ff = RB.ledger_free(td, ips, 300.0, now)
check(abs(ff["10.0.0.100"] - 200.0) < 1e-6 and ff["10.0.0.5"] == 0.0 and ff["10.0.0.6"] == 0.0, f"ledger_free sai: {ff['10.0.0.100']}")
pl = RB.plan_schedule(RB.make_sessions("smoke")[:3], ["10.0.0.100", "10.0.0.32", "10.0.0.33"], 300.0, 150.0, 40,
                      {"10.0.0.100": 0.0, "10.0.0.32": 0.0, "10.0.0.33": 500.0})
check([ip for _, ip, _ in pl][:2] == ["10.0.0.32", "10.0.0.100"], f"thứ tự IP sai: {[ip for _, ip, _ in pl]}")
check(pl[2][2] >= 0.0 and pl[2][1] in ("10.0.0.33", "10.0.0.32", "10.0.0.100"), "")
check(all(st >= 500.0 for _, ip, st in pl if ip == "10.0.0.33"), "IP còn bận vẫn được xếp sớm")
check(RB.PRESETS["lockbox"]["seed"] is None and not RB.PRESETS["lockbox"]["shift"], "lockbox phải không có seed trong code và cùng phân phối train")
td = tempfile.mkdtemp(); s1 = RB.lockbox_seed(os.path.join(td, "runs")); s2 = RB.lockbox_seed(os.path.join(td, "runs"))
check(s1 == s2 and len(s1) > 20, "lockbox_seed không ổn định trong cùng thư mục")
check(s1 != RB.lockbox_seed(os.path.join(tempfile.mkdtemp(), "runs")), "lockbox_seed không ngẫu nhiên giữa các máy")
p = SC.build_session("recon_then_brute", 1, "t", 0)["params"]
check("scan_rate" in p and "brute_rate" in p, "tham số 2 pha của recon_then_brute bị ghi đè")

print("OK" if not fails else f"THẤT BẠI {len(fails)} mục"); sys.exit(1 if fails else 0)
