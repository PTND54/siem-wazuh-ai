#!/usr/bin/env python3
"""Kiểm build_dataset.py trên dữ liệu tổng hợp có đủ các ca khó mà dev1 thật không có:
nhiều batch, alert ở file .json.gz xoay vòng + trùng id giữa 2 file, phiên mồ côi (bị ngắt), phiên thiếu alert,
phiên thừa alert, alert lạ trong khoảng thời gian batch, alert không phải SIEMLAB, alert của rule tương quan 110xxx THAY
CHO alert gốc (như Wazuh thật: không nhóm siemlab_observed, decoder siemlab -> vẫn là sự kiện), alert rule khác cùng dòng
log với alert gốc (bỏ, không đếm hai lần), agent đọc lại file (khác id, cùng dòng log), phiên lỗi mạng, phiên trễ lịch,
glob không khớp, alert SIEMLAB của decoder khác.  python3 tests/test_build_dataset.py"""
import csv, gzip, json, os, subprocess, sys, tempfile
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
T = tempfile.mkdtemp(); T0 = 1.8e9
fails = []
def check(c, m):
    if not c: fails.append(m); print("  LỖI:", m)

def alert(aid, t, ip, url, st, rid="100012", groups=("siemlab", "siemlab_observed"), decoder="siemlab"):
    return json.dumps({"id": aid, "rule": {"id": rid, "level": 4, "groups": list(groups)}, "decoder": {"name": decoder},
                       "full_log": f'SIEMLAB {int(t * 1e6)} {ip} "GET {url} HTTP/1.1" {st} 10'})

def batch(name, sessions, started):
    d = os.path.join(T, "runs", name); os.makedirs(d)
    open(os.path.join(d, "sessions.jsonl"), "w").write("".join(json.dumps(s) + "\n" for s in sessions))
    open(os.path.join(d, "started.jsonl"), "w").write("".join(json.dumps(s) + "\n" for s in started))
    return d

def S(rid, ip, t0, t1, n_ok, label=1, split="train", **kw):
    return {**kw, "run_id": rid, "scenario": "scan_fast" if label else "browse_human", "family": "recon" if label else "benign",
            "label": label, "split": split, "shift": False, "srcip": ip, "t_first": t0, "t_last": t1, "n_ok": n_ok}

# batch A: phiên tốt (10 alert), phiên thiếu (5/10), phiên thừa (12/10), phiên mồ côi; batch B: phiên tốt trên IP khác
A = batch("A", [S("good", "10.0.0.1", T0, T0 + 9, 10), S("miss", "10.0.0.2", T0, T0 + 9, 10, 0),
                S("extra", "10.0.0.3", T0, T0 + 9, 10), S("failed", "10.0.0.6", T0, T0 + 9, 10, failed=True),
                S("laggy", "10.0.0.7", T0, T0 + 9, 10, max_lag=5.0)],
          [{"run_id": r, "srcip": ip, "t_start": T0} for r, ip in (("good", "10.0.0.1"), ("miss", "10.0.0.2"), ("extra", "10.0.0.3"))]
          + [{"run_id": "cut", "srcip": "10.0.0.4", "t_start": T0, "t_end_plan": T0 + 50}])
B = batch("B", [S("goodB", "10.0.0.5", T0 + 400, T0 + 409, 10, 0, "test")],
          [{"run_id": "goodB", "srcip": "10.0.0.5", "t_start": T0 + 400}])
a1, a2 = [], []
for i in range(10):                                                                     # g3, g4: luật 110012 thay alert gốc
    a1.append(alert(f"g{i}", T0 + i, "10.0.0.1", f"/x{i}", 404) if i not in (3, 4) else
              alert(f"g{i}", T0 + i, "10.0.0.1", f"/x{i}", 404, "110012", ("ai_generated", "web_scan", "attack")))
a1.append(alert("w0", T0 + 2.5, "10.0.0.1", "/w", 404, "31101", ("web", "accesslog"), decoder="web-accesslog"))
for i in range(5): a1.append(alert(f"m{i}", T0 + i, "10.0.0.2", "/", 200, "100010"))
for i in range(12): a1.append(alert(f"e{i}", T0 + i * .7, "10.0.0.3", f"/y{i}", 404))
for i in range(7): a1.append(alert(f"c{i}", T0 + i, "10.0.0.4", f"/z{i}", 404))         # traffic dở dang của phiên bị ngắt
a1.append(alert("u0", T0 + 5, "10.0.0.9", "/lạ", 404))                                 # IP lạ trong khoảng batch
a1.append(alert("k0", T0 - 30, "172.30.90.1", "/__siem10_canary/abc123", 404))        # canary apply_rule trước batch 30 s
for ip, tag in (("10.0.0.6", "f"), ("10.0.0.7", "l")):
    for i in range(10): a1.append(alert(f"{tag}{i}", T0 + i, ip, f"/q{i}", 404))
a1.append(alert("ai0", T0 + 0, "10.0.0.1", "/x0", 404, "110012", ("web_scan", "siemlab_observed", "ai_generated")))
a1.append(alert("reread0", T0 + 1, "10.0.0.1", "/x1", 404))                             # agent đọc lại: id mới, cùng dòng
a1.append(json.dumps({"id": "o0", "rule": {"id": "502", "level": 3, "groups": ["ossec"]}, "full_log": "ossec: Manager started."}))
for i in range(10): a2.append(alert(f"b{i}", T0 + 400 + i, "10.0.0.5", f"/p{i}", 200, "100010"))
a2 += a1[:3]                                                                            # trùng id giữa file xoay vòng và alerts.json
with gzip.open(os.path.join(T, "ossec-alerts-20.json.gz"), "wt") as f: f.write("\n".join(a1) + "\n")
open(os.path.join(T, "alerts.json"), "w").write("\n".join(a2) + "\n")

out = os.path.join(T, "ds.csv")
r = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "build_dataset.py"), "--batches", A, B,
                    "--alerts", os.path.join(T, "alerts.json"), os.path.join(T, "*.json.gz"), os.path.join(T, "khong-co-*.gz"),
                    "--out", out],
                   capture_output=True, text=True)
print(r.stdout.strip()); check(r.returncode == 0, f"build_dataset lỗi: {r.stderr[-500:]}")
rows = list(csv.DictReader(open(out)))
au = json.load(open(os.path.join(T, "ds.audit.json")))
ids = {x["run_id"] for x in rows}
check(ids == {"good", "goodB"}, f"chỉ giữ 2 phiên đủ coverage, được {ids}")
d = au["dropped_on_read"]
check(d.get("same_id") == 3 and d.get("same_log_line") == 2 and len(d) == 2, f"bỏ trùng sai: {d}")
check(au.get("correlated_rule_events") == 2, f"phải giữ 2 sự kiện mang alert 110012: {au.get('correlated_rule_events')}")
check("CẢNH BÁO: không tìm thấy" in r.stdout, "không cảnh báo glob không khớp")
check(au["excluded"].get("orphan") == 7, f"phải loại 7 alert phiên mồ côi: {au['excluded']}")
check(au["excluded"].get("unknown_in_range") == 1, f"phải đếm 1 alert lạ: {au['excluded']}")
check(au["excluded"].get("canary_in_range") == 1, f"canary của apply_rule phải được nhận diện riêng: {au['excluded']}")
uk = au.get("unknown_in_range_alerts") or []
check(len(uk) == 1 and uk[0]["srcip"] == "10.0.0.9" and uk[0]["url"] == "/lạ" and uk[0]["alert_id"] == "u0", f"phải liệt kê alert lạ: {uk}")
check("alert lạ: " in r.stdout and "10.0.0.9" in r.stdout, "phải in alert lạ ra màn hình")
ex = au["excluded_sessions"]
check(ex == {"A/extra": ["coverage"], "A/miss": ["coverage"], "A/failed": ["failed"], "A/laggy": ["lag"]}, f"phiên bị loại sai: {ex}")
check({x["session_key"] for x in rows} == {"A/good", "B/goodB"}, "session_key sai")
check(len(rows) == 20 and {x["batch"] for x in rows} == {"A", "B"}, f"số dòng/batch sai: {len(rows)}")
g = [x for x in rows if x["run_id"] == "good"]
check([int(x["seq"]) for x in g] == list(range(10)) and g[-1]["count_60s"] == "10", "seq/đặc trưng của phiên good sai")
check([x["rule_id"] for x in g].count("110012") == 2, "2 dòng của phiên good phải mang rule 110012")
print("OK" if not fails else f"THẤT BẠI {len(fails)}"); sys.exit(1 if fails else 0)
