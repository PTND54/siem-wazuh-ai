#!/usr/bin/env python3
"""Kiểm compare_rules.py trên dữ liệu tổng hợp: alert 110xxx "thật" được sinh bằng mô phỏng CHUNG (wazuh_sim.joint_fires,
theo mã nguồn Wazuh) trên giờ Manager làm tròn giây, với độ trễ ngẫu nhiên và 3 luật áp theo thứ tự r401 -> web_scan
-> any -> biến thể 'joint' phải khớp gần tuyệt đối; luật any (bị web_scan chặn) thì mô phỏng độc lập phải lệch; đổi một
alert thật thì đúng 1 phiên lệch và chỗ lệch được ghi; thống kê trễ đúng; dòng không có alert được đếm.
  python3 tests/test_compare_rules.py"""
import io, json, math, os, random, shutil, sys, tempfile
from contextlib import redirect_stdout
from datetime import datetime, timezone
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import numpy as np, pandas as pd
import compare_rules as CR
import wazuh_sim as W
from rule_proposer import FAMILIES

fails = []
def check(c, m):
    if not c: fails.append(m); print("  LỖI:", m)

r = random.Random(3)
T = tempfile.mkdtemp(); PR = os.path.join(T, "proposals"); os.makedirs(PR)
RULES = {"r401": (12, 60), "web_scan": (8, 10), "any": (6, 10)}
for i, (f, (N, Tw)) in enumerate(RULES.items()):
    json.dump({"proposal_id": f"P-{f}", "status": "applied", "family": f, "params": {"frequency": N, "timeframe": Tw},
               "history": [{"action": "apply", "at": f"2026-10-26T07:2{i}:00+00:00"}]},
              open(os.path.join(PR, f"P-{f}.json"), "w"))
SPECS = CR.joint_specs(CR.applied_rules(PR))
json.dump({"proposal_id": "P-old", "status": "removed", "family": "any", "params": {"frequency": 5, "timeframe": 10}},
          open(os.path.join(PR, "P-old.json"), "w"))                     # không 'applied' -> bỏ qua

rows, alerts, lat_all = [], [], []
t0 = 1.8e9
for s in range(30):
    ip = f"10.7.0.{s}"; sc = ("auth", "scan", "mistakes")[s % 3]; lab = int(sc != "mistakes")
    t = t0 + s * 1000; ev = []
    for k in range(r.randint(20, 120)):
        t += r.uniform(0.05, 3.0) if sc != "scan" else r.uniform(0.01, 0.4)
        st = 401 if sc == "auth" else (404 if r.random() < .8 else 200)
        ev.append((round(t, 6), st, f"/u{k}"))
    lat = [r.uniform(0.05, 1.5) for _ in ev]
    mgr = [e[0] + l for e, l in zip(ev, lat)]
    st_arr = np.array([e[1] for e in ev])
    rid = [ {200: "100010", 401: "100011", 404: "100012"}[e[1]] for e in ev]
    fin = W.joint_fires([math.floor(m) for m in mgr], st_arr, SPECS)  # "Wazuh thật": chung, giờ Manager theo giây
    rid = [str(x) for x in fin]
    for k, ((te, st, url), m, rr) in enumerate(zip(ev, mgr, rid)):
        usec = int(round(te * 1e6))
        rows.append({"session_key": f"B/s{s}", "scenario": sc, "label": lab, "srcip": ip, "event_epoch": usec / 1e6,
                     "method": "GET", "url": url, "status": st, "rule_id": rr})
        ts = datetime.fromtimestamp(m, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
        alerts.append({"id": f"a{s}_{k}", "timestamp": ts, "rule": {"id": rr, "groups": ["x"]}, "decoder": {"name": "siemlab"},
                       "full_log": f'SIEMLAB {usec} {ip} "GET {url} HTTP/1.1" {st} 0'})
        lat_all.append(m - usec / 1e6)
df = pd.DataFrame(rows); D = os.path.join(T, "dataset_x.csv"); df.to_csv(D, index=False)
A = os.path.join(T, "alerts.json")
open(A, "w").write("\n".join(json.dumps(x) for x in alerts[:-1]) + "\n")   # bỏ alert cuối -> 1 dòng không có alert

def run():
    with redirect_stdout(io.StringIO()):
        return CR.main(["--data", D, "--alerts", A, "--proposals", PR, "--out", os.path.join(T, "out")])

M = run()
check(list(M["rules"]) == ["r401", "web_scan", "any"], f"chỉ lấy đề xuất 'applied', theo thứ tự áp: {list(M['rules'])}")
check(M["rows_without_alert"] == 1, f"phải đếm 1 dòng không có alert: {M['rows_without_alert']}")
lat = np.array(lat_all[:-1])
check(abs(M["latency_manager_minus_apache"]["median_s"] - np.median(lat)) < 0.01, f"trung vị trễ sai: {M['latency_manager_minus_apache']}")
for f in RULES:
    R = M["results"]["joint"][f]
    # dòng cuối (không có alert) dùng giờ Apache -> có thể lệch ở đúng phiên cuối; còn lại phải khớp tuyệt đối
    check(R["exact"] >= R["sessions"] - 1, f"joint phải khớp gần tuyệt đối với {f}: {R['exact']}/{R['sessions']}")
    check(R["actual_fires"] > 0, f"{f}: dữ liệu tổng hợp phải có lần khớp thật")
Ri, Rj = M["results"]["manager_sec"]["any"], M["results"]["joint"]["any"]
check(Ri["exact"] < Rj["exact"] and Ri["sim_fires"] > Ri["actual_fires"],
      f"any bị web_scan chặn: mô phỏng độc lập phải lệch (khớp thừa), joint thì không: {Ri['exact']}/{Ri['sim_fires']} vs {Rj['exact']}/{Rj['actual_fires']}")
ap_ = sum(M["results"]["apache"][f]["exact"] for f in RULES); ms_ = sum(M["results"]["manager_sec"][f]["exact"] for f in RULES)
check(ms_ >= ap_, f"manager_sec phải khớp ít nhất bằng apache ({ms_} vs {ap_})")

# đổi 1 alert thật -> đúng 1 phiên thêm lệch, chỗ lệch được ghi
k = next(i for i, x in enumerate(alerts) if x["rule"]["id"] == "110020" and x["id"].startswith("a1_"))
alerts[k]["rule"]["id"] = "100012"
df.loc[(df.session_key == "B/s1") & (df.url == alerts[k]["full_log"].split()[4]), "rule_id"] = "100012"
df.to_csv(D, index=False)
open(A, "w").write("\n".join(json.dumps(x) for x in alerts) + "\n")
M2 = run()
R = M2["results"]["joint"]["web_scan"]
check(R["exact"] == R["sessions"] - 1 and any(mm["session"] == "B/s1" and mm["only_sim"] for mm in R["mismatches"]),
      f"đổi 1 alert phải ra đúng 1 phiên lệch (B/s1, chỉ mô phỏng): {R['exact']}/{R['sessions']} {R['mismatches'][:2]}")
print("OK" if not fails else f"THẤT BẠI {len(fails)}"); shutil.rmtree(T); sys.exit(1 if fails else 0)
