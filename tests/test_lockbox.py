#!/usr/bin/env python3
"""Kiểm lockbox_eval.py + lockbox_manifest.py trên dữ liệu tổng hợp:
  - metrics TỪ CHỐI khi chưa validate, khi mục 5 không đạt, khi dataset đổi sau khi validate;
  - validate: phiên bị loại > 3% / alert lạ / lỗi mạng / coverage -> không đạt; sạch -> đạt (check_pipeline live giả lập);
  - chỉ số: luật = alert 110xxx thật, P5 = RF HOẶC luật, hiệu ghép cặp, TTD chỉ trên phiên bị bắt, tính lại độc lập;
  - manifest: write -> check trùng; sửa 1 file / đổi đề xuất applied -> check báo khác; không ghi đè.
  python3 tests/test_lockbox.py"""
import io, json, os, shutil, subprocess, sys, tempfile, types
from contextlib import redirect_stdout
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import numpy as np, pandas as pd, joblib
from sklearn.linear_model import LogisticRegression
import features as F
import lockbox_eval as LE
import lockbox_manifest as LM

fails = []
def check(c, m):
    if not c: fails.append(m); print("  LỖI:", m)

T = tempfile.mkdtemp(); r = np.random.default_rng(1)
# ---- dataset: 4 kịch bản x 5 phiên split lockbox + 2 phiên stress
rows, sess = [], []
plan = [("scan", 1, 1.0, "100012"), ("auth", 1, 0.0, "100011"), ("browse", 0, 0.0, "100010"), ("dead", 0, 1.0, "100012")]
k = 0
for sc, lab, x0, rid in plan:
    for i in range(5):
        key = f"L/{sc}_{i}"; k += 1
        n = 12
        for j in range(n):
            f = {c: float(r.normal()) for c in F.FEATURE_COLUMNS}
            f["r404"] = x0 + (0.5 if lab and j > 2 else 0.0)            # tấn công rõ dần -> RF bắt sau vài alert
            rr = rid
            if sc == "auth" and j == 7 and i < 3: rr = "110011"          # luật bắt 3/5 phiên auth ở alert thứ 8
            if sc == "dead" and j == 9 and i == 0: rr = "110020"         # luật báo nhầm 1 phiên dead
            if sc == "scan" and j == 11 and i == 4: rr = "110030"        # luật any bắt 1 phiên scan ở alert cuối
            rows.append({"session_key": key, "scenario": sc, "family": sc, "label": lab, "split": "lockbox", "batch": "L",
                         "run_id": key[2:], "srcip": f"10.1.0.{k}", "event_epoch": 1e9 + k * 1000 + j, "t_rel": float(j),
                         "seq": j, "method": "GET", "url": "/", "status": 404, "rule_id": rr, "rule_level": 5, **f})
        sess.append({"session_key": key, "scenario": sc, "label": lab, "excluded": [], "coverage": 1.0, "max_lag": 0.0})
for i in range(2):
    key = f"L/stress_{i}"
    for j in range(5):
        f = {c: 0.0 for c in F.FEATURE_COLUMNS}; f["r404"] = 1.0
        rows.append({"session_key": key, "scenario": "stress", "family": "stress", "label": 0, "split": "stress", "batch": "L",
                     "run_id": key[2:], "srcip": f"10.2.0.{i}", "event_epoch": 2e9 + i * 1000 + j, "t_rel": float(j), "seq": j,
                     "method": "GET", "url": "/", "status": 404, "rule_id": "100012", "rule_level": 5, **f})
    sess.append({"session_key": key, "scenario": "stress", "label": 0, "excluded": [], "coverage": 1.0, "max_lag": 0.0})
df = pd.DataFrame(rows)
D = os.path.join(T, "dataset_lbx.csv"); df.to_csv(D, index=False)
audit = {"sessions": sess, "orphans": [], "excluded": {"outside_batches": 9, "canary_in_range": 1}, "unknown_in_range_alerts": []}
json.dump(audit, open(os.path.join(T, "dataset_lbx.audit.json"), "w"))
BD = os.path.join(T, "runs", "lbx"); os.makedirs(BD)
open(os.path.join(BD, "batch.jsonl"), "w").write(json.dumps({"n_sessions": len(sess), "code_digest": "x"}) + "\n")
open(os.path.join(BD, "sessions.jsonl"), "w").write("".join(json.dumps({"run_id": s["session_key"], "n_err": 0}) + "\n" for s in sess))
open(os.path.join(BD, "started.jsonl"), "w").write("".join(json.dumps({"run_id": s["session_key"]}) + "\n" for s in sess))
# ---- model: logistic trên r404 (đủ để có điểm), bó như model.joblib
X = df[F.NO_URL_COLUMNS].to_numpy(float); y = (df.r404 > 1.2).astype(int)
est = LogisticRegression().fit(X, y)
MP = os.path.join(T, "model.joblib")
joblib.dump({"model": est, "features": list(F.NO_URL_COLUMNS), "thresholds": {"f1": 0.5, "fp5": 0.5}, "score_decimals": 9}, MP)
OUT = os.path.join(T, "out")
PD = os.path.join(T, "proposals"); os.makedirs(PD)
def prop(pid, fam, N, Tw, status, src):
    json.dump({"proposal_id": pid, "family": fam, "status": status, "label_source": src,
               "params": {"frequency": N, "timeframe": Tw}}, open(os.path.join(PD, pid + ".json"), "w"))
for fam, N, Tw in (("r401", 12, 120), ("web_scan", 15, 10), ("any", 600, 10)):   # bộ đang áp (v4-AI giả lập)
    prop(f"AI-{fam}", fam, N, Tw, "applied", "ai")
prop("V3-web_scan", "web_scan", 5, 10, "removed", "truth")                          # đối chứng mô phỏng
prop("V3-slow", "web_scan", 3, 1, "removed", "truth")                               # 3 sự kiện cách 1 s > T=1 -> không bao giờ khớp
json.dump({"proposal_id": "CANARY-1", "status": "applied", "kind": "canary"}, open(os.path.join(PD, "CANARY-1.json"), "w"))

def ns(**kw):
    d = dict(data=D, batch=BD, model=MP, split="lockbox", out=OUT, skip_live=False, test_only=False,
             proposals=PD, baseline=[], alerts=None); d.update(kw)
    return types.SimpleNamespace(**d)

class FakeRun:                                                       # check_pipeline --stage live giả lập
    def __init__(self, ok): self.ok = ok
    def __call__(self, *a, **k):
        return types.SimpleNamespace(returncode=0 if self.ok else 1, stdout="  [OK] live\nTỔNG: OK" if self.ok else "  [LỖI] thiếu 3\nTỔNG: 1 LỖI", stderr="")

def quiet(fn, *a):
    buf = io.StringIO()
    with redirect_stdout(buf): rc = fn(*a)
    return rc, buf.getvalue()

real_run = subprocess.run
# 1. metrics từ chối khi chưa validate
rc, out = quiet(LE.metrics, ns()); check(rc == 2 and "TỪ CHỐI" in out, "metrics phải từ chối khi chưa có validity.json")
# 2. validate sạch -> đạt
LE.subprocess.run = FakeRun(True)
rc, out = quiet(LE.validate, ns()); V = json.load(open(os.path.join(OUT, "validity.json")))
check(rc == 0 and V["passed"], f"validate sạch phải đạt: {[c for c in V['checks'] if not c['ok']]}")
# 3. live lệch -> không đạt -> metrics từ chối
LE.subprocess.run = FakeRun(False)
rc, out = quiet(LE.validate, ns()); check(rc == 1, "live lệch phải làm mục 5 không đạt")
rc, out = quiet(LE.metrics, ns()); check(rc == 2 and "KHÔNG đạt" in out, "metrics phải từ chối khi mục 5 không đạt")
LE.subprocess.run = FakeRun(True)
# 4. phiên bị loại > 3% (22 phiên -> tối đa 0), alert lạ, lỗi mạng -> không đạt, có liệt kê
a2 = json.loads(json.dumps(audit)); a2["sessions"][0]["excluded"] = ["lag"]; a2["sessions"][0]["max_lag"] = 3.1
json.dump(a2, open(os.path.join(T, "dataset_lbx.audit.json"), "w"))
rc, out = quiet(LE.validate, ns()); V = json.load(open(os.path.join(OUT, "validity.json")))
c53 = next(c for c in V["checks"] if c["check"].startswith("5.3"))
check(rc == 1 and not c53["ok"] and c53["detail"]["danh sách"][0]["scenario"] == "scan" and c53["detail"]["danh sách"][0]["lý do"] == ["lag"],
      f"phiên bị loại vượt trần phải không đạt + liệt kê kịch bản/nhãn/lý do: {c53}")
a3 = json.loads(json.dumps(audit)); a3["excluded"]["unknown_in_range"] = 1
json.dump(a3, open(os.path.join(T, "dataset_lbx.audit.json"), "w"))
rc, out = quiet(LE.validate, ns()); check(rc == 1, "alert lạ phải làm mục 5 không đạt")
json.dump(audit, open(os.path.join(T, "dataset_lbx.audit.json"), "w"))
open(os.path.join(BD, "sessions.jsonl"), "a").write(json.dumps({"run_id": "x", "n_err": 2}) + "\n")
rc, out = quiet(LE.validate, ns()); check(rc == 1, "lỗi mạng / số phiên khác kế hoạch phải không đạt")
open(os.path.join(BD, "sessions.jsonl"), "w").write("".join(json.dumps({"run_id": s["session_key"], "n_err": 0}) + "\n" for s in sess))
# 5. validate lại sạch -> metrics chạy; kiểm số độc lập
rc, out = quiet(LE.validate, ns()); check(rc == 0, "validate lại phải đạt")
rc, out = quiet(LE.metrics, ns()); check(rc == 0, f"metrics phải chạy khi mục 5 đạt: {out[-300:]}")
M = json.load(open(os.path.join(OUT, "metrics.json")))
check(M["trial"] is False, "split lockbox + mục 5 đạt -> không phải THỬ")
R = M["results"]["lockbox"]
d = df[df.split == "lockbox"].copy()
d["s"] = np.round(est.predict_proba(d[F.NO_URL_COLUMNS].to_numpy(float))[:, 1], 9)
d["rf"] = d.s >= 0.5; d["rule"] = d.rule_id.isin(["110011", "110020", "110030"]); d["both"] = d.rf | d.rule
for kk, col in (("rf", "rf"), ("rule", "rule"), ("rf_or_rule", "both")):
    g = d.groupby("session_key").agg(lab=("label", "first"), n=(col, "sum"))
    det = (g[g.lab == 1].n >= 1).mean(); fa = (g[g.lab == 0].n >= 1).mean()
    check(abs(R[kk]["det_k1"] - det) < 1e-12 and abs(R[kk]["fp_k1"] - fa) < 1e-12, f"{kk}: det/fa {R[kk]['det_k1']}/{R[kk]['fp_k1']} != {det}/{fa}")
check(R["rule"]["n_detected_k1"] == 4 and R["rule"]["n_not_detected_k1"] == 6 and R["rule"]["n_false_alarm_k1"] == 1,
      f"luật = alert 110xxx thật: {R['rule']['n_detected_k1']}/{R['rule']['n_not_detected_k1']}/{R['rule']['n_false_alarm_k1']}")
check(R["rule"]["ttd_k1_s_median"] == 7.0 and R["rule"]["atd_k1_median"] == 8.0, f"TTD luật chỉ trên phiên bị bắt: {R['rule']['ttd_k1_s_median']} / {R['rule']['atd_k1_median']}")
p = M["paired"]["rf_or_rule-rf"]
check(abs(p["det_k1"]["diff"] - (R["rf_or_rule"]["det_k1"] - R["rf"]["det_k1"])) < 1e-12 and p["det_k1"]["ci95"] is not None, "P5: hiệu ghép cặp")
check("stress" in M["results"] and M["results"]["stress"]["rule"]["n_benign_sessions"] == 2, "stress báo riêng")
rep = open(os.path.join(OUT, "report.md"), encoding="utf-8").read()
check(rep.startswith("# LOCKBOX") and "không có ngưỡng đạt/không đạt" in rep and "Phiên bị loại: không có" in rep, "report lockbox")
# 5b. đối chứng v3 mô phỏng chung (giờ Apache làm tròn giây khi không có --alerts) + tên luật đang áp
import wazuh_sim as W
rc, out = quiet(LE.metrics, ns(baseline=["V3-web_scan"])); check(rc == 0, f"metrics với đối chứng: {out[-300:]}")
M = json.load(open(os.path.join(OUT, "metrics.json"))); R = M["results"]["lockbox"]
check([r["pid"] for r in M["applied_rules"]] == ["AI-r401", "AI-web_scan", "AI-any"] and M["rule_ids"] == ["110011", "110020", "110030"],
      f"luật đang áp đọc từ hồ sơ applied (bỏ canary): {M['applied_rules']}")
spec = [{"id": 110020, "level": 10, "N": 5, "T": 10, "group": "web_scan", "groups": "ai_generated,siem10_web_scan,attack,ai_generated,"}]
det = fa = 0
for key, g in d.groupby("session_key"):
    g = g.sort_values("event_epoch")
    hit = any(x == 110020 for x in W.joint_fires(np.floor(g.event_epoch.to_numpy()).tolist(), g.status.to_numpy(), spec))
    det += hit and g.label.iloc[0] == 1; fa += hit and g.label.iloc[0] == 0
check(det > 0 and fa > 0 and R["rule_v3sim"]["n_detected_k1"] == det and R["rule_v3sim"]["n_false_alarm_k1"] == fa,
      f"v3 mô phỏng: {R['rule_v3sim']['n_detected_k1']}/{R['rule_v3sim']['n_false_alarm_k1']} != {det}/{fa}")
check("rule-rule_v3sim" in M["paired"] and abs(M["paired"]["rule-rule_v3sim"]["det_k1"]["diff"] - (R["rule"]["det_k1"] - R["rule_v3sim"]["det_k1"])) < 1e-12, "P6 hiệu ghép cặp")
rep_ = open(os.path.join(OUT, "report.md"), encoding="utf-8").read()
check("Luật v4-AI (alert 110xxx THẬT)" in rep_ and "MÔ PHỎNG chung" in rep_ and "apache_sec" in rep_, "report: tên luật v4-AI + đối chứng + nguồn giờ")
rc, out = quiet(LE.metrics, ns(baseline=["V3-slow"])); Rs = json.load(open(os.path.join(OUT, "metrics.json")))["results"]["lockbox"]["rule_v3sim"]
check(rc == 0 and Rs["n_detected_k1"] == 0 and Rs["n_false_alarm_k1"] == 0, f"mô phỏng phải dùng giờ thật (T=1 không khớp): {Rs['n_detected_k1']}/{Rs['n_false_alarm_k1']}")
rc, out = quiet(LE.metrics, ns(baseline=["KHONG-CO"])); check(rc == 2 and "đối chứng" in out, "thiếu hồ sơ đối chứng phải từ chối")
rc, out = quiet(LE.metrics, ns(proposals=os.path.join(T, "trong"))); check(rc == 2 and "applied" in out, "lockbox không có luật applied phải từ chối")
rc, out = quiet(LE.metrics, ns())                                     # trả lại metrics.json không đối chứng cho các bước sau
# 6. dataset đổi sau validate -> từ chối
open(D, "a").write("\n")
rc, out = quiet(LE.metrics, ns()); check(rc == 2 and "đã đổi" in out, "dataset đổi sau validate phải bị từ chối")
LE.subprocess.run = real_run

# ---- manifest
R2 = os.path.join(T, "proj"); os.makedirs(os.path.join(R2, "scripts")); os.makedirs(os.path.join(R2, "proposals"))
for f in ("site_model.py", "scenarios.py", "traffic.py", "run_batch.py", "lockbox_eval.py", "lockbox_preflight.py"):
    open(os.path.join(R2, "scripts", f), "w").write(f"# {f}\n")
for p_, c_ in (("models/full1/model.joblib", "m"), ("wazuh/ai_rules/zz_siem10_ai_rules.xml", "<x/>"),
               ("vendor/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf", "<c/>")):
    os.makedirs(os.path.dirname(os.path.join(R2, p_)), exist_ok=True); open(os.path.join(R2, p_), "w").write(c_)
json.dump({"proposal_id": "R1", "status": "applied"}, open(os.path.join(R2, "proposals", "R1.json"), "w"))
LM.ROOT = R2; LM.OUT = os.path.join(R2, "docs", "lockbox_manifest.json"); os.makedirs(os.path.dirname(LM.OUT))
rc, out = quiet(LM.main, ["write", "--manifest", LM.OUT]); check(rc == 0 and os.path.exists(LM.OUT), f"manifest write: {out}")
rc, out = quiet(LM.main, ["write", "--manifest", LM.OUT]); check(rc == 1 and "không ghi đè" in out, "manifest không được ghi đè")
rc, out = quiet(LM.main, ["check", "--manifest", LM.OUT]); check(rc == 0 and "TRÙNG" in out, "check ngay sau write phải trùng")
open(os.path.join(R2, "scripts", "traffic.py"), "a").write("x=1\n")
rc, out = quiet(LM.main, ["check", "--manifest", LM.OUT]); check(rc == 1 and "scripts/traffic.py" in out, "sửa code phải bị phát hiện")
open(os.path.join(R2, "scripts", "traffic.py"), "w").write("# traffic.py\n")
json.dump({"proposal_id": "R1", "status": "removed"}, open(os.path.join(R2, "proposals", "R1.json"), "w"))
rc, out = quiet(LM.main, ["check", "--manifest", LM.OUT]); check(rc == 1 and "applied" in out, "đổi bộ luật applied phải bị phát hiện")
m = json.load(open(LM.OUT)); check(m["run_batch_code_digest"] and m["model_sha256"] and m["ai_rules_sha256"], "manifest phải có digest code/model/luật")

print("OK" if not fails else f"THẤT BẠI {len(fails)}"); shutil.rmtree(T); sys.exit(1 if fails else 0)
