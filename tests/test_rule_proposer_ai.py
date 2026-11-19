#!/usr/bin/env python3
"""Kiểm rule_proposer.py --label-source ai (v4-AI) trên dữ liệu tổng hợp:
  1. nhãn chọn = kết luận RF theo phiên (>= 1 alert có round(proba, d) >= ngưỡng op) — tính lại độc lập;
  2. chọn bằng nhãn AI == chạy chế độ nhãn thật trên bản CSV đã thay nhãn bằng kết luận AI (cùng bộ luật, cùng số);
  3. nhãn thật KHÔNG ảnh hưởng lựa chọn (đảo nhãn thật -> cùng bộ luật); SELECT_TRUTH báo bằng nhãn thật;
  4. mặc định chỉ split val; --select-extra thêm phiên (bỏ stress); từ chối train của chính dataset huấn luyện model;
  5. hồ sơ: pid 'AI-', label_source, ai_labels (sha model, ngưỡng), fingerprint khác đề xuất nhãn thật cùng (N, T).
  python3 tests/test_rule_proposer_ai.py"""
import hashlib, io, json, os, random, shutil, sys, tempfile
from contextlib import redirect_stdout
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import numpy as np, pandas as pd, joblib
from sklearn.linear_model import LogisticRegression
import features as F
import rule_proposer as RP

fails = []
def check(c, m):
    if not c: fails.append(m); print("  LỖI:", m)

r = random.Random(11); rows = []
def sess(key, sc, lab, split, ip, t0, gen, sig):
    t = t0
    for k, (dt, st, url) in enumerate(gen()):
        t += dt
        f = {c: 0.0 for c in F.FEATURE_COLUMNS}; f["r404"] = sig     # "AI" chỉ nhìn r404: sig quyết định kết luận
        rows.append({"session_key": key, "scenario": sc, "label": lab, "split": split, "event_epoch": round(t, 6),
                     "status": st, "srcip": ip, "method": "GET", "url": url, **f})

def auth():      return [(r.uniform(.2, .6), 401, "/private/") for _ in range(r.randint(25, 60))]
def scan():      return [(r.uniform(.02, .1), 404 if r.random() < .9 else 301, f"/x{r.randint(0, 9999)}") for _ in range(r.randint(80, 200))]
def mistakes():  return [(r.uniform(2, 6), 404 if r.random() < .5 else 200, f"/dead{r.randint(0, 3)}") for _ in range(r.randint(20, 40))]
def burst():     return [(r.uniform(.001, .01), 200, "/") for _ in range(r.randint(300, 600))]
def crawler():   return [(r.uniform(.3, 1), 301 if r.random() < .2 else 200, f"/p{r.randint(0, 99)}") for _ in range(r.randint(40, 80))]

T0 = 1.8e9; n = 0
# AI đồng ý với nhãn thật trừ: phiên auth_*_0 (AI cho là sạch), burst_*_0 và mistakes_*_1 (AI cho là nghi ngờ)
for ds, splits in (("main", (("train", 3), ("val", 5), ("test", 3), ("stress", 2))), ("extra", (("train", 3), ("test", 2), ("stress", 2)))):
    for split, reps in splits:
        for sc, lab, g in (("auth", 1, auth), ("scan", 1, scan), ("mistakes", 0, mistakes), ("burst", 0, burst), ("crawler", 0, crawler)):
            for i in range(reps):
                n += 1
                ai = lab
                if (sc == "auth" and i == 0) : ai = 0
                if (sc == "burst" and i == 0) or (sc == "mistakes" and i == 1): ai = 1
                if split == "stress": ai = 1                            # stress: AI nghi ngờ hết — phải bị loại khỏi tập chọn
                sess(f"{ds}/{split}_{sc}_{i}", sc if split != "stress" else "stress_" + sc, lab if split != "stress" else 0,
                     split, f"10.9.{n // 250}.{n % 250}", T0 + n * 1000, g, 2.0 if ai else -2.0)
df = pd.DataFrame(rows)
T = tempfile.mkdtemp()
D = os.path.join(T, "dataset_main.csv"); E = os.path.join(T, "dataset_extra.csv")
df[df.session_key.str.startswith("main/")].to_csv(D, index=False)
df[df.session_key.str.startswith("extra/")].to_csv(E, index=False)
X = df[F.NO_URL_COLUMNS].to_numpy(float); est = LogisticRegression().fit(X, (df.r404 > 0).astype(int))
MP = os.path.join(T, "model.joblib")
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
joblib.dump({"model": est, "features": list(F.NO_URL_COLUMNS), "thresholds": {"fp5": 0.5, "f1": 0.3}, "score_decimals": 9,
             "dataset": {"path": D, "sha256": sha(D)}}, MP)

def run(*args):
    with redirect_stdout(io.StringIO()):
        return RP.main(list(args))

# 1-2. chọn bằng nhãn AI, so với chạy nhãn thật trên bản đã thay nhãn
PR = os.path.join(T, "pr_ai")
M = run("--data", D, "--select-extra", E, "--label-source", "ai", "--model", MP, "--proposals", PR, "--out", os.path.join(T, "o_ai"))
d = pd.concat([pd.read_csv(D), pd.read_csv(E)])
d = d[((d.session_key.str.startswith("main/")) & (d.split == "val")) | ((d.session_key.str.startswith("extra/")) & (d.split != "stress"))]
sc = np.round(est.predict_proba(d[F.NO_URL_COLUMNS].to_numpy(float))[:, 1], 9)
ver = pd.Series(sc >= 0.5, index=d.index).groupby(d.session_key).any().astype(int)
check(M["select_splits"] == ["val"], f"mặc định ai phải chỉ dùng val: {M['select_splits']}")
check(M["ai_labels"]["agreement"]["sessions"] == len(ver) == 5 * 5 + 5 * 5, f"tập chọn = val main + extra không stress: {M['ai_labels']['agreement']}")
check(M["ai_labels"]["agreement"]["ai_benign_truth_attack"] == 3 and M["ai_labels"]["agreement"]["ai_attack_truth_benign"] == 6,
      f"đồng thuận AI/nhãn thật sai: {M['ai_labels']['agreement']}")
SEL = M["results"]["SELECT"]["union"]; TRU = M["results"]["SELECT_TRUTH"]["union"]
check(SEL["attack_sessions"] == int(ver.sum()) and SEL["benign_sessions"] == int((ver == 0).sum()), "SELECT phải đếm theo nhãn AI")
check(TRU["attack_sessions"] == 20 and TRU["benign_sessions"] == 30, f"SELECT_TRUTH phải đếm theo nhãn thật: {TRU}")
check(M["allowed_false_alarm_sessions"] == int(0.05 * int((ver == 0).sum()) + 1e-9), "hạn mức tính trên số phiên AI cho là sạch")
d2 = d.copy(); d2["label"] = d2.session_key.map(ver); d2["split"] = "val"
D2 = os.path.join(T, "dataset_relabel.csv"); d2.to_csv(D2, index=False)
M2 = run("--data", D2, "--select-splits", "val", "--proposals", os.path.join(T, "pr_x"), "--out", os.path.join(T, "o_x"), "--dry-run")
check(M2["chosen"] == M["chosen"], f"nhãn AI phải cho cùng bộ luật như nhãn thật đã thay: {M['chosen']} vs {M2['chosen']}")
check(M2["results"]["SELECT"]["union"] == SEL, "cùng số trên tập chọn")
check(M2["results"]["SELECT"]["joint"]["union"] == M["results"]["SELECT"]["joint"]["union"], "cùng số mô phỏng chung")
# 3. đảo nhãn thật -> lựa chọn không đổi
for p_ in (D, E):
    x = pd.read_csv(p_); x["label"] = 1 - x["label"]; x.to_csv(p_.replace(".csv", "_flip.csv"), index=False)
joblib.dump({"model": est, "features": list(F.NO_URL_COLUMNS), "thresholds": {"fp5": 0.5}, "score_decimals": 9, "dataset": {}}, MP + ".b")
M3 = run("--data", D.replace(".csv", "_flip.csv"), "--select-extra", E.replace(".csv", "_flip.csv"), "--label-source", "ai",
         "--model", MP + ".b", "--dry-run", "--proposals", os.path.join(T, "pr_y"), "--out", os.path.join(T, "o_y"))
check(M3["chosen"] == M["chosen"] and M3["results"]["SELECT"]["union"] == SEL, "nhãn thật không được ảnh hưởng lựa chọn khi --label-source ai")
check(M3["results"]["SELECT_TRUTH"]["union"]["attack_sessions"] == 30, "SELECT_TRUTH đổi theo nhãn thật (đã đảo)")
# 4. từ chối split train của dataset đã huấn luyện model
try:
    run("--data", D, "--select-splits", "train,val", "--label-source", "ai", "--model", MP, "--dry-run", "--out", os.path.join(T, "o_z"))
    check(False, "phải từ chối train của dataset huấn luyện")
except SystemExit as e:
    check("RF đã học" in str(e), f"thông báo từ chối: {e}")
# 5. hồ sơ
cases = [json.load(open(os.path.join(PR, f), encoding="utf-8")) for f in os.listdir(PR) if f.endswith(".json")]
check(cases and all(c["proposal_id"].startswith("AI-R") and c["label_source"] == "ai" for c in cases), "pid 'AI-' + label_source")
check(all(c["ai_labels"]["model_sha256"] == sha(MP) and c["ai_labels"]["threshold"] == 0.5 for c in cases), "hồ sơ ghi sha model + ngưỡng")
check(all("tu ket luan AI" in open(os.path.join(PR, c["proposal_id"] + ".xml"), encoding="utf-8").read() for c in cases), "mô tả XML ghi nguồn AI")
check(all(c["regression"]["passed"] for c in cases), "hồi quy (trên nhãn AI) phải đạt")
PT = os.path.join(T, "pr_truth"); os.makedirs(PT)
for c in cases:                                                       # đề xuất nhãn thật cùng (N, T) có sẵn -> AI vẫn tạo hồ sơ riêng
    fam, N_, T_ = c["family"], c["params"]["frequency"], c["params"]["timeframe"]
    fp = hashlib.sha256(json.dumps([RP.TEMPLATE, fam, RP.FAMILIES[fam]["cond"], N_, T_]).encode()).hexdigest()[:16]
    json.dump({"proposal_id": f"R-{fam}", "fingerprint": fp, "status": "applied"}, open(os.path.join(PT, f"R-{fam}.json"), "w"))
M4 = run("--data", D, "--select-extra", E, "--label-source", "ai", "--model", MP, "--proposals", PT, "--out", os.path.join(T, "o_w"))
check(len(M4["proposals_written"]) == len(cases), "fingerprint AI phải khác đề xuất nhãn thật cùng tham số")
M5 = run("--data", D, "--select-extra", E, "--label-source", "ai", "--model", MP, "--proposals", PT, "--out", os.path.join(T, "o_w"))
check(M5["proposals_written"] == [], "chạy lại không tạo trùng")
rep = open(os.path.join(T, "o_ai", "report.md"), encoding="utf-8").read()
check("NHÃN TỪ AI" in rep and "nhãn thật (chỉ báo cáo)" in rep, "report ghi nguồn nhãn")

print("OK" if not fails else f"THẤT BẠI {len(fails)}"); shutil.rmtree(T); sys.exit(1 if fails else 0)
