#!/usr/bin/env python3
"""Kiểm trainer.py trên dữ liệu tổng hợp (đặc trưng tính bằng đúng features.enrich):
ngưỡng f1/fp5 so với bản tham chiếu vét cạn, luật tần suất so với bản đếm ngây thơ, tổng hợp theo phiên (k=1/k=3,
thời gian đến phát hiện), trọng số 1/n, không rò rỉ test (đảo nhãn test không đổi mô hình/ngưỡng), model.joblib nạp lại
cho đúng điểm số đã xuất, kiểm tra toàn vẹn (phiên ở 2 split, file --eval trùng phiên), cảnh báo features.py đổi.
  python3 tests/test_trainer.py"""
import contextlib, io, json, math, os, random, sys, tempfile
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import numpy as np, pandas as pd
import features as F
import trainer as TR

fails = []
def check(c, m):
    if not c: fails.append(m); print("  LỖI:", m)

# ---------------------------------------------------------------- dữ liệu tổng hợp
SCEN = {  # tên: (nhãn, family, khoảng cách trung bình (s), hàm mã trạng thái, số sự kiện)
    "browse":  (0, "benign", 4.0, lambda r: 200 if r.random() < .9 else 404, 40),
    "burst":   (0, "benign", 0.3, lambda r: 200, 60),
    "typo":    (0, "benign", 3.0, lambda r: 401 if r.random() < .5 else 200, 15),
    "scan":    (1, "recon", 0.4, lambda r: 404 if r.random() < .85 else 200, 80),
    "scan_slow": (1, "recon", 2.5, lambda r: 404 if r.random() < .9 else 403, 40),
    "brute":   (1, "cred", 0.8, lambda r: 401, 50),
    "flood":   (1, "flood", 0.05, lambda r: 200, 150),
    "retry":   (0, "benign", 1.0, lambda r: 401, 30),          # stress
}
def make_df(seed=0, n=None):
    n = n or {"train": 6, "val": 4, "test": 4}
    r = random.Random(seed); ev = []; ip = 0
    for split, k in list(n.items()) + [("stress", 2)]:
        names = ["retry"] if split == "stress" else [s for s in SCEN if s != "retry"]
        for name in names:
            lab, fam, gap, st, m = SCEN[name]
            for i in range(k):
                ip += 1; t = 1.8e9 + ip * 10000.0
                for j in range(m):
                    t += r.expovariate(1 / gap)
                    ev.append({"srcip": f"10.0.{ip // 250}.{ip % 250}", "event_epoch": t, "url": f"/{name}/{r.randint(0, 30)}",
                               "status": st(r), "session_key": f"syn/{split}_{name}_{i}", "scenario": name, "family": fam,
                               "label": lab, "split": split, "t0": 1.8e9 + ip * 10000.0})
    rows = F.enrich(ev)
    df = pd.DataFrame(rows)
    df["t_rel"] = df["event_epoch"] - df["t0"]
    df = df.drop(columns="t0").sort_values(["session_key", "event_epoch"]).reset_index(drop=True)
    df["seq"] = df.groupby("session_key").cumcount()
    return df

T = tempfile.mkdtemp()
df = make_df()
DATA = os.path.join(T, "dataset_syn.csv"); df.to_csv(DATA, index=False)
code_sha = TR.sha256_file(os.path.join(ROOT, "scripts", "features.py"))[:16]
json.dump({"features_sha": code_sha, "feature_columns": F.FEATURE_COLUMNS}, open(os.path.join(T, "dataset_syn.audit.json"), "w"))

# ---------------------------------------------------------------- 1. đơn vị
P = TR.Part(df[df.split == "val"], "val")
check(np.allclose(np.bincount(P.code, weights=P.w), 1.0), "trọng số 1/n không cộng thành 1 mỗi phiên")
check((P.pos == P.df["seq"].to_numpy()).all(), "pos khác seq")

rng = np.random.default_rng(0)
score = np.round(rng.random(len(P.y)) + .4 * P.y, 2)
tau, best = TR.tau_f1(score, P.y, P.w)
def wf1(fl):
    tp = (P.w * fl * P.y).sum(); fp = (P.w * fl * (1 - P.y)).sum(); fn = (P.w * (1 - fl) * P.y).sum()
    return 2 * tp / (2 * tp + fp + fn)
ref = max(wf1(score >= u) for u in np.unique(score))
check(abs(best - ref) < 1e-12 and abs(wf1(score >= tau) - ref) < 1e-12, f"tau_f1 sai: {best} vs vét cạn {ref}")
uq = np.unique(score)
def is_mid(t):                                 # ngưỡng phải nằm đúng giữa hai giá trị điểm liền kề trên dữ liệu chọn ngưỡng
    lo, hi = uq[uq < t], uq[uq > t]
    return len(lo) and len(hi) and abs(t - (lo.max() + hi.min()) / 2) < 1e-12
check(tau not in uq and is_mid(tau), f"tau_f1 không ở điểm giữa hai giá trị liền kề: {tau}")

for target in (0.0, 0.05, 0.25, 0.5):
    tfp, anchor = TR.tau_fp(score, P, target)
    if anchor is not None and (score > anchor).any():
        check(is_mid(tfp) and uq[uq < tfp].max() == anchor, f"tau_fp không ở điểm giữa anchor và giá trị liền trên (target={target})")
    mx = TR.sess_max(score, P); ben = P.ys == 0
    nb = ben.sum(); allowed = math.floor(target * nb + 1e-9)
    check(((mx[ben] >= tfp).sum()) <= allowed, f"tau_fp vi phạm ràng buộc ở target={target}")
    smaller = [u for u in np.unique(score) if u < tfp]
    if smaller:                               # ngưỡng nhỏ hơn kế tiếp phải vi phạm (=> tau là nhỏ nhất)
        u = max(smaller); check((mx[ben] >= u).sum() > allowed, f"tau_fp không nhỏ nhất ở target={target}")

for st, Tw in (((401,), 10), ((403, 404), 30), (None, 60)):
    got = TR.rule_counts(P, st, Tw)
    t, s, c = P.tt, P.status, P.code
    naive = np.array([0 if (st is not None and s[i] not in st) else
                      sum(1 for j in range(len(t)) if c[j] == c[i] and t[i] - Tw <= t[j] <= t[i] and (st is None or s[j] in st))
                      for i in range(len(t))])
    check((got == naive).all(), f"rule_counts sai với {st}, T={Tw}")

# biên cửa sổ [t-T, t] gồm cả hai đầu (như features.py: t_j >= t_i - 60), thời điểm nguyên để có ca trùng biên
toy = pd.DataFrame({"session_key": ["a"] * 6 + ["b"] * 3, "scenario": "x", "family": "recon", "label": 1, "split": "val",
                    "event_epoch": [0, 10, 10, 20, 30, 41, 0, 5, 10], "t_rel": [0, 10, 10, 20, 30, 41, 0, 5, 10],
                    "status": [401, 401, 404, 401, 401, 401, 401, 401, 401]})
for c in F.FEATURE_COLUMNS: toy[c] = 0.0
Q = TR.Part(toy, "toy")
check(TR.rule_counts(Q, (401,), 10).tolist() == [1, 2, 0, 2, 2, 1, 1, 2, 3], f"rule_counts biên sai: {TR.rule_counts(Q, (401,), 10).tolist()}")
check(TR.rule_counts(Q, None, 20).tolist() == [1, 2, 3, 4, 4, 2, 1, 2, 3], f"rule_counts (mọi mã) sai: {TR.rule_counts(Q, None, 20).tolist()}")

# rule_fires = ngữ nghĩa Wazuh đo được (khớp ở N, rồi tiêu thụ) — so với cài đặt ngây thơ viết độc lập
def naive_fires(P, st, Tw, N):
    out = np.zeros(len(P.tt), bool)
    for c in range(P.S):
        pend = []
        for i in np.flatnonzero(P.code == c):
            if st is not None and P.status[i] not in st: continue
            if N == 2:                               # Wazuh N=2 (đo 26/10): khớp khi sự kiện cha chưa khớp gần nhất còn trong T
                if pend and P.tt[i] - pend[-1] <= Tw: out[i] = True
                else: pend = [P.tt[i]]
                continue
            pend = [x for x in pend if x >= P.tt[i] - Tw]
            if len(pend) + 1 >= N: out[i] = True; pend = []
            else: pend.append(P.tt[i])
    return out
for st, Tw, N in (((401,), 10, 2), ((403, 404), 30, 3), (None, 60, 5), ((401,), 120, 12)):
    f = TR.rule_fires(P, st, Tw, N)
    check((f == naive_fires(P, st, Tw, N)).all(), f"rule_fires sai với {st}, T={Tw}, N={N}")
    # lần khớp ĐẦU của mỗi phiên trùng với lần đầu đếm trượt >= N
    first = lambda fl: [np.flatnonzero(fl & (P.code == c))[:1].tolist() for c in range(P.S)]
    check(first(f) == first(TR.rule_counts(P, st, Tw) >= N), f"lần khớp đầu khác đếm trượt: {st}, T={Tw}, N={N}")
# toy: phiên a (401 tại 0,10,20,30,41; 404 tại 10), N=2, T=10 -> neo 0, khớp 10; 20 quá T so với neo -> neo mới, khớp 30;
# 41 neo mới. Phiên b (0, 5, 10): neo 0, khớp 5 VÀ 10 (N=2 không tiêu thụ — đo thật 26/10)
check(np.flatnonzero(TR.rule_fires(Q, (401,), 10, 2)).tolist() == [1, 4, 7, 8], f"rule_fires toy sai: {np.flatnonzero(TR.rule_fires(Q, (401,), 10, 2)).tolist()}")

fl = score >= tau
g = TR.sess_agg(P, fl)
for si in range(P.S):
    idx = np.nonzero(P.code == si)[0]; hits = idx[fl[idx]]
    check(g["nflag"][si] == len(hits), "nflag sai")
    for k in (1, 3):
        exp_t = P.t[hits[k - 1]] if len(hits) >= k else np.nan
        exp_a = (hits[k - 1] - idx[0] + 1) if len(hits) >= k else np.nan
        check((np.isnan(exp_t) and np.isnan(g[f"t{k}"][si])) or g[f"t{k}"][si] == exp_t, f"t{k} sai ở phiên {si}")
        check((np.isnan(exp_a) and np.isnan(g[f"a{k}"][si])) or g[f"a{k}"][si] == exp_a, f"a{k} sai ở phiên {si}")
r = TR.summarize(P, fl, g, score)
check(abs(r["w_f1"] - wf1(fl)) < 1e-12, "summarize w_f1 sai")
sess_hit = pd.Series(fl).groupby(P.code).sum().to_numpy()
check(abs(r["fp_k3"] - (sess_hit[P.ys == 0] >= 3).mean()) < 1e-12, "fp_k3 sai")
I = TR.boot_index(P, 200, 1); I2 = TR.boot_index(P, 200, 1)
check((I == I2).all(), "bootstrap không tái lập được")
counts = pd.Series(P.sess["scenario"].to_numpy()[I[0]]).value_counts().to_dict()
check(counts == P.sess["scenario"].value_counts().to_dict(), "bootstrap không giữ số phiên mỗi kịch bản")

Ptr = TR.Part(df[df.split == "train"], "train")
tree = TR.fit_est("tree_d3", Ptr, F.NO_URL_COLUMNS)
check(abs(tree.tree_.weighted_n_node_samples[0] - Ptr.S) < 1e-6, "cây không fit với trọng số 1/n (tổng trọng số gốc != số phiên)")
rf = TR.fit_est("rf", Ptr, F.NO_URL_COLUMNS, n_estimators=5, n_jobs=1)   # sklearn có thể chuẩn hóa tổng trọng số -> so tỉ lệ lớp ở gốc
root = np.mean([t.tree_.value[0][0][1] / t.tree_.value[0][0].sum() for t in rf.estimators_])
sess_share, alert_share = Ptr.ys.mean(), Ptr.y.mean()
check(abs(root - sess_share) < abs(root - alert_share), f"RF không fit với trọng số 1/n (gốc {root:.3f}, phiên {sess_share:.3f}, alert {alert_share:.3f})")

# ---------------------------------------------------------------- 2. chạy đầu-cuối
FAST = ["--n-estimators", "25", "--n-boot", "60", "--seeds", "2", "--perm-repeats", "1", "--n-jobs", "1", "--run-label", "test"]
def run(data, out, extra=()):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        M = TR.main(["--data", data, "--out", out] + FAST + list(extra))
    return M, buf.getvalue()

out1 = os.path.join(T, "m1")
M, txt = run(DATA, out1)
for f in ("model.joblib", "metrics.json", "report.md", "test_predictions.csv"):
    check(os.path.exists(os.path.join(out1, f)), f"thiếu {f}")
check(not M["dataset"]["audit"]["warnings"], f"không được cảnh báo khi features_sha khớp: {M['dataset']['audit']['warnings']}")
check("stress" in M["eval"] and M["eval"]["stress"]["rf"]["f1"]["n_attack_sessions"] == 0, "thiếu đánh giá stress")
check(M["eval"]["val"]["rf"]["fp5"]["fp_k1"] <= 0.05 + 1e-12, "fp5 vi phạm ràng buộc trên val")
check(M["eval"]["val"]["wazuh_rule"]["fp5"]["fp_k1"] <= 0.05 + 1e-12, "luật fp5 vi phạm ràng buộc trên val")
check(len(M["rf_seeds"]) == 2, "thiếu kết quả nhiều seed")
lo = {r["left_out"] for r in M["leave_out"]}
check({"family:recon", "family:cred", "family:flood", "scenario:scan", "scenario:browse"} <= lo and "scenario:flood" not in lo,
      f"nhóm leave-out sai: {sorted(lo)}")
row = next(r for r in M["leave_out"] if r["left_out"] == "family:cred")
check(row["n_held_sessions"] == 8 and row["n_test_benign_sessions"] == 12, f"leave-out cred: số phiên sai {row['n_held_sessions']}/{row['n_test_benign_sessions']}")
rowb = next(r for r in M["leave_out"] if r["left_out"] == "scenario:browse")
check(rowb["n_test_benign_sessions"] == 8, "leave-out benign: test benign phải bỏ kịch bản bị loại")
check(set(M["ablation"]) == {"full_18", "no_url_minus_volume", "no_url_minus_variety", "no_url_minus_timing", "no_url_minus_status", "no_url_minus_auth"},
      "bộ ablation sai")
check(set(M["permutation_importance"]["groups"]) == {"volume", "variety", "timing", "status", "auth"}, "nhóm permutation sai")

import joblib
B = joblib.load(os.path.join(out1, "model.joblib"))
check(B["features"] == F.NO_URL_COLUMNS and set(B["thresholds"]) == {"f1", "fp5"}, "bundle thiếu đặc trưng/ngưỡng")
check(B["dataset"]["sha256"] == TR.sha256_file(DATA), "hash dataset sai")
pr = pd.read_csv(os.path.join(out1, "test_predictions.csv"))
te = df[df.split == "test"].sort_values(["session_key", "event_epoch"])
s = B["model"].predict_proba(te[B["features"]].to_numpy(float))[:, 1]
check(len(pr) == len(te) and np.allclose(s, pr["score_rf"].to_numpy()), "điểm của model.joblib khác test_predictions")
sr = np.round(s, B["score_decimals"])
check(((sr >= B["thresholds"]["f1"]).astype(int) == pr["flag_rf_f1"].to_numpy()).all(), "cờ f1 không khớp ngưỡng đã lưu")
check(((sr >= B["thresholds"]["fp5"]).astype(int) == pr["flag_rf_fp5"].to_numpy()).all(), "cờ fp5 không khớp ngưỡng đã lưu")

# hồi quy (full1 trên máy thật): điểm trùng đúng giá trị quyết định ngưỡng fp5, máy khác lệch 1 ulp -> cờ không được đổi
class Fake:
    def __init__(self, v): self.v = v
    def predict_proba(self, X): return np.c_[1 - self.v, self.v]
Pv = TR.Part(df[df.split == "val"], "val")
tie = 0.75730465650433945
base = np.where(np.arange(len(Pv.y)) % 3 == 0, tie, 0.2)
m1 = TR.ScoreModel("rf", F.NO_URL_COLUMNS, Fake(base)).calibrate(Pv, 0.05)
m2 = TR.ScoreModel("rf", F.NO_URL_COLUMNS, Fake(np.nextafter(base, 1.0))); m2.tau = dict(m1.tau)
check((m1.flags(Pv, "fp5") == m2.flags(Pv, "fp5")).all(), "lệch 1 ulp giữa hai máy làm đổi cờ fp5 (thiếu làm tròn điểm)")
check(not m1.flags(Pv, "fp5").any(), "alert có điểm bằng đúng điểm phiên benign quyết định ngưỡng fp5 không được gắn cờ")
va = TR.Part(df[df.split == "val"], "val")
sv = np.round(B["model"].predict_proba(va.X(B["features"]))[:, 1], B["score_decimals"])
check(B["thresholds"]["f1"] == TR.tau_f1(sv, va.y, va.w)[0], "ngưỡng f1 không phải ngưỡng tối đa wF1 (trọng số 1/n) trên val")
check(B["thresholds"]["fp5"] == TR.tau_fp(sv, va, 0.05)[0], "ngưỡng fp5 không khớp val")
check(B["model"].n_features_in_ == 15 == len(B["features"]) and B["features"] == F.NO_URL_COLUMNS,
      f"mô hình phải nhận đúng 15 cột NO_URL_COLUMNS: {B['model'].n_features_in_} {B['features']}")
check(not set(B["features"]) & set(F.FEATURE_GROUPS["url"]), "có cột URL lọt vào mô hình")
try:                                           # mô hình phải từ chối ma trận 18 cột (chặn nhầm thứ tự / thêm cột ở ai-service)
    B["model"].predict_proba(te[F.FEATURE_COLUMNS].to_numpy(float)); check(False, "mô hình nhận ma trận 18 cột")
except ValueError:
    pass
rep = open(os.path.join(out1, "report.md"), encoding="utf-8").read()
check("## Test (chỉ báo cáo)" in rep and "stress" in rep and "Leave-family-out" in rep, "report thiếu mục")

# ---------------------------------------------------------------- 3. không rò rỉ test
d2 = df.copy(); m = d2.split == "test"; d2.loc[m, "label"] = 1 - d2.loc[m, "label"]
DATA2 = os.path.join(T, "dataset_flip.csv"); d2.to_csv(DATA2, index=False)
M2, _ = run(DATA2, os.path.join(T, "m2"), ["--no-leaveout", "--no-ablation"])
check(M2["chosen"] == M["chosen"], "đảo nhãn test làm đổi tham số/ngưỡng đã chọn -> rò rỉ test")
check(M2["eval"]["val"]["rf"]["f1"]["w_f1"] == M["eval"]["val"]["rf"]["f1"]["w_f1"], "đảo nhãn test làm đổi kết quả val")
check(M2["dataset"]["audit"]["warnings"], "phải cảnh báo khi thiếu .audit.json")

# ---------------------------------------------------------------- 4. toàn vẹn
d3 = df.copy(); k = d3.session_key == d3.session_key.iloc[0]; idx = d3.index[k][:3]; d3.loc[idx, "split"] = "test"
DATA3 = os.path.join(T, "dataset_bad.csv"); d3.to_csv(DATA3, index=False)
try:
    run(DATA3, os.path.join(T, "m3"), ["--no-leaveout", "--no-ablation"]); check(False, "không báo lỗi phiên ở 2 split")
except SystemExit as e:
    check("nhiều hơn một giá trị 'split'" in str(e), f"thông báo lỗi sai: {e}")
EV = os.path.join(T, "dataset_ev.csv"); df[df.split == "test"].assign(split="shift").to_csv(EV, index=False)
try:
    run(DATA, os.path.join(T, "m4"), ["--no-leaveout", "--no-ablation", "--eval", EV]); check(False, "không báo lỗi --eval trùng phiên")
except SystemExit as e:
    check("trùng với dataset chính" in str(e), f"thông báo lỗi sai: {e}")
e2 = make_df(seed=5, n={"shift": 2}); e2 = e2[e2.split == "shift"].copy(); e2["session_key"] = "sh/" + e2["session_key"]
EV2 = os.path.join(T, "dataset_shiftsyn.csv"); e2.to_csv(EV2, index=False)
M5, _ = run(DATA, os.path.join(T, "m5"), ["--no-leaveout", "--no-ablation", "--eval", EV2])
check("shiftsyn:shift" in M5["eval"] and M5["eval"]["shiftsyn:shift"]["rf"]["f1"]["n_sessions"] == 14, "đánh giá --eval sai")
json.dump({"features_sha": "deadbeef", "feature_columns": F.FEATURE_COLUMNS}, open(os.path.join(T, "dataset_flip.audit.json"), "w"))
check(any("features.py đã đổi" in w for w in TR.check_audit(DATA2)["warnings"]), "không cảnh báo features.py đổi")

print("OK" if not fails else f"THẤT BẠI {len(fails)}"); sys.exit(1 if fails else 0)
