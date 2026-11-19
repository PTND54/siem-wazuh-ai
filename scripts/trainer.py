#!/usr/bin/env python3
"""trainer.py — mục 14 hướng dẫn v2 (huấn luyện + đánh giá), viết mới cho v10.

  python3 scripts/trainer.py --data data/dataset_dev1.csv                       # -> models/dev1/
  python3 scripts/trainer.py --data data/dataset_full1.csv --run-label "máy thật" \
          [--eval data/dataset_shift1.csv data/dataset_tools1.csv] [--out models/full1]

Nguyên tắc (HANDOFF_v10 mục 6.1):
  * Đơn vị độc lập là PHIÊN (session_key). Fit trên train, chọn tham số/ngưỡng trên val, test CHỈ để báo cáo.
  * Trọng số mẫu w = 1/(số alert của phiên): mỗi phiên đóng góp tổng trọng số 1, phiên dài không áp đảo.
    "F1 cân bằng theo phiên" (wF1) = F1 tính với trọng số w.
  * Bộ đặc trưng chính: features.NO_URL_COLUMNS (15). Bộ đầy đủ (18) và bỏ từng nhóm = ablation.
  * Hai điểm vận hành, đều chọn trên val:
      f1  : ngưỡng tối đa wF1 trên val;
      fp5 : ngưỡng nhỏ nhất sao cho <= 5% phiên benign của val có >= 1 alert vượt ngưỡng.
  * Mức phiên: phiên tấn công "bị phát hiện" / phiên benign "bị báo nhầm" khi có >= k alert vượt ngưỡng, báo k=1 và k=3.
    Ngưỡng luôn chọn theo k=1; k=3 chỉ để báo cáo.
  * Mô hình: luật tần suất kiểu Wazuh (mô phỏng offline theo ngữ nghĩa ĐÃ ĐO trên Wazuh 4.14.7 — wazuh_sim.py: khớp ở
    sự kiện cha thứ N trong T giây rồi tiêu thụ N sự kiện; 401 / 403+404 / mọi mã, OR 3 luật; alert bị "gắn cờ" = alert
    làm luật khớp, đúng như alert level cao Wazuh sinh ra),
    ngưỡng đơn (một đặc trưng), cây độ sâu 3, hồi quy logistic, Random Forest (mô hình chính, chạy nhiều seed).
  * Khoảng tin cậy 95%: bootstrap theo phiên, phân tầng theo kịch bản. Chỉ phản ánh dao động do chọn phiên đánh giá,
    không phản ánh dao động do huấn luyện (phần đó xem bảng RF nhiều seed).
  * Leave-family-out / leave-scenario-out: bỏ nhóm khỏi train VÀ val (fit + chọn ngưỡng lại), đánh giá trên val+test
    của nhóm bị bỏ (không dùng ở bước nào); tỉ lệ báo nhầm benign chỉ tính trên benign của test.
  * Split khác train/val/test (stress, shift, tools, lockbox, và các file --eval) chỉ được đánh giá.

Đầu ra (--out): model.joblib (RF seed 0 + đặc trưng + ngưỡng + hash dataset + phiên bản), metrics.json, report.md,
test_predictions.csv.
Giới hạn: luật Wazuh ở đây là MÔ PHỎNG (đếm trên dữ liệu), chưa đối chiếu với wazuh-logtest (việc của bước sinh luật).
"""
import argparse, hashlib, itertools, json, math, os, platform, sys, time, warnings
from collections import OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler
from sklearn.tree import DecisionTreeClassifier, export_text

import features as F
import wazuh_sim as W

FORMAT = "siem10-trainer-v1"
REQUIRED = ["session_key", "scenario", "family", "label", "split", "event_epoch", "t_rel", "status"] + F.FEATURE_COLUMNS
MAIN_SPLITS = ("train", "val", "test")
OPS = ("f1", "fp5")
KS = (1, 3)
MAL_FAMILIES = ("recon", "cred", "flood")
RULE_VARIANTS = OrderedDict([("r401", (401,)), ("r403_404", (403, 404)), ("any", None)])
RULE_T = (10, 30, 60, 120)
# lưới N phải đủ cao: ở full1, flood có >= 440 alert/10 s còn heavy_burst (benign) tới ~530 -> N < 100 buộc phải tắt luật "mọi mã"
RULE_N = (2, 3, 4, 5, 6, 8, 10, 12, 15, 20, 30, 50, 75, 100, 150, 200, 300, 400, 500, 600, 800, 1000, math.inf)
LOGREG_C = (0.01, 0.1, 1.0, 10.0)
RF_LEAF = (1, 5, 20)
NAMES = OrderedDict([("wazuh_rule", "Luật tần suất kiểu Wazuh (mô phỏng)"), ("single_thr", "Ngưỡng đơn"),
                     ("tree_d3", "Cây độ sâu 3"), ("logreg", "Hồi quy logistic"), ("rf", "Random Forest (seed 0)")])
# Điểm được làm tròn trước khi so ngưỡng. Lý do (gặp thật ở full1): nhiều alert có đặc trưng giống hệt nhau (vd. 404 đầu
# cửa sổ) nên cùng một điểm RF; numpy khác phiên bản cộng xác suất các cây theo thứ tự khác -> lệch 1 ulp, và ngưỡng fp5
# (= ngay trên điểm của một phiên benign val) rơi đúng vào giá trị đó -> 12 phiên benign test đổi cờ giữa hai máy.
SCORE_DECIMALS = 9
T_OFFSET = 1e6         # tách các phiên trên một trục thời gian chung (t_rel của một phiên << 1e6 s)


def log(*a):
    print(*a, flush=True)


def _log1p0(X):
    return np.log1p(np.maximum(X, 0.0))


# ============================================================ dữ liệu
class Part:
    """Một tập con (split) đã sắp theo (phiên, thời gian); mã phiên liên tục 0..S-1."""

    def __init__(self, df, name):
        self.name = name
        df = df.sort_values(["session_key", "event_epoch"], kind="mergesort").reset_index(drop=True)
        self.df = df
        self.code, keys = pd.factorize(df["session_key"], sort=False)
        self.S = len(keys)
        self.n = np.bincount(self.code, minlength=self.S)
        self.start = np.r_[0, np.cumsum(self.n)[:-1]].astype(np.int64)
        self.pos = np.arange(len(df)) - self.start[self.code]            # 0 = alert đầu tiên của phiên
        self.w = 1.0 / self.n[self.code]
        self.y = df["label"].to_numpy(np.int64)
        self.t = df["t_rel"].to_numpy(float)
        self.status = df["status"].to_numpy(np.int64)
        self.sess = df.iloc[self.start][["session_key", "scenario", "family", "label", "split"]].reset_index(drop=True)
        self.sess["n"] = self.n
        self.ys = self.sess["label"].to_numpy(np.int64)
        tt = self.t + self.code * T_OFFSET
        if len(tt) > 1 and not np.all(np.diff(tt) >= 0):
            raise ValueError(f"{name}: t_rel không tăng dần trong phiên hoặc vượt {T_OFFSET} s")
        self.tt = tt

    def X(self, cols):
        return self.df[cols].to_numpy(float)

    def subset(self, mask_sess, name):
        keys = set(self.sess["session_key"][mask_sess])
        return Part(self.df[self.df["session_key"].isin(keys)], name)


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def load_dataset(path):
    df = pd.read_csv(path, low_memory=False)
    miss = [c for c in REQUIRED if c not in df.columns]
    if miss:
        raise SystemExit(f"{path}: thiếu cột {miss}")
    if df[F.FEATURE_COLUMNS].isna().any().any():
        raise SystemExit(f"{path}: có giá trị rỗng trong cột đặc trưng")
    df["label"] = df["label"].astype(int)
    df["split"] = df["split"].astype(str)
    if "seq" not in df.columns:
        df["seq"] = df.groupby("session_key").cumcount()
    for col in ("split", "label", "scenario", "family"):
        k = df.groupby("session_key")[col].nunique()
        if (k > 1).any():
            raise SystemExit(f"{path}: phiên có nhiều hơn một giá trị '{col}': {list(k[k > 1].index[:5])}")
    return df


def check_audit(data_path):
    """So features_sha trong audit (lúc dựng dataset) với features.py hiện tại."""
    ap = os.path.splitext(data_path)[0] + ".audit.json"
    code_sha = sha256_file(os.path.join(HERE, "features.py"))[:16]
    out = {"audit_path": ap if os.path.exists(ap) else None, "features_sha_code": code_sha,
           "features_sha_dataset": None, "warnings": []}
    if not os.path.exists(ap):
        out["warnings"].append("không có file .audit.json kèm dataset")
        return out
    au = json.load(open(ap, encoding="utf-8"))
    out["features_sha_dataset"] = au.get("features_sha")
    out["excluded_sessions"] = len(au.get("excluded_sessions", {}))
    out["coverage_min"], out["coverage_max"] = au.get("coverage_min"), au.get("coverage_max")
    if au.get("features_sha") != code_sha:
        out["warnings"].append(f"features.py đã đổi so với lúc dựng dataset ({au.get('features_sha')} != {code_sha}): "
                               "đặc trưng online sẽ khác dữ liệu huấn luyện")
    if au.get("feature_columns") and au["feature_columns"] != F.FEATURE_COLUMNS:
        out["warnings"].append("danh sách cột đặc trưng trong audit khác features.FEATURE_COLUMNS")
    return out


# ============================================================ ngưỡng
# Ngưỡng luôn đặt ở ĐIỂM GIỮA hai giá trị điểm liền kề trên val (không đặt sát một giá trị): quyết định trên val giữ
# nguyên, nhưng một alert ở tập khác có điểm trùng/lệch vài ulp so với giá trị val sẽ không rơi ngẫu nhiên sang phía kia.
def tau_f1(score, y, w):
    """Ngưỡng (gắn cờ khi score >= tau) tối đa F1 có trọng số. Trả (tau, wF1).
    tau = điểm giữa giá trị nhỏ nhất được gắn cờ và giá trị liền dưới nó trên dữ liệu chọn ngưỡng."""
    o = np.argsort(-score, kind="mergesort")
    s = score[o]
    tp = np.cumsum((w * y)[o]); fp = np.cumsum((w * (1 - y))[o]); P = tp[-1]
    last = np.r_[s[1:] != s[:-1], True]
    tp, fp, s = tp[last], fp[last], s[last]
    f1 = np.where(tp > 0, 2 * tp / (tp + fp + P), 0.0)
    i = int(np.argmax(f1))
    tau = (s[i] + s[i + 1]) / 2.0 if i + 1 < len(s) else -math.inf      # gắn cờ tất cả
    return float(tau), float(f1[i])


def sess_max(score, P):
    return np.maximum.reduceat(score, P.start) if P.S else np.array([])


def tau_fp(score, P, target):
    """Ngưỡng nhỏ nhất (theo nghĩa quyết định trên val) để số phiên benign có >= 1 alert vượt ngưỡng
    <= floor(target * số phiên benign). Trả (tau, anchor): anchor = điểm cao nhất của phiên benign đầu tiên KHÔNG được
    phép bị báo (nó và mọi điểm <= nó không bị gắn cờ); tau = điểm giữa anchor và giá trị val liền trên nó."""
    mb = np.sort(sess_max(score, P)[P.ys == 0])[::-1]
    if len(mb) == 0:
        return -math.inf, None
    k = int(math.floor(target * len(mb) + 1e-9))
    if k >= len(mb):
        return -math.inf, None
    anchor = float(mb[k])
    above = score[score > anchor]
    if len(above) == 0:                                   # không khả thi: không còn giá trị nào trên anchor
        return float(np.nextafter(anchor, math.inf)), anchor
    return float((anchor + above.min()) / 2.0), anchor


# ============================================================ luật tần suất kiểu Wazuh (mô phỏng)
def rule_counts(P, statuses, T):
    """Với alert i khớp statuses: số alert khớp trong [t_i - T, t_i] cùng phiên (gồm i); alert không khớp: 0.
    Tương tự luật frequency + if_matched_sid + same_srcip (mỗi phiên một srcip, cooldown IP 300 s > T)."""
    m = np.ones(len(P.tt), bool) if statuses is None else np.isin(P.status, statuses)
    cm = np.cumsum(m)
    j = np.searchsorted(P.tt, P.tt - T, side="left")
    cnt = cm - np.r_[0, cm][j]
    return np.where(m, cnt, 0)


def rule_fires(P, statuses, T, N):
    """Alert i có làm luật tần suất (rule cha khớp statuses, frequency=N, timeframe=T, same_srcip) KHỚP không, theo
    ngữ nghĩa ĐÃ ĐO trên Wazuh 4.14.7 (wazuh_sim.py): khớp ở sự kiện cha thứ N trong T giây, rồi N sự kiện đó bị tiêu
    thụ -> khớp ở N, 2N, ... (KHÔNG phải mọi alert có >= N trong cửa sổ); riêng N=2 khớp ở mọi sự kiện cha từ thứ 2
    (không tiêu thụ — mã nguồn + đo thật 26/10). Lần khớp ĐẦU của mỗi phiên trùng với
    rule_counts(...) >= N (nên phát hiện/báo nhầm phiên k=1 và TTD k=1 như cách đếm trượt); khác ở k=3 và theo alert.
    Phiên nối nhau trên P.tt với khoảng đệm T_OFFSET >> T nên trạng thái không lan giữa các phiên."""
    out = np.zeros(len(P.tt), bool)
    if N is None or N == math.inf:
        return out
    m = np.ones(len(P.tt), bool) if statuses is None else np.isin(P.status, statuses)
    idx = np.flatnonzero(m)
    f = W.freq_fires(P.tt[idx].tolist(), N, T)
    out[idx[np.asarray(f, bool)]] = True
    return out


def rule_flags(P, prm):
    f = np.zeros(len(P.tt), bool)
    for v, st in RULE_VARIANTS.items():
        f |= rule_fires(P, st, prm["T"], prm[v])
    return f


def fit_rule(Pva, target):
    """Tìm (T, N401, N403_404, Nany) trên val. f1: tối đa wF1; fp5: tối đa tỉ lệ phát hiện phiên với ràng buộc
    phiên benign báo nhầm <= target (hòa thì wF1 cao hơn)."""
    yw = Pva.w * Pva.y; nw = Pva.w * (1 - Pva.y); Ptot = yw.sum()
    att, ben = Pva.ys == 1, Pva.ys == 0
    best = {"f1": (-1, None), "fp5": ((-1, -1), None)}
    n_eval = 0
    for T in RULE_T:
        FL = [[rule_fires(Pva, st, T, N) for N in RULE_N] for st in RULE_VARIANTS.values()]
        for i, j, k in itertools.product(range(len(RULE_N)), repeat=3):
            f = FL[0][i] | FL[1][j] | FL[2][k]
            n_eval += 1
            tp = yw @ f; fp = nw @ f
            wf1 = 2 * tp / (tp + fp + Ptot) if tp > 0 else 0.0
            anyf = np.logical_or.reduceat(f, Pva.start)
            det, fpr = anyf[att].mean(), anyf[ben].mean()
            prm = {"T": T, "r401": RULE_N[i], "r403_404": RULE_N[j], "any": RULE_N[k]}
            if wf1 > best["f1"][0]:
                best["f1"] = (wf1, prm)
            if fpr <= target + 1e-12 and (det, wf1) > best["fp5"][0]:
                best["fp5"] = ((det, wf1), prm)
    return {"f1": best["f1"][1], "fp5": best["fp5"][1]}, n_eval


def fmt_rule(prm):
    parts = []
    for v, lab in (("r401", "401"), ("r403_404", "403/404"), ("any", "mọi mã")):
        if prm[v] != math.inf:
            parts.append(f"{lab} >= {prm[v]}")
    return f"T={prm['T']}s: " + (" HOẶC ".join(parts) if parts else "(tắt hết)")


# ============================================================ mô hình
class ScoreModel:
    kind = "score"

    def __init__(self, name, cols, est=None, single=None, params=None):
        self.name, self.cols, self.est, self.single, self.params = name, list(cols), est, single, params or {}
        self.tau = {}

    def score(self, P):
        if self.single is not None:
            c, sgn = self.single
            return np.round(sgn * P.df[c].to_numpy(float), SCORE_DECIMALS)
        return np.round(self.est.predict_proba(P.X(self.cols))[:, 1], SCORE_DECIMALS)

    def calibrate(self, Pva, target):
        s = self.score(Pva)
        self.tau["f1"], self.val_wf1 = tau_f1(s, Pva.y, Pva.w)
        self.tau["fp5"], self.fp5_anchor = tau_fp(s, Pva, target)
        # fp5 "không khả thi": ngưỡng cao hơn mọi điểm trên val (vd. RF cho 1.0 ở một phiên benign) -> không gắn cờ gì
        self.fp5_infeasible = bool((s >= self.tau["fp5"]).sum() == 0)
        return self

    def flags(self, P, op, score=None):
        s = self.score(P) if score is None else score
        return s >= self.tau[op]


class RuleModel:
    kind = "rule"

    def __init__(self, prm, n_eval):
        self.name, self.prm, self.n_eval, self.cols = "wazuh_rule", prm, n_eval, []
        self.tau = {op: None for op in OPS}

    def score(self, P):
        return None

    def flags(self, P, op, score=None):
        return rule_flags(P, self.prm[op])


def fit_est(kind, Ptr, cols, seed=0, n_estimators=200, n_jobs=-1, **hp):
    X, y, w = Ptr.X(cols), Ptr.y, Ptr.w
    if kind == "tree_d3":
        est = DecisionTreeClassifier(max_depth=3, random_state=seed)
    elif kind == "logreg":
        est = make_pipeline(FunctionTransformer(_log1p0), StandardScaler(),
                            LogisticRegression(C=hp.get("C", 1.0), max_iter=5000))
    elif kind == "rf":
        est = RandomForestClassifier(n_estimators=n_estimators, min_samples_leaf=hp.get("min_samples_leaf", 1),
                                     max_features="sqrt", random_state=seed, n_jobs=n_jobs)
    else:
        raise ValueError(kind)
    if kind == "logreg":
        est.fit(X, y, logisticregression__sample_weight=w)
    else:
        est.fit(X, y, sample_weight=w)
    return est


def fit_single(Ptr, cols):
    res = []
    for c in cols:
        x = Ptr.df[c].to_numpy(float)
        for sgn in (1, -1):
            tau, f1 = tau_f1(sgn * x, Ptr.y, Ptr.w)
            res.append((f1, c, sgn, tau))
    res.sort(key=lambda r: -r[0])
    return res


def fit_all(Ptr, Pva, cols, a, hp=None, seed=0):
    """Fit 5 mô hình trên Ptr, chọn siêu tham số + ngưỡng trên Pva. hp=None: tìm siêu tham số; ngược lại dùng lại."""
    models, info = OrderedDict(), {}
    prm, n_eval = fit_rule(Pva, a.fp_target)
    models["wazuh_rule"] = RuleModel(prm, n_eval)
    ranking = fit_single(Ptr, cols)
    _, c, sgn, _ = ranking[0]
    models["single_thr"] = ScoreModel("single_thr", cols, single=(c, sgn), params={"feature": c, "direction": ">=" if sgn > 0 else "<="}).calibrate(Pva, a.fp_target)
    info["single_ranking_train"] = [{"feature": r[1], "direction": ">=" if r[2] > 0 else "<=", "train_wf1": r[0]} for r in ranking[:6]]
    models["tree_d3"] = ScoreModel("tree_d3", cols, fit_est("tree_d3", Ptr, cols, seed)).calibrate(Pva, a.fp_target)
    sel = {}
    if hp is None:
        hp = {}
        for name, grid, key in (("logreg", LOGREG_C, "C"), ("rf", RF_LEAF, "min_samples_leaf")):
            scores = []
            for v in grid:
                m = ScoreModel(name, cols, fit_est(name, Ptr, cols, seed, a.n_estimators, a.n_jobs, **{key: v})).calibrate(Pva, a.fp_target)
                scores.append((m.val_wf1, v, m))
                log(f"    chọn {name} {key}={v}: val wF1={m.val_wf1:.4f}")
            best = max(scores, key=lambda r: r[0])
            hp[name] = {key: best[1]}
            sel[name] = [{"value": v, "val_wf1": s} for s, v, _ in scores]
            models[name] = best[2]
            models[name].params = dict(hp[name])
    else:
        for name in ("logreg", "rf"):
            models[name] = ScoreModel(name, cols, fit_est(name, Ptr, cols, seed, a.n_estimators, a.n_jobs, **hp[name]),
                                      params=dict(hp[name])).calibrate(Pva, a.fp_target)
    info["hp"], info["hp_search"] = hp, sel
    return models, info


# ============================================================ chỉ số
def sess_agg(P, flag):
    f = flag.astype(np.int64)
    yb = P.y == 1
    S = P.S
    g = {"nflag": np.bincount(P.code, weights=f, minlength=S),
         "wtp": np.bincount(P.code, weights=P.w * f * yb, minlength=S),
         "wfp": np.bincount(P.code, weights=P.w * f * (~yb), minlength=S),
         "wfn": np.bincount(P.code, weights=P.w * (1 - f) * yb, minlength=S)}
    cs = np.cumsum(f)
    base = np.r_[0, cs][P.start]
    within = cs - base[P.code]
    for k in KS:
        idx = np.nonzero((f == 1) & (within == k))[0]
        tk = np.full(S, np.nan); ak = np.full(S, np.nan)
        tk[P.code[idx]] = P.t[idx]; ak[P.code[idx]] = P.pos[idx] + 1
        g[f"t{k}"], g[f"a{k}"] = tk, ak
    return g


def _ratio(a, b):
    return float(a / b) if b else None


def _q(x, q):
    x = x[~np.isnan(x)]
    return float(np.quantile(x, q)) if len(x) else None


def summarize(P, flag, g, score=None):
    att, ben = P.ys == 1, P.ys == 0
    TP, FP, FN = g["wtp"].sum(), g["wfp"].sum(), g["wfn"].sum()
    tp = int((flag & (P.y == 1)).sum()); fp = int((flag & (P.y == 0)).sum()); fn = int((~flag & (P.y == 1)).sum())
    has_pos = bool((P.y == 1).any())
    r = {"n_alerts": int(len(P.y)), "n_sessions": int(P.S), "n_attack_sessions": int(att.sum()), "n_benign_sessions": int(ben.sum()),
         "w_precision": _ratio(TP, TP + FP) if has_pos else None, "w_recall": _ratio(TP, TP + FN),
         "w_f1": _ratio(2 * TP, 2 * TP + FP + FN) if (TP + FN) > 0 else None,
         "precision": _ratio(tp, tp + fp) if has_pos else None, "recall": _ratio(tp, tp + fn),
         "f1": _ratio(2 * tp, 2 * tp + fp + fn) if (tp + fn) > 0 else None}
    for k in KS:
        r[f"det_k{k}"] = float((g["nflag"][att] >= k).mean()) if att.any() else None
        r[f"fp_k{k}"] = float((g["nflag"][ben] >= k).mean()) if ben.any() else None
        r[f"ttd_k{k}_s_median"] = _q(g[f"t{k}"][att], .5) if att.any() else None
        r[f"ttd_k{k}_s_p90"] = _q(g[f"t{k}"][att], .9) if att.any() else None
        r[f"atd_k{k}_median"] = _q(g[f"a{k}"][att], .5) if att.any() else None
        r[f"atd_k{k}_p90"] = _q(g[f"a{k}"][att], .9) if att.any() else None
    r["benign_alert_flag_rate"] = float((g["nflag"][ben] / P.n[ben]).mean()) if ben.any() else None
    r["attack_alert_flag_rate"] = float((g["nflag"][att] / P.n[att]).mean()) if att.any() else None
    if score is not None and att.any() and ben.any():
        r["w_ap"] = float(average_precision_score(P.y, score, sample_weight=P.w))
        r["w_roc_auc"] = float(roc_auc_score(P.y, score, sample_weight=P.w))
    return r


def per_scenario(P, g):
    rows = []
    for scen, idx in P.sess.groupby("scenario").indices.items():
        idx = np.asarray(idx)
        lab = int(P.ys[idx[0]])
        r = {"scenario": scen, "family": P.sess["family"][idx[0]], "label": lab, "n_sessions": int(len(idx)),
             "alert_flag_rate": float((g["nflag"][idx] / P.n[idx]).mean())}
        for k in KS:
            r[f"rate_k{k}"] = float((g["nflag"][idx] >= k).mean())
        if lab == 1:
            for k in KS:   # chỉ trên phiên đã phát hiện; số phiên chưa phát hiện báo riêng
                r[f"n_detected_k{k}"] = int((g["nflag"][idx] >= k).sum())
                for q, nm in ((.5, "median"), (.9, "p90")):
                    r[f"ttd_k{k}_s_{nm}"] = _q(g[f"t{k}"][idx], q)
                    r[f"atd_k{k}_{nm}"] = _q(g[f"a{k}"][idx], q)
                r[f"ttd_k{k}_s_max"] = _q(g[f"t{k}"][idx], 1.0)
        rows.append(r)
    return rows


def boot_index(P, B, seed):
    rng = np.random.default_rng(seed)
    cols = []
    for _, idx in sorted(P.sess.groupby("scenario").indices.items()):
        idx = np.asarray(idx)
        cols.append(idx[rng.integers(0, len(idx), (B, len(idx)))])
    return np.concatenate(cols, 1) if cols else np.zeros((B, 0), int)


BOOT_KEYS = ("w_f1", "det_k1", "det_k3", "fp_k1", "fp_k3")


def boot_stats(P, g, I):
    ys = P.ys[I]
    att, ben = ys == 1, ys == 0
    TP, FP, FN = g["wtp"][I].sum(1), g["wfp"][I].sum(1), g["wfn"][I].sum(1)
    out = {}
    with np.errstate(invalid="ignore", divide="ignore"):
        out["w_f1"] = np.where(TP + FN > 0, 2 * TP / (2 * TP + FP + FN), np.nan)
        for k in KS:
            hit = g["nflag"][I] >= k
            out[f"det_k{k}"] = (hit & att).sum(1) / att.sum(1)
            out[f"fp_k{k}"] = (hit & ben).sum(1) / ben.sum(1)
    return out


def ci(x):
    x = np.asarray(x, float); x = x[~np.isnan(x)]
    return [float(np.percentile(x, 2.5)), float(np.percentile(x, 97.5))] if len(x) else None


# ============================================================ đánh giá
def evaluate(models, P, a, boot=True, keep=None):
    """Trả {model: {op: {...}}}; keep (dict) nhận flag/agg/score để dùng lại (paired bootstrap, xuất dự đoán)."""
    I = boot_index(P, a.n_boot, a.boot_seed) if (boot and a.n_boot > 0) else None
    res = OrderedDict()
    for name, m in models.items():
        sc = m.score(P)
        res[name] = OrderedDict()
        for op in OPS:
            fl = m.flags(P, op, sc)
            g = sess_agg(P, fl)
            r = summarize(P, fl, g, sc)
            r["by_scenario"] = per_scenario(P, g)
            if op == "fp5" and sc is not None and getattr(m, "fp5_anchor", None) is not None:
                # độ nhạy: hạ ngưỡng xuống đúng điểm của phiên benign val quyết định ngưỡng (gắn cờ cả giá trị trùng)
                g2 = sess_agg(P, sc >= m.fp5_anchor)
                att, ben = P.ys == 1, P.ys == 0
                r["tie_included"] = {"det_k1": float((g2["nflag"][att] >= 1).mean()) if att.any() else None,
                                     "fp_k1": float((g2["nflag"][ben] >= 1).mean()) if ben.any() else None}
            if I is not None:
                bs = boot_stats(P, g, I)
                r["ci95"] = {k: ci(bs[k]) for k in BOOT_KEYS}
                if keep is not None:
                    keep.setdefault("boot", {})[(name, op)] = bs
            if keep is not None:
                keep.setdefault("flags", {})[(name, op)] = fl
            res[name][op] = r
        if keep is not None and sc is not None:
            keep.setdefault("scores", {})[name] = sc
    return res


def paired_vs_rf(keep):
    out = {}
    if "boot" not in keep:
        return out
    for (name, op), bs in keep["boot"].items():
        if name == "rf":
            continue
        rf = keep["boot"].get(("rf", op))
        if rf is None:
            continue
        out.setdefault(name, {})[op] = {k: ci(rf[k] - bs[k]) for k in ("w_f1", "det_k1", "fp_k1")}
    return out


def perm_importance(est, P, cols, repeats, seed):
    X = P.X(cols)
    base = average_precision_score(P.y, est.predict_proba(X)[:, 1], sample_weight=P.w)
    rng = np.random.default_rng(seed)
    groups = OrderedDict((g, [c for c in cs if c in cols]) for g, cs in F.FEATURE_GROUPS.items())
    groups = OrderedDict((g, cs) for g, cs in groups.items() if cs)
    out = {"metric": "weighted average precision (val)", "base": float(base), "features": {}, "groups": {}}
    for kind, items in (("features", [(c, [c]) for c in cols]), ("groups", list(groups.items()))):
        for nm, cs in items:
            j = [cols.index(c) for c in cs]
            drops = []
            for _ in range(repeats):
                Xp = X.copy()
                perm = rng.permutation(len(X))
                Xp[:, j] = X[perm][:, j]
                drops.append(base - average_precision_score(P.y, est.predict_proba(Xp)[:, 1], sample_weight=P.w))
            out[kind][nm] = {"mean": float(np.mean(drops)), "sd": float(np.std(drops))}
    return out


def leave_out(parts, a, hp, models_main):
    tr, va, te = parts["train"], parts["val"], parts["test"]
    groups = [("family", f) for f in MAL_FAMILIES]
    for scen in sorted(set(tr.sess["scenario"])):
        fam = tr.sess.loc[tr.sess["scenario"] == scen, "family"].iloc[0]
        n_in_fam = tr.sess.loc[tr.sess["family"] == fam, "scenario"].nunique()
        if fam != "benign" and n_in_fam == 1:
            continue                                              # trùng với leave-family-out (vd. flood)
        groups.append(("scenario", scen))
    out = []
    for kind, val in groups:
        t0 = time.time()
        inm = lambda P: (P.sess[kind] == val).to_numpy()
        trp, vap = tr.subset(~inm(tr), "train-lo"), va.subset(~inm(va), "val-lo")
        held = Part(pd.concat([va.df[va.df[kind] == val], te.df[te.df[kind] == val]]), "held")
        tben = te.subset((~inm(te)) & (te.ys == 0), "test-benign")
        lab = int(held.ys[0])
        ms, _ = fit_all(trp, vap, models_main["rf"].cols, a, hp=hp)
        row = {"left_out": f"{kind}:{val}", "label": lab, "n_held_sessions": int(held.S),
               "held_scenarios": sorted(set(held.sess["scenario"])), "n_test_benign_sessions": int(tben.S),
               "models": OrderedDict()}
        Ih = boot_index(held, a.n_boot, a.boot_seed) if a.n_boot else None
        Ib = boot_index(tben, a.n_boot, a.boot_seed) if a.n_boot else None
        tref = te.subset(inm(te), "test-group")
        for name, m in ms.items():
            row["models"][name] = OrderedDict()
            sh, sb = m.score(held), m.score(tben)
            for op in OPS:
                gh, gb = sess_agg(held, m.flags(held, op, sh)), sess_agg(tben, m.flags(tben, op, sb))
                r = {}
                for k in KS:
                    r[f"held_rate_k{k}"] = float((gh["nflag"] >= k).mean())
                    r[f"test_benign_fp_k{k}"] = float((gb["nflag"] >= k).mean())
                r["held_alert_flag_rate"] = float((gh["nflag"] / held.n).mean())
                if lab == 1:
                    r["held_ttd_k1_s_median"] = _q(gh["t1"], .5)
                if Ih is not None:
                    bh, bb = boot_stats(held, gh, Ih), boot_stats(tben, gb, Ib)
                    key = "det_k1" if lab == 1 else "fp_k1"
                    r["ci95"] = {"held_rate_k1": ci(bh[key]), "test_benign_fp_k1": ci(bb["fp_k1"])}
                mm = models_main[name]                     # tham chiếu: mô hình chính (có thấy nhóm này khi train)
                gr = sess_agg(tref, mm.flags(tref, op))
                r["ref_main_test_rate_k1"] = float((gr["nflag"] >= 1).mean())
                r["fp5_infeasible"] = bool(getattr(m, "fp5_infeasible", False)) if op == "fp5" else False
                row["models"][name][op] = r
        log(f"  leave-out {kind}:{val}: RF f1 held={row['models']['rf']['f1']['held_rate_k1']:.2f} "
            f"(chính: {row['models']['rf']['f1']['ref_main_test_rate_k1']:.2f})  ({time.time() - t0:.0f}s)")
        out.append(row)
    return out


def ablation(parts, a, hp, main_keep):
    tr, va, te = parts["train"], parts["val"], parts["test"]
    sets = OrderedDict([("full_18", F.FEATURE_COLUMNS)])
    for g, cs in F.FEATURE_GROUPS.items():
        if g == "url":
            continue
        sets[f"no_url_minus_{g}"] = [c for c in F.NO_URL_COLUMNS if c not in cs]
    I = boot_index(te, a.n_boot, a.boot_seed) if a.n_boot else None
    out = OrderedDict()
    for nm, cols in sets.items():
        m = ScoreModel("rf", cols, fit_est("rf", tr, cols, 0, a.n_estimators, a.n_jobs, **hp["rf"])).calibrate(va, a.fp_target)
        sc = m.score(te)
        out[nm] = {"features": cols, "val_wf1": m.val_wf1, "fp5_infeasible": m.fp5_infeasible, "ops": {}}
        for op in OPS:
            fl = m.flags(te, op, sc); g = sess_agg(te, fl)
            r = summarize(te, fl, g, sc)
            r = {k: r[k] for k in ("w_f1", "w_ap", "det_k1", "fp_k1", "fp_k3", "ttd_k1_s_median")}
            if I is not None and ("boot" in main_keep):
                bs = boot_stats(te, g, I); base = main_keep["boot"][("rf", op)]
                r["diff_vs_main_ci95"] = {k: ci(bs[k] - base[k]) for k in ("w_f1", "det_k1", "fp_k1")}
            out[nm]["ops"][op] = r
        log(f"  ablation {nm}: test wF1(f1)={out[nm]['ops']['f1']['w_f1']:.4f}")
    return out


# ============================================================ báo cáo
def f3(x):
    return "—" if x is None else (f"{x:.3f}" if isinstance(x, float) else str(x))


def fci(v, c):
    return f3(v) + ("" if not c else f" [{c[0]:.3f}, {c[1]:.3f}]")


def fiv(c):
    return "—" if not c else f"[{c[0]:+.3f}, {c[1]:+.3f}]"


def fsec(x):
    return "—" if x is None else f"{x:.1f}"


def write_report(path, M):
    L = []
    d = M["dataset"]
    L += [f"# Báo cáo huấn luyện — {os.path.basename(d['path'])}", "",
          f"- Nơi chạy: **{M['run_label']}** ({M['env']['host']}, Python {M['env']['python']}, sklearn {M['env']['sklearn']}, "
          f"numpy {M['env']['numpy']}, pandas {M['env']['pandas']}); {M['created']}; {M['elapsed_s']:.0f} s",
          f"- Dataset sha256 `{d['sha256'][:16]}…`, {d['rows']} alert, {d['sessions']} phiên. "
          f"features.py: dataset `{d['audit'].get('features_sha_dataset')}` / code `{d['audit']['features_sha_code']}`",
          "- Dữ liệu: traffic do generator sinh (nhãn = ý định kịch bản), đi qua Apache + Wazuh thật; KHÔNG phải traffic người dùng thật.",
          f"- Đặc trưng chính ({len(M['features'])}): {', '.join(M['features'])}",
          f"- Ngưỡng `f1` = tối đa wF1 trên val; `fp5` = ≤ {M['fp_target']:.0%} phiên benign của val bị báo nhầm (k=1). "
          "k=1/k=3: phiên tính là phát hiện/báo nhầm khi có ≥ 1 / ≥ 3 alert vượt ngưỡng.",
          f"- CI 95%: bootstrap {M['n_boot']} lần theo phiên, phân tầng theo kịch bản (chỉ dao động do chọn phiên đánh giá).", ""]
    for w in d["audit"]["warnings"]:
        L.append(f"> CẢNH BÁO: {w}")
    L += ["", "## Số phiên / alert theo split", "", "| split | phiên benign | phiên tấn công | alert benign | alert tấn công |", "|---|---|---|---|---|"]
    for s, v in M["splits"].items():
        L.append(f"| {s} | {v['benign_sessions']} | {v['attack_sessions']} | {v['benign_alerts']} | {v['attack_alerts']} |")

    def main_table(res, title, with_ci=True):
        L.extend(["", f"## {title}", "",
                  "| mô hình | op | wF1 | wP | wR | F1 (alert) | wAP | phát hiện k1 | phát hiện k3 | báo nhầm k1 | báo nhầm k3 | alert benign bị gắn cờ | TTD k1 trung vị (s) | số alert đến phát hiện (trung vị) |",
                  "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"])
        for name, ops in res.items():
            for op, r in ops.items():
                c = r.get("ci95", {}) if with_ci else {}
                opn = op + (" (không khả thi)" if op == "fp5" and M["chosen"].get(name, {}).get("fp5_infeasible") else "")
                L.append(f"| {NAMES.get(name, name)} | {opn} | {fci(r['w_f1'], c.get('w_f1'))} | {f3(r['w_precision'])} | {f3(r['w_recall'])} | "
                         f"{f3(r['f1'])} | {f3(r.get('w_ap'))} | {fci(r['det_k1'], c.get('det_k1'))} | {fci(r['det_k3'], c.get('det_k3'))} | "
                         f"{fci(r['fp_k1'], c.get('fp_k1'))} | {fci(r['fp_k3'], c.get('fp_k3'))} | {f3(r['benign_alert_flag_rate'])} | "
                         f"{fsec(r['ttd_k1_s_median'])} | {f3(r['atd_k1_median'])} |")

    main_table(M["eval"]["test"], "Test (chỉ báo cáo)")
    L += ["", "### RF − baseline trên test (CI 95% của hiệu, bootstrap ghép cặp)", "", "| baseline | op | ΔwF1 | Δphát hiện k1 | Δbáo nhầm k1 |", "|---|---|---|---|---|"]
    for name, ops in M.get("paired_test", {}).items():
        for op, r in ops.items():
            L.append(f"| {NAMES.get(name, name)} | {op} | {fiv(r['w_f1'])} | {fiv(r['det_k1'])} | {fiv(r['fp_k1'])} |")
    L += ["", "### Độ nhạy ngưỡng fp5 (test)", "",
          "Ngưỡng fp5 nằm giữa điểm 'anchor' (điểm cao nhất của phiên benign val đầu tiên không được phép bị báo) và giá trị val "
          "liền trên. Nếu nhiều alert test có ĐÚNG điểm anchor (đặc trưng trùng nhau), chỉ cần hạ ngưỡng xuống anchor là chúng "
          "bị gắn cờ: cột 2 là kết quả khi gắn cờ cả giá trị anchor.", "",
          "| mô hình | báo nhầm k1 / phát hiện k1 tại ngưỡng | khi gắn cờ cả giá trị trùng |", "|---|---|---|"]
    for name, ops in M["eval"]["test"].items():
        t = ops["fp5"].get("tie_included")
        if t:
            L.append(f"| {NAMES.get(name, name)} | {f3(ops['fp5']['fp_k1'])} / {f3(ops['fp5']['det_k1'])} | {f3(t['fp_k1'])} / {f3(t['det_k1'])} |")
    L += ["", f"## Random Forest {len(M['rf_seeds'])} seed (test; ngưỡng chọn lại trên val cho từng seed)", "",
          "| op | chỉ số | trung bình | sd | min | max |", "|---|---|---|---|---|---|"]
    for op in OPS:
        for k in ("w_f1", "w_ap", "det_k1", "det_k3", "fp_k1", "fp_k3"):
            v = [s[op][k] for s in M["rf_seeds"] if s[op].get(k) is not None]
            if v:
                L.append(f"| {op} | {k} | {np.mean(v):.3f} | {np.std(v):.3f} | {min(v):.3f} | {max(v):.3f} |")
    L += ["", "## Theo kịch bản — test", "", "Tấn công: tỉ lệ phiên bị phát hiện; benign: tỉ lệ phiên bị báo nhầm.", ""]
    show = [n for n in ("wazuh_rule", "tree_d3", "logreg", "rf") if n in M["eval"]["test"]]
    hdr = "| kịch bản | nhãn | phiên | " + " | ".join(f"{n} {op} k1/k3" for n in show for op in OPS) + " | RF f1 TTD (s) |"
    L += [hdr, "|" + "---|" * (4 + 2 * len(show))]
    sc_rows = {n: {op: {r["scenario"]: r for r in M["eval"]["test"][n][op]["by_scenario"]} for op in OPS} for n in show}
    for r0 in sorted(M["eval"]["test"]["rf"]["f1"]["by_scenario"], key=lambda r: (r["label"], r["family"], r["scenario"])):
        s = r0["scenario"]
        cells = [f"{sc_rows[n][op][s]['rate_k1']:.2f}/{sc_rows[n][op][s]['rate_k3']:.2f}" for n in show for op in OPS]
        L.append(f"| {s} | {r0['label']} | {r0['n_sessions']} | " + " | ".join(cells) + f" | {fsec(r0.get('ttd_k1_s_median'))} |")

    def ttd_table(res, title):
        L.extend(["", f"### {title}", "",
                  "Thời gian (s, tính từ request đầu của phiên) và số alert (gồm alert phát hiện) đến lần phát hiện đầu (k=1) / "
                  "đến alert vượt ngưỡng thứ 3 (k=3); chỉ trên phiên đã phát hiện — cột 'phát hiện' cho biết bao nhiêu phiên.", "",
                  "| mô hình | op | kịch bản | phát hiện k1 | TTD k1 trung vị / p90 / max (s) | số alert k1 trung vị / p90 | phát hiện k3 | TTD k3 trung vị / p90 (s) | số alert k3 trung vị / p90 |",
                  "|---|---|---|---|---|---|---|---|---|"])
        for name in ("rf", "wazuh_rule", "logreg"):
            if name not in res:
                continue
            for op in OPS:
                for r in sorted(res[name][op]["by_scenario"], key=lambda r: (r["family"], r["scenario"])):
                    if r["label"] != 1:
                        continue
                    L.append(f"| {name} | {op} | {r['scenario']} | {r['n_detected_k1']}/{r['n_sessions']} | "
                             f"{fsec(r['ttd_k1_s_median'])} / {fsec(r['ttd_k1_s_p90'])} / {fsec(r['ttd_k1_s_max'])} | "
                             f"{f3(r['atd_k1_median'])} / {f3(r['atd_k1_p90'])} | {r['n_detected_k3']}/{r['n_sessions']} | "
                             f"{fsec(r['ttd_k3_s_median'])} / {fsec(r['ttd_k3_s_p90'])} | {f3(r['atd_k3_median'])} / {f3(r['atd_k3_p90'])} |")

    ttd_table(M["eval"]["test"], "Thời gian / số alert đến phát hiện theo kịch bản tấn công — test")
    for pname, res in M["eval"].items():
        if pname in ("test", "val"):
            continue
        main_table(res, f"Tập đánh giá riêng: {pname}")
        if any(r["label"] == 1 for r in res["rf"]["f1"]["by_scenario"]):
            ttd_table(res, f"Thời gian / số alert đến phát hiện — {pname}")
        L += ["", "| kịch bản | nhãn | phiên | " + " | ".join(f"{n} {op} k1/k3" for n in show for op in OPS) + " |", "|" + "---|" * (3 + 2 * len(show))]
        srows = {n: {op: {r["scenario"]: r for r in res[n][op]["by_scenario"]} for op in OPS} for n in show}
        for r0 in res["rf"]["f1"]["by_scenario"]:
            s = r0["scenario"]
            L.append(f"| {s} | {r0['label']} | {r0['n_sessions']} | " + " | ".join(f"{srows[n][op][s]['rate_k1']:.2f}/{srows[n][op][s]['rate_k3']:.2f}" for n in show for op in OPS) + " |")
    main_table(M["eval"]["val"], "Val (đã dùng để chọn tham số/ngưỡng — lạc quan, chỉ tham khảo)", with_ci=False)
    if M.get("leave_out"):
        L += ["", "## Leave-family-out / leave-scenario-out", "",
              "Bỏ nhóm khỏi train và val; đánh giá trên val+test của nhóm bị bỏ; báo nhầm benign chỉ tính trên benign của test. "
              "'chính' = mô hình train đủ, trên test của nhóm đó (tham chiếu).", "",
              "Cột 'nhóm bị bỏ': nhóm tấn công = tỉ lệ phiên bị phát hiện; kịch bản benign = tỉ lệ phiên bị báo nhầm.", "",
              "| bỏ | nhãn | số phiên nhóm | mô hình | f1: nhóm bị bỏ k1 [CI] / k3 | f1: chính k1 | f1: test benign báo nhầm k1 [CI] / k3 | fp5: nhóm bị bỏ k1 [CI] / k3 | fp5: chính k1 | fp5: test benign báo nhầm k1 [CI] / k3 |",
              "|---|---|---|---|---|---|---|---|---|---|"]
        for row in M["leave_out"]:
            for name in ("wazuh_rule", "tree_d3", "logreg", "rf"):
                cells = []
                for op in OPS:
                    r = row["models"][name][op]; c = r.get("ci95", {})
                    cells += [f"{fci(r['held_rate_k1'], c.get('held_rate_k1'))} / {f3(r['held_rate_k3'])}", f3(r["ref_main_test_rate_k1"]),
                              f"{fci(r['test_benign_fp_k1'], c.get('test_benign_fp_k1'))} / {f3(r['test_benign_fp_k3'])}"]
                if row["models"][name]["fp5"].get("fp5_infeasible"):
                    cells[3] += " (fp5 không khả thi)"
                L.append(f"| {row['left_out']} | {row['label']} | {row['n_held_sessions']} | {name} | " + " | ".join(cells) + " |")
    if M.get("ablation"):
        L += ["", "## Ablation bộ đặc trưng (RF seed 0, test)", "", "| bộ | số đặc trưng | op | wF1 | ΔwF1 vs chính [CI] | phát hiện k1 | báo nhầm k1 | báo nhầm k3 |", "|---|---|---|---|---|---|---|---|"]
        for nm, v in M["ablation"].items():
            for op, r in v["ops"].items():
                dci = (r.get("diff_vs_main_ci95") or {}).get("w_f1")
                opn = op + (" (không khả thi)" if op == "fp5" and v.get("fp5_infeasible") else "")
                L.append(f"| {nm} | {len(v['features'])} | {opn} | {f3(r['w_f1'])} | {fiv(dci)} | {f3(r['det_k1'])} | {f3(r['fp_k1'])} | {f3(r['fp_k3'])} |")
    if M.get("permutation_importance"):
        pi = M["permutation_importance"]
        L += ["", f"## Permutation importance (RF seed 0, {pi['metric']}, cơ sở {pi['base']:.4f})", "", "| đặc trưng / nhóm | giảm wAP (trung bình ± sd) |", "|---|---|"]
        for kind in ("groups", "features"):
            for nm, v in sorted(pi[kind].items(), key=lambda kv: -kv[1]["mean"]):
                L.append(f"| {'**nhóm** ' if kind == 'groups' else ''}{nm} | {v['mean']:.4f} ± {v['sd']:.4f} |")
    L += ["", "## Tham số đã chọn (trên val)", ""]
    for name, p in M["chosen"].items():
        L.append(f"- **{NAMES.get(name, name)}**: {p}")
    L += ["", "Ngưỡng đơn — xếp hạng trên train (wF1 tại ngưỡng tốt nhất của train):", ""]
    for r in M["single_ranking_train"]:
        L.append(f"- {r['feature']} {r['direction']}: {r['train_wf1']:.3f}")
    L += ["", "Cây độ sâu 3:", "", "```", M["tree_text"].rstrip(), "```", "",
          "## Giới hạn cần ghi khi trích dẫn", "",
          "- Luật kiểu Wazuh là mô phỏng offline (wazuh_sim.py) theo ngữ nghĩa đã đo bằng wazuh-logtest trên Wazuh 4.14.7 "
          "(scripts/wazuh_probe.py): khớp ở sự kiện cha thứ N trong cửa sổ [t−T, t], rồi N sự kiện đó bị tiêu thụ (khớp ở N, 2N, …). "
          "Alert được tính là bị gắn cờ khi nó làm luật khớp. Xấp xỉ còn lại: dùng giờ Apache thay giờ Manager (độ phân giải giây, "
          "trễ thường < 1 s); 3 luật OR được mô phỏng độc lập (Wazuh chỉ sinh một alert cho mỗi sự kiện).",
          "- Số phiên mỗi kịch bản ở test nhỏ → CI rộng; CI không gồm dao động do huấn luyện (xem bảng nhiều seed). "
          "Bootstrap phân tầng giữ nguyên cơ cấu kịch bản, nên CI có điều kiện theo tập kịch bản đã thiết kế.",
          "- fp5  'không khả thi' = trên val không có ngưỡng nào vừa giữ ≤ mục tiêu báo nhầm vừa gắn cờ được alert nào "
          "(vd. mô hình cho điểm tối đa ở một phiên benign); số phiên benign của val càng ít thì càng dễ gặp.",
          "- fp5 chọn từ điểm cao nhất của một số ít phiên benign trên val nên dao động mạnh; báo nhầm trên test có thể vượt mục tiêu.",
          "- Nhãn gán theo phiên cho mọi alert, kể cả vài alert đầu của phiên tấn công (chưa thể phân biệt) → chỉ số theo alert bị kéo xuống; "
          "đánh giá chính là theo phiên.",
          "- Nếu nhiều phiên benign dài, báo nhầm k=1 phụ thuộc độ dài phiên; xem thêm k=3 và tỉ lệ alert benign bị gắn cờ."]
    open(path, "w", encoding="utf-8").write("\n".join(L) + "\n")


def _json_default(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return None if not np.isfinite(o) else float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    return str(o)


def _clean(o):
    if isinstance(o, float):
        return None if not math.isfinite(o) else o
    if isinstance(o, dict):
        return {str(k): _clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_clean(v) for v in o]
    return o


# ============================================================ main
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data", required=True)
    ap.add_argument("--eval", nargs="*", default=[], help="dataset chỉ để đánh giá (shift, tools, ...)")
    ap.add_argument("--out", default=None, help="mặc định models/<tên dataset bỏ 'dataset_'>")
    ap.add_argument("--run-label", default="chưa ghi", help="vd. 'sandbox' hoặc 'máy thật' — ghi vào report")
    ap.add_argument("--fp-target", type=float, default=0.05)
    ap.add_argument("--seeds", type=int, default=5, help="số seed RF (seed 0 là mô hình lưu)")
    ap.add_argument("--n-estimators", type=int, default=200)
    ap.add_argument("--n-boot", type=int, default=1000)
    ap.add_argument("--boot-seed", type=int, default=12345)
    ap.add_argument("--perm-repeats", type=int, default=5)
    ap.add_argument("--n-jobs", type=int, default=-1)
    ap.add_argument("--no-leaveout", action="store_true")
    ap.add_argument("--no-ablation", action="store_true")
    a = ap.parse_args(argv)
    warnings.filterwarnings("ignore", category=UserWarning)
    t_start = time.time()
    stem = os.path.splitext(os.path.basename(a.data))[0]
    out = a.out or os.path.join(HERE, "..", "models", stem.replace("dataset_", ""))
    os.makedirs(out, exist_ok=True)

    df = load_dataset(a.data)
    audit = check_audit(a.data)
    for w in audit["warnings"]:
        log("CẢNH BÁO:", w)
    for s in MAIN_SPLITS:
        sub = df[df["split"] == s]
        if sub.empty or sub["label"].nunique() < 2:
            raise SystemExit(f"split '{s}' phải có cả benign và tấn công")
    parts = {s: Part(df[df["split"] == s], s) for s in MAIN_SPLITS}
    eval_parts = OrderedDict((s, Part(df[df["split"] == s], s)) for s in sorted(set(df["split"]) - set(MAIN_SPLITS)))
    main_keys = set(df["session_key"])
    for p in a.eval:
        e = load_dataset(p)
        ov = main_keys & set(e["session_key"])
        if ov:
            raise SystemExit(f"{p}: {len(ov)} phiên trùng với dataset chính (vd. {sorted(ov)[:3]})")
        est = os.path.splitext(os.path.basename(p))[0].replace("dataset_", "")
        for s in sorted(set(e["split"])):
            eval_parts[f"{est}:{s}"] = Part(e[e["split"] == s], f"{est}:{s}")
    splits = OrderedDict()
    for nm, P in list(parts.items()) + list(eval_parts.items()):
        splits[nm] = {"benign_sessions": int((P.ys == 0).sum()), "attack_sessions": int((P.ys == 1).sum()),
                      "benign_alerts": int((P.y == 0).sum()), "attack_alerts": int((P.y == 1).sum())}
    log(f"dataset {a.data}: {len(df)} alert, {df['session_key'].nunique()} phiên; " +
        "; ".join(f"{k}: {v['benign_sessions']}b/{v['attack_sessions']}m phiên" for k, v in splits.items()))

    cols = list(F.NO_URL_COLUMNS)
    tr, va, te = parts["train"], parts["val"], parts["test"]
    log("[1] fit + chọn tham số/ngưỡng trên val")
    models, info = fit_all(tr, va, cols, a)
    hp = info["hp"]

    log("[2] đánh giá")
    keep = {}
    ev = OrderedDict()
    ev["test"] = evaluate(models, te, a, keep=keep)
    ev["val"] = evaluate(models, va, a, boot=False)
    for nm, P in eval_parts.items():
        ev[nm] = evaluate(models, P, a)
    paired = paired_vs_rf(keep)
    for name in models:
        r = ev["test"][name]
        log(f"  test {name:10s} f1: wF1={f3(r['f1']['w_f1'])} det={f3(r['f1']['det_k1'])} fp={f3(r['f1']['fp_k1'])}/{f3(r['f1']['fp_k3'])} | "
            f"fp5: det={f3(r['fp5']['det_k1'])} fp={f3(r['fp5']['fp_k1'])}/{f3(r['fp5']['fp_k3'])}")

    log(f"[3] RF {a.seeds} seed")
    rf_seeds = []
    for s in range(a.seeds):
        m = models["rf"] if s == 0 else ScoreModel("rf", cols, fit_est("rf", tr, cols, s, a.n_estimators, a.n_jobs, **hp["rf"])).calibrate(va, a.fp_target)
        sc = m.score(te)
        row = {"seed": s, "tau": dict(m.tau)}
        for op in OPS:
            fl = m.flags(te, op, sc)
            r = summarize(te, fl, sess_agg(te, fl), sc)
            row[op] = {k: r[k] for k in ("w_f1", "w_ap", "det_k1", "det_k3", "fp_k1", "fp_k3", "ttd_k1_s_median")}
        rf_seeds.append(row)
        log(f"  seed {s}: wF1(f1)={row['f1']['w_f1']:.4f} det/fp(fp5)={row['fp5']['det_k1']:.3f}/{row['fp5']['fp_k1']:.3f}")

    log("[4] permutation importance (val)")
    pi = perm_importance(models["rf"].est, va, cols, a.perm_repeats, 7) if a.perm_repeats > 0 else None
    abl = None
    if not a.no_ablation:
        log("[5] ablation")
        abl = ablation(parts, a, hp, keep)
    lo = None
    if not a.no_leaveout:
        log("[6] leave-out")
        lo = leave_out(parts, a, hp, models)

    chosen = OrderedDict()
    chosen["wazuh_rule"] = {op: fmt_rule(models["wazuh_rule"].prm[op]) for op in OPS}
    chosen["single_thr"] = {"feature": models["single_thr"].params["feature"], "direction": models["single_thr"].params["direction"],
                            "tau": {op: (models["single_thr"].tau[op] * (1 if models["single_thr"].params["direction"] == ">=" else -1)) for op in OPS}}
    chosen["single_thr"]["fp5_infeasible"] = models["single_thr"].fp5_infeasible
    for n in ("tree_d3", "logreg", "rf"):
        chosen[n] = {"params": models[n].params, "tau": dict(models[n].tau), "fp5_infeasible": models[n].fp5_infeasible}
    env = {"python": platform.python_version(), "sklearn": sklearn.__version__, "numpy": np.__version__, "pandas": pd.__version__,
           "host": platform.node(), "platform": platform.platform()}
    dsha = sha256_file(a.data)
    M = OrderedDict(format=FORMAT, created=time.strftime("%Y-%m-%dT%H:%M:%S%z"), run_label=a.run_label, env=env,
                    args=vars(a), elapsed_s=time.time() - t_start, fp_target=a.fp_target, n_boot=a.n_boot,
                    dataset={"path": a.data, "sha256": dsha, "rows": int(len(df)), "sessions": int(df["session_key"].nunique()),
                             "audit": audit, "eval_files": a.eval},
                    splits=splits, features=cols, chosen=chosen, hp_search=info["hp_search"],
                    single_ranking_train=info["single_ranking_train"],
                    tree_text=export_text(models["tree_d3"].est, feature_names=cols, decimals=3),
                    logreg_coef=dict(zip(cols, models["logreg"].est[-1].coef_[0].round(4).tolist())),
                    eval=ev, paired_test=paired, rf_seeds=rf_seeds, permutation_importance=pi, ablation=abl, leave_out=lo)
    M["elapsed_s"] = time.time() - t_start

    # ---- lưu
    import joblib
    rf = models["rf"]
    # mô hình lưu nhận ĐÚNG 15 cột NO_URL_COLUMNS theo đúng thứ tự (fit bằng ma trận numpy: thứ tự cột = danh sách này)
    assert rf.cols == cols == list(F.NO_URL_COLUMNS) and rf.est.n_features_in_ == len(cols) == 15, \
        f"mô hình lưu không nhận đúng 15 cột NO_URL_COLUMNS: {rf.cols} / {rf.est.n_features_in_}"
    assert not set(cols) & set(F.FEATURE_GROUPS["url"])
    bundle = {"format": FORMAT, "model": rf.est, "features": cols, "n_features_in": int(rf.est.n_features_in_),
              "thresholds": dict(rf.tau), "fp5_anchor": rf.fp5_anchor, "fp_target": a.fp_target,
              "score": f"round(predict_proba[:,1], {SCORE_DECIMALS}) >= threshold", "score_decimals": SCORE_DECIMALS, "positive_label": 1, "window_s": F.WINDOW, "seed": 0,
              "hyperparams": dict(hp["rf"], n_estimators=a.n_estimators, max_features="sqrt"),
              "dataset": {"path": a.data, "sha256": dsha, "features_sha_dataset": audit["features_sha_dataset"],
                          "features_sha_code": audit["features_sha_code"], "rows": int(len(df))},
              "baselines": {"wazuh_rule": models["wazuh_rule"].prm}, "versions": env, "created": M["created"]}
    joblib.dump(bundle, os.path.join(out, "model.joblib"))
    json.dump(_clean(M), open(os.path.join(out, "metrics.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False, default=_json_default)
    pred = te.df[["session_key", "scenario", "family", "label", "event_epoch", "t_rel", "status", "url"]].copy() if "url" in te.df else \
        te.df[["session_key", "scenario", "family", "label", "event_epoch", "t_rel", "status"]].copy()
    pred.insert(4, "pos", te.pos)
    for name in models:
        if name in keep.get("scores", {}):
            pred[f"score_{name}"] = keep["scores"][name]
        for op in OPS:
            pred[f"flag_{name}_{op}"] = keep["flags"][(name, op)].astype(int)
    pred.to_csv(os.path.join(out, "test_predictions.csv"), index=False)
    write_report(os.path.join(out, "report.md"), M)
    log(f"xong ({M['elapsed_s']:.0f}s) -> {out}/ model.joblib metrics.json report.md test_predictions.csv")
    return M


if __name__ == "__main__":
    main()
