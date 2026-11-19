#!/usr/bin/env python3
"""dryrun_gauge.py — ĐỒNG HỒ ĐO ĐỘ KHÓ trước khi tốn giờ sinh traffic thật.

Không cần Docker/Apache: chạy các kịch bản qua mô hình site (site_model.status_of), tính đặc trưng bằng
đúng features.py, rồi so ngưỡng đơn / cây nông / hồi quy logistic / RF. Mục đích: kiểm tra generator có tạo
vùng chồng lấn thật (benign giống malicious ở từng đặc trưng) hay lại dễ như v9.

  python3 scripts/dryrun_gauge.py [--seed 0] [--train 10 --val 3 --test 5 --shift 5]

CẢNH BÁO: đây là kết quả trên dữ liệu MÔ PHỎNG của chính generator, không phải trên log Apache/Wazuh thật.
Chỉ dùng để tinh chỉnh thiết kế; không đưa vào báo cáo như kết quả đánh giá mô hình.
"""
import argparse, os, sys, warnings
warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np, pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

import features as F
import scenarios as SC
import site_model as S


def build(counts, seed):
    rows, idx = [], 0
    for split, (n, shift) in counts.items():
        names = SC.STRESS if split.startswith("stress") else SC.BENIGN + SC.MALICIOUS
        for name in names:
            for k in range(n):
                s = SC.build_session(name, seed, split, k, shift)
                for q in s["reqs"]:
                    rows.append(dict(srcip=f"sim{idx}", event_epoch=1.8e9 + idx * 1000 + q.t, url=q.url,
                                     status=S.status_of(q.url, q.cred), scenario=name, family=s["family"],
                                     label=s["label"], split=split, run_id=s["run_id"]))
                idx += 1
    df = pd.DataFrame(F.enrich(rows))
    df["w"] = 1.0 / df.groupby("run_id")["label"].transform("size")
    return df


def sf1(d, p): return f1_score(d.label, p, sample_weight=d.w)


def sess(d, p):
    d = d.assign(p=p)
    m = d[d.label == 1].groupby("run_id").p.max().mean()
    b = d[d.label == 0].groupby("run_id").p.max().mean()
    return m, b


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", default="0")
    ap.add_argument("--train", type=int, default=10); ap.add_argument("--val", type=int, default=3)
    ap.add_argument("--test", type=int, default=5); ap.add_argument("--shift", type=int, default=5)
    a = ap.parse_args()
    df = build({"train": (a.train, False), "val": (a.val, False), "test": (a.test, False), "shift": (a.shift, True),
                "stress": (4, False), "stress_shift": (4, True)}, a.seed)
    tr, va, te, sh = (df[df.split == s] for s in ("train", "val", "test", "shift"))
    st = df[df.split.isin(["stress", "stress_shift"])]
    print(f"[DRY-RUN, mô phỏng] {len(df)} sự kiện, {df.run_id.nunique()} phiên; "
          f"alert malicious/tổng ở train = {tr.label.mean():.2f}")
    print("\nA. Ngưỡng đơn tốt nhất (chọn trên val)  F1 cân bằng theo phiên: val | test | shift")
    best = []
    for f in F.FEATURE_COLUMNS:
        m = DecisionTreeClassifier(max_depth=1, random_state=0).fit(tr[[f]], tr.label)
        best.append((sf1(va, m.predict(va[[f]])), f, m))
    best.sort(key=lambda x: -x[0])
    for v, f, m in best[:3]:
        print(f"   {f:16s} {v:.3f} | {sf1(te, m.predict(te[[f]])):.3f} | {sf1(sh, m.predict(sh[[f]])):.3f}")
    print("\nB. Mô hình x bộ đặc trưng — test | shift | (shift) phiên tấn công bị bắt / phiên benign có >=1 FP | stress FP phiên")
    models = {"Tree d=3": lambda: DecisionTreeClassifier(max_depth=3, random_state=0),
              "LogReg": lambda: make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000)),
              "RF-200": lambda: RandomForestClassifier(200, random_state=42, n_jobs=-1)}
    for nm, cols in (("không URL", F.NO_URL_COLUMNS), ("đầy đủ", F.FEATURE_COLUMNS)):
        for mn, mk in models.items():
            m = mk().fit(tr[cols], tr.label)
            ps = m.predict(sh[cols]); det, fp = sess(sh, ps)
            _, sfp = sess(st, m.predict(st[cols]))
            print(f"   {nm:10s} {mn:9s} {sf1(te, m.predict(te[cols])):.3f} | {sf1(sh, ps):.3f} | {det:.2f} / {fp:.2f} | {sfp:.2f}")
    print("\nC. Bỏ nguyên một HỌ tấn công khỏi train, đo recall trên họ đó (đặc trưng không URL)")
    pool = df[df.split.isin(["train", "val", "test"])]
    for fam in ("recon", "cred", "flood"):
        row = {}
        for mn in ("Tree d=3", "RF-200"):
            m = models[mn]().fit(pool[pool.family != fam][F.NO_URL_COLUMNS], pool[pool.family != fam].label)
            t = pool[pool.family == fam]
            row[mn] = round(float((m.predict(t[F.NO_URL_COLUMNS]) == 1).mean()), 2)
        print(f"   bỏ họ {fam:6s}: {row}")
    print("\nĐọc kết quả: nếu ngưỡng đơn tốt nhất ở A đã ~0.99 thì generator vẫn quá dễ (như v9: 0.98 chỉ với mean_interval).")


if __name__ == "__main__":
    main()
