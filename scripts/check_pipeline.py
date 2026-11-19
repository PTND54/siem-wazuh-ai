#!/usr/bin/env python3
"""Kiểm tra pipeline theo từng chặng, KHÔNG cần Wazuh/Redis/indexer (chỉ đọc file đã có).

  python3 scripts/check_pipeline.py                     # mọi chặng, mặc định data/runs/*, data/dataset_*.csv, models/full1
  python3 scripts/check_pipeline.py --stage features --data data/dataset_tools2.csv

Chặng:
  runs      sessions.jsonl: phiên lỗi / trễ lịch / hai phiên dùng chung srcip chồng thời gian (nhãn mơ hồ)
  datasets  dataset_*.csv + .audit.json: số dòng, phiên mồ côi/bị loại, nhãn nhất quán trong phiên, features.py chưa đổi,
            không phiên nào nằm ở hai dataset
  requests  đối chiếu TỪNG dòng dataset với request generator đã gửi (data/runs/<batch>/requests/<run_id>.jsonl):
            multiset (method, url, mã) trùng, |Δt| Apache − lúc gửi nhỏ; srcip/kịch bản/nhãn/split/thời gian khớp
            manifest (công cụ thật: không có request log -> chỉ kiểm manifest)
  features  tính lại 18 đặc trưng từ (srcip, thời gian, url, mã) của CSV bằng features.enrich, so với cột trong CSV
  model     model.joblib/metrics.json/test_predictions.csv: chấm lại test bằng model.joblib, tính lại wF1/phát hiện/báo nhầm
            độc lập từ cờ, ngưỡng lưu == ngưỡng báo cáo, đúng 15 cột
  replay    phát lại dataset huấn luyện qua ai_service (MemoryStore + FileSink, có xáo trộn thứ tự < 0,9 s):
            đặc trưng và điểm online phải trùng offline
  live      (cần indexer; KHÔNG chạy mặc định) so tài liệu ai-service đã ghi vào ai-enriched-alerts-* với dataset dựng
            offline từ cùng batch: mỗi alert có đúng một tài liệu, đặc trưng + điểm + cờ trùng
            vd: --stage live --data data/dataset_smokeai1.csv
Chặng 2 (siem.log -> alerts.json) cần file log thật: dùng audit_coverage.py (xem README).
Mã thoát 1 nếu có [LỖI].
"""
import argparse, glob, hashlib, json, os, random, sys, tempfile, time
from collections import Counter, defaultdict

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import features as F  # noqa: E402

N_ERR = 0


def ok(m): print(f"  [OK]      {m}")
def warn(m): print(f"  [CẢNH BÁO] {m}")
def err(m):
    global N_ERR
    N_ERR += 1
    print(f"  [LỖI]     {m}")


def sha16(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()[:16]


def read_csv(p):
    return pd.read_csv(p, low_memory=False, float_precision="round_trip")


# ------------------------------------------------------------------ 1. runs
def stage_runs(paths, max_lag):
    print("\n== 1. Sinh dữ liệu (sessions.jsonl) ==")
    allrows = []
    for p in paths:
        rows = [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]
        name = os.path.basename(os.path.dirname(p))
        failed = [r["run_id"] for r in rows if r.get("failed") or r.get("status") not in (None, "done", "ok", "timeout")]
        # công cụ thật: nikto trả exit 1 khi có phát hiện; dirb_slow bị cắt theo thời gian (timeout) — có chủ đích
        odd = [f"{r['run_id']}({r.get('status')},exit={r.get('exit')})" for r in rows
               if r["run_id"] not in failed and (r.get("status") == "timeout" or r.get("exit") not in (None, 0))]
        if odd: warn(f"{name}: công cụ kết thúc bất thường (thường là bình thường: nikto exit 1, dirb_slow timeout): {odd}")
        lag = [r["run_id"] for r in rows if (r.get("max_lag") or 0) > max_lag]
        notime = [r["run_id"] for r in rows if r.get("t_first") is None]
        msg = f"{name}: {len(rows)} phiên, nhãn {dict(Counter(r.get('label') for r in rows))}"
        (err if failed else ok)(msg + (f"; LỖI/không xong: {failed[:5]}" if failed else ""))
        if lag: warn(f"{name}: {len(lag)} phiên trễ lịch > {max_lag}s (build_dataset sẽ loại): {lag[:5]}")
        if notime: warn(f"{name}: {len(notime)} phiên không có t_first/t_last: {notime[:5]}")
        allrows += [dict(r, _batch=name) for r in rows if r.get("t_first") is not None]
    by_ip = defaultdict(list)
    for r in allrows: by_ip[r["srcip"]].append(r)
    clash = []
    for ip, rs in by_ip.items():
        rs.sort(key=lambda r: r["t_first"])
        for a, b in zip(rs, rs[1:]):
            if b["t_first"] - a["t_last"] < F.WINDOW:      # cửa sổ 60 s của phiên sau còn thấy phiên trước
                clash.append((ip, a["run_id"], b["run_id"], round(b["t_first"] - a["t_last"], 1)))
    (err if clash else ok)(f"srcip dùng lại cách nhau < {F.WINDOW:.0f}s (đặc trưng/nhãn lẫn giữa hai phiên): {len(clash)}"
                          + (f" {clash[:3]}" if clash else ""))


# ------------------------------------------------------------------ 3. datasets
def stage_datasets(paths):
    print("\n== 3. Gán nhãn / dataset ==")
    code_sha = sha16(os.path.join(HERE, "features.py"))
    owner = {}
    for p in paths:
        name = os.path.basename(p)
        df = read_csv(p)
        ap = os.path.splitext(p)[0] + ".audit.json"
        au = json.load(open(ap, encoding="utf-8")) if os.path.exists(ap) else None
        if au is None:
            err(f"{name}: thiếu {os.path.basename(ap)}"); continue
        (ok if au.get("n_rows") == len(df) else err)(f"{name}: {len(df)} dòng (audit ghi {au.get('n_rows')}), "
                                                     f"{df.session_key.nunique()} phiên, giữ {au.get('n_sessions_kept')}")
        orph, exc = au.get("orphans") or [], au.get("excluded_sessions") or []
        if isinstance(exc, dict): exc = [f"{k}:{v}" for k, v in exc.items()]
        if isinstance(orph, dict): orph = list(orph)
        (warn if orph else ok)(f"{name}: phiên mồ côi (có trong sessions.jsonl nhưng không có alert) = {len(orph)}")
        (warn if exc else ok)(f"{name}: phiên bị loại (coverage/failed/lag) = {len(exc)}"
                              + (f" {[e if isinstance(e, str) else e.get('run_id', e) for e in exc[:3]]}" if exc else ""))
        ex = au.get("excluded") or {}
        if ex.get("unknown_in_range"):
            warn(f"{name}: {ex['unknown_in_range']} alert trong khoảng thời gian batch nhưng không thuộc phiên nào (traffic lạ?)")
        cov = (au.get("coverage_min"), au.get("coverage_max"))
        if cov[0] is not None:
            (ok if 0.98 <= cov[0] and cov[1] <= 1.02 else err)(f"{name}: coverage phiên min/max = {cov[0]:.4f}/{cov[1]:.4f}")
        (ok if au.get("features_sha") == code_sha else err)(
            f"{name}: features_sha lúc dựng {au.get('features_sha')} vs features.py hiện tại {code_sha}")
        multi = [c for c in ("label", "scenario", "family", "split", "srcip") if (df.groupby("session_key")[c].nunique() > 1).any()]
        (err if multi else ok)(f"{name}: mỗi phiên một nhãn/kịch bản/split/srcip" + (f" — LỆCH ở {multi}" if multi else ""))
        bad = df[(df.family == "benign") != (df.label == 0)].session_key.unique()
        (err if len(bad) else ok)(f"{name}: family 'benign' <=> label 0" + (f" — lệch {list(bad[:3])}" if len(bad) else ""))
        miss = [c for c in F.FEATURE_COLUMNS if c not in df.columns]
        (err if miss else ok)(f"{name}: đủ 18 cột đặc trưng, không rỗng" if not miss and not df[F.FEATURE_COLUMNS].isna().any().any()
                              else f"{name}: thiếu/rỗng cột đặc trưng {miss}")
        for k in df.session_key.unique():
            if k in owner: err(f"phiên {k} có ở cả {owner[k]} và {name}")
            owner[k] = name
    ok(f"tổng {len(owner)} phiên qua {len(paths)} dataset (phiên trùng giữa các dataset nếu có đã báo [LỖI] ở trên)")


# ------------------------------------------------------------------ 3b. requests
def stage_requests(paths, max_dt):
    print("\n== 3b. Dòng dataset <-> request generator đã gửi (đúng phiên?) ==")
    for p in paths:
        name = os.path.basename(p)
        df = read_csv(p)
        probs, dts, nmatch, nlog = [], [], 0, 0
        mans = {}
        for (batch, run_id), g in df.groupby(["batch", "run_id"], sort=False):
            bdir = batch if os.path.isdir(f"data/runs/{batch}") else name[len("dataset_"):-len(".csv")]
            if bdir not in mans:
                mp = f"data/runs/{bdir}/sessions.jsonl"
                mans[bdir] = {r["run_id"]: r for r in map(json.loads, open(mp, encoding="utf-8"))} if os.path.exists(mp) else {}
            m = mans[bdir].get(run_id)
            if m is None:
                probs.append(f"{run_id}: không có trong data/runs/{bdir}/sessions.jsonl"); continue
            if g.session_key.iloc[0] != f"{batch}/{run_id}": probs.append(f"{run_id}: session_key {g.session_key.iloc[0]}")
            for c in ("srcip", "scenario", "label", "split"):
                if str(g[c].iloc[0]) != str(m.get(c)): probs.append(f"{run_id}: {c} {g[c].iloc[0]} != manifest {m.get(c)}")
            lo, hi = g.event_epoch.min(), g.event_epoch.max()
            if lo < m["t_first"] - 2 or hi > m["t_last"] + 2:
                probs.append(f"{run_id}: thời gian [{lo:.1f}, {hi:.1f}] ngoài phiên [{m['t_first']:.1f}, {m['t_last']:.1f}]")
            rq = f"data/runs/{bdir}/requests/{run_id}.jsonl"
            if not os.path.exists(rq): continue
            nlog += 1
            ka, kd = defaultdict(list), defaultdict(list)
            for r in map(json.loads, open(rq, encoding="utf-8")):
                if r.get("status") is not None and not r.get("err"): ka[(r["m"], r["url"], int(r["status"]))].append(r["t_sent"])
            for k in zip(g.method, g.url, g.status.astype(int), g.event_epoch): kd[k[:3]].append(k[3])
            ca, cd = Counter({k: len(v) for k, v in ka.items()}), Counter({k: len(v) for k, v in kd.items()})
            if ca != cd:
                probs.append(f"{run_id}: request đã gửi != dòng dataset (thiếu {sum((ca - cd).values())}, thừa {sum((cd - ca).values())})"); continue
            d = np.concatenate([np.sort(kd[k]) - np.sort(ka[k]) for k in ka]) if ka else np.zeros(0)
            if len(d) and np.abs(d).max() > max_dt: probs.append(f"{run_id}: |Δt| tối đa {np.abs(d).max():.2f}s > {max_dt}s")
            dts.append(d); nmatch += 1
        D = np.concatenate(dts) if dts else np.zeros(1)
        (err if probs else ok)(f"{name}: {df.run_id.nunique()} phiên khớp manifest; {nmatch}/{nlog} phiên có request log khớp từng request"
                               + (f", Δt trung vị {np.median(D)*1e3:.1f} ms, max {np.abs(D).max()*1e3:.1f} ms" if nlog else " (công cụ thật: không có request log)")
                               + (f" — {len(probs)} vấn đề: {probs[:4]}" if probs else ""))


# ------------------------------------------------------------------ 4. features
def stage_features(paths, tol):
    print("\n== 4. Đặc trưng: tính lại từ CSV bằng features.enrich ==")
    for p in paths:
        name = os.path.basename(p)
        df = read_csv(p)
        t0 = time.time()
        ev = df[["srcip", "event_epoch", "url", "status"]].to_dict("records")
        re = pd.DataFrame(F.enrich(ev))[F.FEATURE_COLUMNS].to_numpy(float)
        cs = df[F.FEATURE_COLUMNS].to_numpy(float)
        d = np.abs(re - cs)
        nbad = int((d > tol).sum())
        cols = [c for c, n in zip(F.FEATURE_COLUMNS, (d > tol).sum(0)) if n]
        msg = f"{name}: {len(df)} dòng, max|Δ| = {d.max():.2e}, ô lệch > {tol:g}: {nbad}" + (f" ở {cols}" if cols else "") + f" ({time.time()-t0:.0f}s)"
        # lệch nhỏ có thể do alert cùng srcip bị loại khỏi CSV (ngoài batch / phiên bị loại) nhưng vẫn nằm trong cửa sổ 60 s lúc dựng
        (ok if nbad == 0 else warn if nbad < 1e-3 * d.size else err)(msg)


# ------------------------------------------------------------------ 5. model
def stage_model(mdir, data_override):
    print(f"\n== 5. Mô hình / báo cáo ({mdir}) ==")
    import joblib
    B = joblib.load(os.path.join(mdir, "model.joblib"))
    M = json.load(open(os.path.join(mdir, "metrics.json"), encoding="utf-8"))
    pr = pd.read_csv(os.path.join(mdir, "test_predictions.csv"), float_precision="round_trip")
    cols = B["features"]
    (ok if cols == list(F.NO_URL_COLUMNS) and B["n_features_in"] == B["model"].n_features_in_ == 15 else err)(
        f"model nhận {B['model'].n_features_in_} cột, == NO_URL_COLUMNS: {cols == list(F.NO_URL_COLUMNS)}")
    code_sha = sha16(os.path.join(HERE, "features.py"))
    ds = B.get("dataset") or {}
    (ok if ds.get("features_sha_dataset") == code_sha else err)(f"features.py lúc dựng dataset train {ds.get('features_sha_dataset')} vs hiện tại {code_sha}")
    (ok if B["thresholds"] == M["chosen"]["rf"]["tau"] else err)(f"ngưỡng trong model.joblib == metrics.json: {B['thresholds']}")
    data = data_override or ds.get("path")
    if data and os.path.exists(data):
        dsha = hashlib.sha256(open(data, "rb").read()).hexdigest()
        (ok if dsha == ds.get("sha256") else err)(f"{data}: sha256 khớp dataset đã train" if dsha == ds.get("sha256") else f"{data}: sha256 KHÁC dataset đã train")
        df = read_csv(data)
        te = df[df.split.astype(str) == "test"].sort_values(["session_key", "event_epoch"], kind="mergesort").reset_index(drop=True)
        if len(te) != len(pr) or (te.session_key.to_numpy() != pr.session_key.to_numpy()).any():
            err(f"hàng test của dataset ({len(te)}) không khớp test_predictions ({len(pr)})")
        else:
            sc = np.round(B["model"].predict_proba(te[cols].to_numpy(float))[:, 1], B["score_decimals"])
            d = np.abs(sc - pr.score_rf.to_numpy())
            fl = {op: int(((sc >= B["thresholds"][op]).astype(int) != pr[f"flag_rf_{op}"].to_numpy()).sum()) for op in ("f1", "fp5")}
            (ok if d.max() <= 1e-9 and not any(fl.values()) else err)(
                f"chấm lại {len(te)} alert test bằng model.joblib: max|Δ điểm| = {d.max():.1e}, cờ lệch {fl}")
    else:
        warn(f"không tìm thấy dataset train ({data}) — bỏ qua chấm lại; dùng --train-data")
    w = 1 / pr.groupby("session_key")["label"].transform("size")
    for m in ("wazuh_rule", "single_thr", "tree_d3", "logreg", "rf"):
        if m not in M["eval"]["test"]: continue
        for op in ("f1", "fp5"):
            f = pr[f"flag_{m}_{op}"]
            g = pr.assign(f=f).groupby("session_key").agg(lab=("label", "first"), k=("f", "sum"))
            tp = (w * f * pr.label).sum(); fp = (w * f * (1 - pr.label)).sum(); fn = (w * (1 - f) * pr.label).sum()
            mine = {"w_f1": 2 * tp / (2 * tp + fp + fn) if tp else 0.0, "det_k1": (g[g.lab == 1].k >= 1).mean(),
                    "det_k3": (g[g.lab == 1].k >= 3).mean(), "fp_k1": (g[g.lab == 0].k >= 1).mean(), "fp_k3": (g[g.lab == 0].k >= 3).mean()}
            rep = M["eval"]["test"][m][op]
            diff = {k: (round(v, 4), round(rep[k], 4)) for k, v in mine.items() if k in rep and rep[k] is not None and abs(v - rep[k]) > 1e-9}
            (err if diff else ok)(f"test {m:10s} {op:3s}: tính lại từ cờ — wF1 {mine['w_f1']:.3f}, phát hiện {mine['det_k1']:.3f}, "
                                  f"báo nhầm {mine['fp_k1']:.3f}/{mine['fp_k3']:.3f}" + (f" — LỆCH báo cáo {diff}" if diff else " == báo cáo"))


# ------------------------------------------------------------------ 6. replay
def stage_replay(mdir, data, max_rows):
    print("\n== 6. ai-service: phát lại offline, so với dataset ==")
    import ai_service as AS
    model = os.path.join(mdir, "model.joblib")
    M = AS.load_model(model)
    data = data or M.get("dataset", {}).get("path")
    if not data or not os.path.exists(data):
        warn(f"không có dataset ({data}) — bỏ qua"); return
    df = read_csv(data)
    if max_rows and len(df) > max_rows:          # lấy trọn phiên (theo srcip) để cửa sổ 60 s đầy đủ
        keys = list(dict.fromkeys(df.session_key)); random.Random(0).shuffle(keys)
        n, keep = 0, []
        for k in keys:
            if n >= max_rows: break
            keep.append(k); n += int((df.session_key == k).sum())
        ips = set(df[df.session_key.isin(keep)].srcip)
        df = df[df.srcip.isin(ips)]
    df = df.reset_index(drop=True)
    RID = {200: "100010", 401: "100011", 404: "100012", 403: "100013"}
    r = random.Random(0)
    usec = (df.event_epoch * 1e6).round().astype("int64")
    key = usec / 1e6 + np.array([r.uniform(0, 0.9) for _ in range(len(df))])
    with tempfile.TemporaryDirectory() as td:
        A, O = os.path.join(td, "alerts.json"), os.path.join(td, "out.jsonl")
        with open(A, "w") as f:
            for i in np.argsort(key.to_numpy(), kind="mergesort"):
                st = int(df.status[i])
                rid = RID.get(st, "100014" if 300 <= st < 400 else "100015" if st >= 500 else "100016")
                f.write(json.dumps({"id": f"r{i}", "timestamp": "x", "rule": {"id": rid, "level": 3, "groups": ["siemlab", "siemlab_observed"]},
                                    "full_log": f'SIEMLAB {usec[i]} {df.srcip[i]} "{df.method[i]} {df.url[i]} HTTP/1.1" {st} 0'}) + "\n")
        svc = AS.Service(M, AS.MemoryStore(), AS.FileSink(O), A, op="fp5", reorder=2.0, idle_flush=1e9)
        t0 = time.time(); svc.run(once=True, poll=0, stats_every=1e9); dt = time.time() - t0
        docs = {d["_id"]: d for d in map(json.loads, open(O))}
    (ok if len(docs) == len(df) else err)(f"{len(df)} alert vào, {len(docs)} tài liệu ra, late={svc.c['late']}, {len(df)/max(dt,1e-9):.0f} alert/s")
    idx = sorted(int(k[1:]) for k in docs)
    sub = df.loc[idx]
    fo = np.array([[docs[f"r{i}"]["ai"]["features"][c] for c in M["features"]] for i in idx])
    fc = sub[M["features"]].to_numpy(float)
    d = np.abs(fo - fc)
    (ok if d.max() <= 1e-9 else err)(f"đặc trưng online vs CSV: max|Δ| = {d.max():.1e}, ô lệch > 1e-9: {int((d > 1e-9).sum())}")
    so = np.array([docs[f"r{i}"]["ai"]["score"] for i in idx])
    sc = np.round(M["model"].predict_proba(fc)[:, 1], M["score_decimals"])
    fl = {op: int(((so >= M["thresholds"][op]) != (sc >= M["thresholds"][op])).sum()) for op in ("f1", "fp5")}
    (ok if np.abs(so - sc).max() <= 1e-9 and not any(fl.values()) else err)(
        f"điểm online vs model(CSV): max|Δ| = {np.abs(so - sc).max():.1e}, cờ lệch {fl}")


# ------------------------------------------------------------------ 6b. live (indexer thật)
def stage_live(mdir, paths, url, user, pw, ca):
    print("\n== 6b. ai-service trên stack thật: index ai-enriched-alerts-* vs dataset offline ==")
    import calendar, joblib
    from opensearchpy import OpenSearch, helpers
    B = joblib.load(os.path.join(mdir, "model.joblib"))
    cols, tau, dec = B["features"], B["thresholds"], B["score_decimals"]
    kw = dict(hosts=[url], http_auth=(user, pw), timeout=60)
    if url.startswith("https"):
        if ca and os.path.exists(ca):
            kw.update(use_ssl=True, verify_certs=True, ca_certs=ca)
        else:
            warn(f"không có CA ({ca}) -> không kiểm chứng chỉ (chỉ đọc, trong mạng lab)")
            kw.update(use_ssl=True, verify_certs=False, ssl_show_warn=False)
    es = OpenSearch(**kw)
    for p in paths:
        name = os.path.basename(p)
        df = read_csv(p)
        lo, hi = df.event_epoch.min() - 1, df.event_epoch.max() + 1
        # sự kiện = tài liệu không phải ai.duplicate (gồm cả alert luật tương quan đã thay alert gốc);
        # tài liệu cũ (trước 22/10) không có trường duplicate -> vẫn được tính
        q = {"query": {"bool": {"filter": [
            {"terms": {"srcip": sorted(df.srcip.unique())}},
            {"range": {"event_time": {"gte": int(lo * 1000), "lte": int(hi * 1000) + 1, "format": "epoch_millis"}}}],
            "must_not": [{"term": {"ai.duplicate": True}}]}}}
        docs = [h["_source"] for h in helpers.scan(es, index="ai-enriched-alerts-*", query=q, size=2000)]

        def us(t):                                  # "YYYY-mm-ddTHH:MM:SS.ffffffZ" -> µs epoch
            a, f = t.rstrip("Z").split(".")
            return calendar.timegm(time.strptime(a, "%Y-%m-%dT%H:%M:%S")) * 1_000_000 + int(f.ljust(6, "0")[:6])
        idx = defaultdict(list)
        for d in docs: idx[(d["srcip"], us(d["event_time"]), d["url"], int(d["status"]))].append(d)
        keys = list(zip(df.srcip, (df.event_epoch * 1e6).round().astype("int64"), df.url, df.status.astype(int)))
        miss = [k for k in keys if k not in idx]
        dup = sum(len(v) > 1 for v in idx.values())
        extra = len(idx) - (len(keys) - len(miss))
        (ok if not miss and not dup and extra == 0 else err)(
            f"{name}: {len(df)} alert offline, {len(docs)} tài liệu sự kiện trong index; thiếu {len(miss)}, trùng {dup}, thừa {extra}")
        if miss: print(f"            ví dụ thiếu: {miss[:3]}")
        have = [i for i, k in enumerate(keys) if k in idx]
        if not have: continue
        sub = df.iloc[have]
        D = [idx[keys[i]][0] for i in have]
        fo = np.array([[d["ai"]["features"][c] for c in cols] for d in D], float)
        fc = sub[cols].to_numpy(float)
        dd = np.abs(fo - fc)
        bad_cols = [c for c, n in zip(cols, (dd > 1e-9).sum(0)) if n]
        (ok if dd.max() <= 1e-9 else err)(f"{name}: đặc trưng online vs offline: max|Δ| = {dd.max():.1e}, ô lệch {int((dd > 1e-9).sum())}"
                                          + (f" ở {bad_cols}" if bad_cols else ""))
        so = np.array([d["ai"]["score"] for d in D], float)
        sc = np.round(B["model"].predict_proba(fc)[:, 1], dec)
        fl = {op: int(sum(bool(d["ai"]["flags"][op]) != bool(v >= tau[op]) for d, v in zip(D, sc))) for op in tau}
        (ok if np.abs(so - sc).max() <= 1e-9 and not any(fl.values()) else err)(
            f"{name}: điểm online vs model(offline): max|Δ| = {np.abs(so - sc).max():.1e}, cờ lệch {fl}")
        late = sum(bool(d["ai"].get("late")) for d in D)
        (warn if late else ok)(f"{name}: alert đến trễ quá reorder (ai.late) = {late}")
        g = sub.assign(f=[bool(d["ai"]["flags"]["fp5"]) for d in D]).groupby("session_key").agg(
            sc=("scenario", "first"), lab=("label", "first"), n=("f", "size"), k=("f", "sum"))
        for k, r in g.iterrows():
            print(f"            {r.sc:20s} nhãn {r.lab}: {int(r.k)}/{r.n} alert vượt ngưỡng fp5 -> "
                  + ("PHÁT HIỆN" if r.k >= 1 and r.lab == 1 else "bỏ sót" if r.lab == 1 else "báo nhầm" if r.k >= 1 else "đúng (không báo)"))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--stage", nargs="+", default=["runs", "datasets", "requests", "features", "model", "replay"],
                    choices=["runs", "datasets", "requests", "features", "model", "replay", "live"])
    ap.add_argument("--runs", nargs="*", help="các sessions.jsonl (mặc định data/runs/*/sessions.jsonl)")
    ap.add_argument("--data", nargs="*", help="các dataset CSV (mặc định data/dataset_*.csv)")
    ap.add_argument("--model-dir", default="models/full1")
    ap.add_argument("--train-data", help="dataset đã train model (mặc định: đường dẫn ghi trong model.joblib)")
    ap.add_argument("--replay-max-rows", type=int, default=0, help="giới hạn số alert phát lại (0 = toàn bộ)")
    ap.add_argument("--max-lag", type=float, default=2.0)
    ap.add_argument("--max-dt", type=float, default=1.0, help="|thời gian Apache − lúc gửi| tối đa cho phép (s)")
    ap.add_argument("--tol", type=float, default=1e-9)
    ap.add_argument("--indexer", default=os.environ.get("INDEXER_URL", "https://wazuh.indexer:9200"))
    ap.add_argument("--indexer-user", default=os.environ.get("INDEXER_USERNAME", "admin"))
    ap.add_argument("--indexer-password", default=os.environ.get("INDEXER_PASSWORD", "SecretPassword"))
    ap.add_argument("--ca", default=os.environ.get("INDEXER_CA", "/certs/root-ca.pem"))
    a = ap.parse_args()
    runs = a.runs if a.runs is not None else sorted(glob.glob("data/runs/*/sessions.jsonl"))
    data = a.data if a.data is not None else sorted(glob.glob("data/dataset_*.csv"))
    t0 = time.time()
    if "runs" in a.stage: stage_runs(runs, a.max_lag)
    if "datasets" in a.stage: stage_datasets(data)
    if "requests" in a.stage: stage_requests(data, a.max_dt)
    if "features" in a.stage: stage_features(data, a.tol)
    if "model" in a.stage: stage_model(a.model_dir, a.train_data)
    if "replay" in a.stage: stage_replay(a.model_dir, a.train_data, a.replay_max_rows)
    if "live" in a.stage: stage_live(a.model_dir, data, a.indexer, a.indexer_user, a.indexer_password, a.ca)
    print(f"\nTỔNG: {'OK' if N_ERR == 0 else f'{N_ERR} LỖI'} ({time.time()-t0:.0f}s)")
    sys.exit(1 if N_ERR else 0)


if __name__ == "__main__":
    main()
