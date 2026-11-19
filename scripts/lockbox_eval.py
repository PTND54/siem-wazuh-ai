#!/usr/bin/env python3
"""lockbox_eval.py — đánh giá lockbox ĐÚNG như docs/LOCKBOX_PREREG.md. Hai bước, theo thứ tự bắt buộc:

  1) python3 scripts/lockbox_eval.py validate --batch data/runs/lockbox1 --data data/dataset_lockbox1.csv
         -> output/lockbox1/validity.json  (mục 5: chỉ hợp lệ khi đạt TẤT CẢ)
  2) python3 scripts/lockbox_eval.py metrics  --data data/dataset_lockbox1.csv
         -> output/lockbox1/{metrics.json, report.md}  (mục 6) — TỪ CHỐI chạy nếu validity.json chưa có, không đạt,
            hoặc dataset đã đổi (sha256) sau khi kiểm.

Chạy trong container lab. Không có ngưỡng đạt/không đạt cho chỉ số: lockbox để ƯỚC LƯỢNG kèm khoảng tin cậy.
Chỉ số dùng chính các hàm của trainer.py (sess_agg, summarize, per_scenario, boot_index, boot_stats) -> cùng định nghĩa
với test full1. Thử trên batch khác (vd. dev_rules3, split test): --split test --out output/lockbox_try_dev_rules3
(báo cáo ghi "THỬ — KHÔNG PHẢI LOCKBOX" khi split khác 'lockbox' hoặc --test-only).

28/10 (v4-AI, trước lockbox): "luật" (P2) = các luật ĐANG ÁP lấy từ hồ sơ đề xuất 'applied' (bộ v4-AI), không ghi cứng id.
Đối chứng P6: bộ v3 (chọn bằng nhãn thật) MÔ PHỎNG CHUNG (wazuh_sim.joint_fires, giờ Manager làm tròn giây lấy từ
alerts.json qua --alerts; thiếu --alerts thì dùng giờ Apache làm tròn giây và report ghi rõ) trên CÙNG các phiên.
Mô phỏng chung đã khớp Wazuh thật ở mức phiên trên dev_rules1-3 (lệch theo hướng an toàn).
"""
import argparse, hashlib, json, math, os, subprocess, sys, time
from collections import OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

RULE_IDS_V3_FALLBACK = ("110011", "110020", "110030")
V3_PIDS = ("R110011-r401-N12-T120-20261022-163955", "R110020-web_scan-N15-T10-20261022-163955", "R110030-any-N600-T10-20261026-110447")
EXCL_FRAC = 0.03                 # PREREG mục 5.3: <= 3% phiên bị loại
N_BOOT, BOOT_SEED = 1000, 12345  # PREREG mục 6
COV = (0.98, 1.02)


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def outdir(a):
    stem = os.path.splitext(os.path.basename(a.data))[0].replace("dataset_", "")
    return a.out or os.path.join(ROOT, "output", stem)


def load_rules(pdir, pids=None):
    """pids=None: các đề xuất 'applied' (luật đang áp); ngược lại: đúng các pid (mọi trạng thái). Trả list dict theo id."""
    from rule_proposer import FAMILIES
    out = []
    for fn in sorted(os.listdir(pdir)) if os.path.isdir(pdir) else []:
        if not fn.endswith(".json"):
            continue
        c = json.load(open(os.path.join(pdir, fn), encoding="utf-8"))
        pid = c.get("proposal_id", fn[:-5])
        if (pids is None and c.get("status") == "applied") or (pids is not None and pid in pids):
            if c.get("family") not in FAMILIES:
                continue                                              # canary / luật thử không phải họ tần suất
            out.append({"pid": pid, "family": c["family"], "rule_id": str(FAMILIES[c["family"]]["rule_id"]),
                        "N": int(c["params"]["frequency"]), "T": int(c["params"]["timeframe"]),
                        "label_source": c.get("label_source", "truth"), "status": c.get("status")})
    return sorted(out, key=lambda r: int(r["rule_id"]))


def sim_flags(df, rules, tsec):
    """Cờ theo alert: sự kiện có alert cuối cùng là một luật trong `rules` khi MÔ PHỎNG CHUNG (thứ tự nạp = id)."""
    import numpy as np
    import wazuh_sim as W
    from compare_rules import joint_specs
    spec = joint_specs(OrderedDict((r["family"], r) for r in rules))
    ids = {int(r["rule_id"]) for r in rules}
    fl = np.zeros(len(df), bool)
    for _, ix in df.groupby("session_key", sort=False).indices.items():
        ix = np.sort(ix)
        o = np.argsort(df["event_epoch"].to_numpy()[ix], kind="mergesort"); ix = ix[o]
        fin = W.joint_fires(tsec[ix].tolist(), df["status"].to_numpy()[ix], spec)
        fl[ix] = [int(x) in ids for x in fin]
    return fl


# ============================================================ mục 5
def validate(a):
    bdir = a.batch
    S = [json.loads(l) for l in open(os.path.join(bdir, "sessions.jsonl"), encoding="utf-8")]
    meta = [json.loads(l) for l in open(os.path.join(bdir, "batch.jsonl"), encoding="utf-8")]
    started = [json.loads(l) for l in open(os.path.join(bdir, "started.jsonl"), encoding="utf-8")]
    audit_p = os.path.splitext(a.data)[0] + ".audit.json"
    A = json.load(open(audit_p, encoding="utf-8"))
    n_plan = meta[0]["n_sessions"]
    V = OrderedDict(created=time.strftime("%Y-%m-%dT%H:%M:%S%z"), batch=bdir, data=a.data, data_sha256=sha256(a.data),
                    audit=audit_p, audit_sha256=sha256(audit_p), code_digest=[m.get("code_digest") for m in meta],
                    n_planned=n_plan, checks=[])

    def rec(name, ok, detail):
        V["checks"].append({"check": name, "ok": bool(ok), "detail": detail})
        print(f"[{'ĐẠT' if ok else 'KHÔNG ĐẠT':9s}] {name}: {json.dumps(detail, ensure_ascii=False)[:600]}")

    n_err = sum(int(s.get("n_err") or 0) for s in S); failed = [s["run_id"] for s in S if s.get("failed")]
    orph = A.get("orphans") or []
    rec("5.1 đủ phiên, 0 lỗi mạng, 0 phiên mồ côi", len(S) == n_plan and len(started) == n_plan and n_err == 0 and not failed and not orph,
        {"phiên xong": len(S), "kế hoạch": n_plan, "đã bắt đầu": len(started), "request lỗi": n_err, "failed": failed, "mồ côi": len(orph)})
    bad_cov = [(x["session_key"], x["coverage"]) for x in A["sessions"]
               if x["coverage"] is not None and not (COV[0] <= x["coverage"] <= COV[1])]
    covs = [x["coverage"] for x in A["sessions"] if x["coverage"] is not None]
    rec("5.2 coverage mọi phiên trong [0,98; 1,02]", not bad_cov and len(covs) == n_plan,
        {"min": min(covs) if covs else None, "max": max(covs) if covs else None, "ngoài khoảng": bad_cov})
    lim = int(math.floor(EXCL_FRAC * n_plan + 1e-9))
    ex = [{"session_key": x["session_key"], "scenario": x["scenario"], "label": x["label"], "lý do": x["excluded"],
           "max_lag": x.get("max_lag"), "coverage": x["coverage"]} for x in A["sessions"] if x["excluded"]]
    rec(f"5.3 phiên bị loại <= {lim} ({EXCL_FRAC:.0%} của {n_plan})", len(ex) <= lim, {"số phiên bị loại": len(ex), "danh sách": ex})
    exc = A.get("excluded") or {}
    rec("5.4 không có alert chưa giải thích", exc.get("unknown_in_range", 0) == 0 and exc.get("ambiguous", 0) == 0,
        {"unknown_in_range": exc.get("unknown_in_range", 0), "ambiguous": exc.get("ambiguous", 0),
         "canary_in_range (được phép)": exc.get("canary_in_range", 0), "liệt kê": (A.get("unknown_in_range_alerts") or [])[:20]})
    if a.skip_live:
        rec("5.5 ai-service trực tiếp == offline", False, "BỎ QUA (--skip-live) -> chỉ dùng để thử")
    else:
        p = subprocess.run([sys.executable, os.path.join(HERE, "check_pipeline.py"), "--stage", "live", "--data", a.data],
                           capture_output=True, text=True, cwd=ROOT)
        lines = [l.strip() for l in (p.stdout + p.stderr).splitlines() if "[OK]" in l or "[LỖI]" in l or "TỔNG" in l]
        rec("5.5 ai-service trực tiếp == offline (check_pipeline --stage live)", p.returncode == 0 and "TỔNG: OK" in p.stdout, lines[:12])
    V["passed"] = all(c["ok"] for c in V["checks"])
    V["excluded_sessions"] = ex
    o = outdir(a); os.makedirs(o, exist_ok=True)
    json.dump(V, open(os.path.join(o, "validity.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"\nMỤC 5: {'HỢP LỆ — được tính chỉ số mục 6' if V['passed'] else 'KHÔNG HỢP LỆ — không tính chỉ số; xem PREREG mục 5'}"
          f"  -> {os.path.relpath(os.path.join(o, 'validity.json'), ROOT)}")
    return 0 if V["passed"] else 1


# ============================================================ mục 6
def metrics(a):
    o = outdir(a); vp = os.path.join(o, "validity.json")
    if not os.path.exists(vp):
        print(f"TỪ CHỐI: chưa có {vp} — chạy 'validate' trước (PREREG mục 5 -> 7)"); return 2
    V = json.load(open(vp, encoding="utf-8"))
    if V.get("data_sha256") != sha256(a.data):
        print("TỪ CHỐI: dataset đã đổi sau khi kiểm mục 5 (sha256 khác)"); return 2
    if not V.get("passed") and not a.test_only:
        print("TỪ CHỐI: mục 5 KHÔNG đạt -> lần chạy không hợp lệ, không tính chỉ số (PREREG mục 5)"); return 2
    import joblib
    import numpy as np, pandas as pd
    import trainer as TR
    trial = a.test_only or a.split != "lockbox" or not V.get("passed")
    B = joblib.load(a.model)
    tau = B["thresholds"]["fp5"]; cols = B["features"]
    df = TR.load_dataset(a.data)
    df["rule_id"] = df["rule_id"].astype(str)
    applied = load_rules(a.proposals)
    if not applied and a.split == "lockbox":
        print(f"TỪ CHỐI: không có đề xuất 'applied' trong {a.proposals} — không biết luật nào đang áp (P2)"); return 2
    RULE_IDS = tuple(r["rule_id"] for r in applied) or RULE_IDS_V3_FALLBACK
    base = load_rules(a.proposals, set(a.baseline)) if a.baseline else []
    if a.baseline and len(base) != len(a.baseline):
        print(f"TỪ CHỐI: không tìm thấy đủ hồ sơ đối chứng {a.baseline} trong {a.proposals}"); return 2
    time_src = "apache_sec"
    if base:
        if a.alerts:
            from audit_coverage import expand
            from compare_rules import read_alert_times
            amap = read_alert_times(expand(a.alerts, "alert"), df.event_epoch.min() - 1, df.event_epoch.max() + 1)
            keys = zip(df.srcip, (df.event_epoch * 1e6).round().astype("int64"), df.url, df.status.astype(int))
            mgr = np.array([amap[k][1] if k in amap else np.nan for k in keys])
            n_miss = int(np.isnan(mgr).sum())
            tsec = np.floor(np.where(np.isnan(mgr), df.event_epoch.to_numpy(float), mgr)); time_src = f"manager_sec (thiếu {n_miss} dòng -> giờ Apache)"
        else:
            tsec = np.floor(df.event_epoch.to_numpy(float))
        df["_v3sim"] = sim_flags(df, base, tsec)

    def run(split):
        d = df[df["split"] == split]
        if d.empty:
            return None
        P = TR.Part(d, split)
        sc = np.round(B["model"].predict_proba(P.X(cols))[:, 1], B["score_decimals"])
        rid = P.df["rule_id"].to_numpy()
        F = OrderedDict(rf=sc >= tau, rule=np.isin(rid, RULE_IDS))
        F["rf_or_rule"] = F["rf"] | F["rule"]
        if base:
            F["rule_v3sim"] = P.df["_v3sim"].to_numpy(bool)
        out = OrderedDict(); G = {}
        for k, fl in F.items():
            g = TR.sess_agg(P, fl); G[k] = g
            r = TR.summarize(P, fl, g, sc if k == "rf" else None)
            att, ben = P.ys == 1, P.ys == 0
            r["n_detected_k1"] = int((g["nflag"][att] >= 1).sum()); r["n_not_detected_k1"] = int((g["nflag"][att] < 1).sum())
            r["n_false_alarm_k1"] = int((g["nflag"][ben] >= 1).sum())
            r["by_scenario"] = TR.per_scenario(P, g)
            out[k] = r
        return P, out, G

    res = OrderedDict(); paired = {}
    main = run(a.split)
    if main is None:
        print(f"không có split '{a.split}' trong {a.data}"); return 2
    P, out, G = main
    I = TR.boot_index(P, N_BOOT, BOOT_SEED)
    bs = {k: TR.boot_stats(P, G[k], I) for k in G}
    for k in out:
        out[k]["ci95"] = {m: TR.ci(bs[k][m]) for m in TR.BOOT_KEYS}
    pairs = [("rf", "rule"), ("rf_or_rule", "rf"), ("rf_or_rule", "rule")] + ([("rule", "rule_v3sim"), ("rf", "rule_v3sim")] if base else [])
    for x, y in pairs:
        paired[f"{x}-{y}"] = {m: {"diff": out[x][m] - out[y][m], "ci95": TR.ci(bs[x][m] - bs[y][m])} for m in ("det_k1", "fp_k1")}
    res[a.split] = out
    st = run("stress")
    if st is not None:
        res["stress"] = st[1]
    M = OrderedDict(created=time.strftime("%Y-%m-%dT%H:%M:%S%z"), trial=bool(trial), data=a.data, data_sha256=V["data_sha256"],
                    validity=V, model=a.model, model_sha256=sha256(a.model), op="fp5", tau=tau, rule_ids=RULE_IDS,
                    applied_rules=applied, baseline_rules=base, baseline_time=time_src if base else None,
                    n_boot=N_BOOT, boot_seed=BOOT_SEED, results=res, paired=paired)
    json.dump(TR._clean(M), open(os.path.join(o, "metrics.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False, default=TR._json_default)
    write_report(os.path.join(o, "report.md"), M, a.split)
    print(open(os.path.join(o, "report.md"), encoding="utf-8").read()[:3500])
    return 0


def write_report(path, M, split):
    pct = lambda v: "—" if v is None else f"{100 * v:.1f}%"
    civ = lambda c: "" if not c else f" [{100 * c[0]:.1f}; {100 * c[1]:.1f}]"
    num = lambda v, d=1: "—" if v is None or (isinstance(v, float) and math.isnan(v)) else f"{v:.{d}f}"
    R = M["results"][split]
    src = {r.get("label_source") for r in M.get("applied_rules") or []}
    rname = "Luật v4-AI" if src == {"ai"} else "Luật đang áp"
    NAME = {"rf": "RF (fp5, k=1)", "rule": f"{rname} (alert 110xxx THẬT)", "rf_or_rule": "RF HOẶC luật (P5, phụ)",
            "rule_v3sim": "Luật v3 — nhãn thật (MÔ PHỎNG chung, đối chứng P6)"}
    L = [f"# {'THỬ — KHÔNG PHẢI LOCKBOX' if M['trial'] else 'LOCKBOX'} — {os.path.basename(M['data'])} (split {split})", "",
         f"Tạo {M['created']}. Model sha256 `{M['model_sha256'][:16]}…`, op fp5, ngưỡng {M['tau']}. Bootstrap {M['n_boot']} lần theo "
         f"phiên, phân tầng theo kịch bản, seed {M['boot_seed']}. Mục 5 (hợp lệ): {'ĐẠT' if M['validity'].get('passed') else 'KHÔNG ĐẠT / bỏ qua'}. "
         "Lockbox để ƯỚC LƯỢNG kèm khoảng tin cậy — không có ngưỡng đạt/không đạt.", "",
         "Luật đang áp (thật): " + (", ".join(f"{r['family']} {r['rule_id']} N={r['N']} T={r['T']}s ({r['label_source']})" for r in M.get("applied_rules") or []) or "—")
         + ". Đối chứng mô phỏng: " + (", ".join(f"{r['family']} {r['rule_id']} N={r['N']} T={r['T']}s" for r in M.get("baseline_rules") or []) or "không")
         + (f" — giờ {M['baseline_time']}" if M.get("baseline_time") else "") + ".", "",
         "## P1, P2, P5 — theo phiên", "",
         "| phương pháp | phát hiện k=1 | số phiên bắt / không bắt | báo nhầm k=1 | số phiên báo nhầm | phát hiện k=3 | báo nhầm k=3 |",
         "|---|---|---|---|---|---|---|"]
    for k, r in R.items():
        ci = r.get("ci95", {})
        L.append(f"| {NAME[k]} | {pct(r['det_k1'])}{civ(ci.get('det_k1'))} | {r['n_detected_k1']} / {r['n_not_detected_k1']} (của {r['n_attack_sessions']}) | "
                 f"{pct(r['fp_k1'])}{civ(ci.get('fp_k1'))} | {r['n_false_alarm_k1']} / {r['n_benign_sessions']} | {pct(r['det_k3'])} | {pct(r['fp_k3'])} |")
    L += ["", "## P3 — thời gian đến phát hiện (chỉ trên phiên bị bắt)", "",
          "| phương pháp | phiên bị bắt | không bị bắt | giây: trung vị / p90 | số alert đến lần đầu: trung vị / p90 |", "|---|---|---|---|---|"]
    for k, r in R.items():
        L.append(f"| {NAME[k]} | {r['n_detected_k1']} | {r['n_not_detected_k1']} | {num(r['ttd_k1_s_median'])} / {num(r['ttd_k1_s_p90'])} | "
                 f"{num(r['atd_k1_median'], 0)} / {num(r['atd_k1_p90'], 0)} |")
    L += ["", "## P4, P5 — hiệu ghép cặp (điểm phần trăm, CI 95% bootstrap ghép cặp)", "", "| so sánh | Δ phát hiện | Δ báo nhầm |", "|---|---|---|"]
    lab = {"rf-rule": "RF − luật (P4)", "rf_or_rule-rf": "(RF HOẶC luật) − RF: tăng thêm so với RF (P5)", "rf_or_rule-rule": "(RF HOẶC luật) − luật (P5)",
           "rule-rule_v3sim": "luật đang áp − luật v3 mô phỏng (P6)", "rf-rule_v3sim": "RF − luật v3 mô phỏng (phụ)"}
    for k, d in M["paired"].items():
        f = lambda m: f"{100 * d[m]['diff']:+.1f}{civ(d[m]['ci95'])}"
        L.append(f"| {lab[k]} | {f('det_k1')} | {f('fp_k1')} |")
    L += ["", "## Theo kịch bản (tỉ lệ phiên bị bắt k=1; TTD giây trung vị trên phiên bị bắt)", "",
          "| kịch bản | nhãn | phiên | RF | luật | RF HOẶC luật | v3 mô phỏng | TTD RF | TTD luật |", "|---|---|---|---|---|---|---|---|---|"]
    bys = {k: {x["scenario"]: x for x in R[k]["by_scenario"]} for k in R}
    for sc in sorted(bys["rf"], key=lambda s: (bys["rf"][s]["label"], s)):
        x = bys["rf"][sc]
        L.append(f"| {sc} | {x['label']} | {x['n_sessions']} | {pct(x['rate_k1'])} | {pct(bys['rule'][sc]['rate_k1'])} | "
                 f"{pct(bys['rf_or_rule'][sc]['rate_k1'])} | {pct(bys['rule_v3sim'][sc]['rate_k1']) if 'rule_v3sim' in bys else '—'} | "
                 f"{num(x.get('ttd_k1_s_median'))} | {num(bys['rule'][sc].get('ttd_k1_s_median'))} |")
    if "stress" in M["results"]:
        L += ["", "## Stress (benign trông như tấn công; báo cáo riêng)", ""]
        for k, r in M["results"]["stress"].items():
            L.append(f"- {NAME[k]}: báo nhầm {r['n_false_alarm_k1']}/{r['n_benign_sessions']} phiên")
    V = M["validity"]
    L += ["", "## Mục 5 — hợp lệ", ""] + [f"- {'ĐẠT' if c['ok'] else 'KHÔNG ĐẠT'} — {c['check']}" for c in V["checks"]]
    L += ["", "Phiên bị loại: " + (", ".join(f"{e['session_key']} ({e['scenario']}, nhãn {e['label']}, {'/'.join(e['lý do'])})"
                                            for e in V.get("excluded_sessions", [])) or "không có"), "",
          "Phụ: wF1 theo alert của RF = " + num(R["rf"]["w_f1"], 3) + " (KHÔNG so wF1 với luật — luật tần suất chỉ bắn ở sự kiện thứ N, 2N…).", ""]
    open(path, "w", encoding="utf-8").write("\n".join(L))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=("validate", "metrics"))
    ap.add_argument("--data", required=True); ap.add_argument("--batch", default=None)
    ap.add_argument("--model", default=os.path.join(ROOT, "models", "full1", "model.joblib"))
    ap.add_argument("--split", default="lockbox"); ap.add_argument("--out", default=None)
    ap.add_argument("--skip-live", action="store_true", help="chỉ để thử khi không có stack (mục 5 sẽ KHÔNG đạt)")
    ap.add_argument("--test-only", action="store_true", help="cho tính chỉ số khi mục 5 không đạt — báo cáo ghi THỬ")
    ap.add_argument("--proposals", default=os.path.join(ROOT, "proposals"))
    ap.add_argument("--baseline", nargs="*", default=list(V3_PIDS), help="pid bộ đối chứng mô phỏng (mặc định v3); rỗng = bỏ")
    ap.add_argument("--alerts", nargs="*", default=None, help="alerts.json để lấy giờ Manager cho mô phỏng đối chứng")
    a = ap.parse_args(argv)
    if a.cmd == "validate":
        if not a.batch:
            ap.error("validate cần --batch")
        return validate(a)
    return metrics(a)


if __name__ == "__main__":
    sys.exit(main())
