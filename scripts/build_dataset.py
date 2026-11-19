#!/usr/bin/env python3
"""build_dataset.py — tương ứng mục 13 hướng dẫn v2 ("thu alert và trích đặc trưng"), làm lại.

  python3 scripts/build_dataset.py --batches data/runs/dev1 \
          --alerts /wazuh-logs/alerts/alerts.json [/wazuh-logs/alerts/2026/Oct/ossec-alerts-*.json* ...] \
          --out data/dataset_dev1.csv

Các bước:
  1. Đọc MỌI alert SIEMLAB (nhóm siemlab_observed) từ alerts.json + file đã xoay vòng; bỏ trùng theo id alert.
  2. Tính đặc trưng bằng features.enrich trên TOÀN BỘ luồng alert của từng srcip (đúng như ai-service sẽ thấy
     online, kể cả alert không thuộc phiên nào), thời gian = thời điểm Apache (event_usec), không phải giờ Wazuh.
  3. Gán nhãn theo (srcip, khoảng thời gian phiên) từ sessions.jsonl. Nhãn = ý định của kịch bản, không theo rule level.
  4. Loại: alert thuộc phiên bị ngắt (started.jsonl có, sessions.jsonl không; khoảng [t_start, t_end_plan]),
     alert không khớp phiên nào ("unknown"), alert khớp > 1 phiên ("ambiguous" — không được xảy ra nếu sổ IP đúng).
  5. Ghi dataset CSV + <out>.audit.json: coverage từng phiên = số alert khớp / số request Apache đã trả lời.
     Phiên có coverage ngoài [--min-coverage, --max-coverage], phiên lỗi mạng (failed) hoặc trễ lịch > --max-lag
     (hành vi thời gian không còn như kịch bản) bị đánh dấu và (mặc định) loại khỏi dataset.

Một dòng log SIEMLAB = một sự kiện = một dòng dataset, bất kể rule nào sinh alert. Khi một luật tương quan đã áp dụng
(vd. 110xxx) khớp, Wazuh sinh alert 110xxx THAY CHO alert gốc 10001x (xem audit_coverage.siemlab_match) — nếu chỉ lấy
rule gốc, các request đó biến mất khỏi dataset và khỏi cửa sổ đặc trưng (lỗi "mất 18%" của v9). Đếm riêng trong
"correlated_rule_events" trong audit (không bị bỏ, chỉ để biết).
Bỏ trùng 2 lớp: theo id alert (file xoay vòng chồng nhau) và theo nội dung dòng log (agent đọc lại file; hoặc nếu một
dòng có cả alert gốc lẫn alert tương quan thì chỉ giữ alert đến trước).
Khóa phiên duy nhất là session_key = batch/run_id (run_id có thể lặp giữa các batch).
"""
import argparse, bisect, glob, gzip, hashlib, json, os, sys, time
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import features as F
from audit_coverage import BASE_RULES, siemlab_match

PRE, POST = 2.0, 10.0
CANARY_PREFIX = "/__siem10_canary/"        # apply_rule.py health: 1 request host -> Apache :8080 (srcip = gateway Docker)
META = ["session_key", "run_id", "batch", "scenario", "family", "label", "split", "shift", "kind"]


def _open(p):
    return gzip.open(p, "rt", errors="replace") if p.endswith(".gz") else open(p, errors="replace", encoding="utf-8")


def read_alerts(paths):
    seen, seen_log, rows, dup = set(), set(), [], Counter()
    for p in paths:
        with _open(p) as f:
            for l in f:
                if "SIEMLAB" not in l: continue
                try: a = json.loads(l)
                except Exception: continue
                m = siemlab_match(a)
                if not m: continue
                aid = a.get("id") or a["full_log"]
                if aid in seen: dup["same_id"] += 1; continue
                seen.add(aid)
                if m[0] in seen_log: dup["same_log_line"] += 1; continue     # cùng usec+ip+request+mã: agent đọc lại
                seen_log.add(m[0])
                if str(a["rule"]["id"]) not in BASE_RULES: dup["kept_correlated_rule"] += 1
                rows.append({"alert_id": aid, "event_epoch": int(m[1]) / 1e6, "srcip": m[2], "method": m[3], "url": m[4],
                             "status": int(m[5]), "rule_id": a["rule"]["id"], "rule_level": int(a["rule"]["level"])})
    return rows, dup


def load_sessions(batch_dirs):
    done, orphans = [], []
    for b in batch_dirs:
        name = os.path.basename(os.path.normpath(b))
        ss = []
        for l in open(os.path.join(b, "sessions.jsonl"), encoding="utf-8"):
            try: ss.append(json.loads(l))
            except Exception: pass
        for s in ss:
            if "t_first" not in s: continue                      # công cụ bị skipped
            s["batch"] = name; s.setdefault("kind", "generator"); s["session_key"] = f"{name}/{s['run_id']}"; done.append(s)
        keys = {(s["run_id"], s["srcip"], round(s["t_first"], 3)) for s in ss if "t_first" in s}
        sp = os.path.join(b, "started.jsonl")
        if os.path.exists(sp):
            for l in open(sp, encoding="utf-8"):
                try: o = json.loads(l)
                except Exception: continue
                if (o["run_id"], o["srcip"], round(o["t_start"], 3)) not in keys:
                    o["batch"] = name; orphans.append(o)
    return done, orphans


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--batches", nargs="+", required=True)
    ap.add_argument("--alerts", nargs="+", required=True, help="alerts.json và/hoặc file .json.gz đã xoay vòng (glob được)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--min-coverage", type=float, default=0.98)
    ap.add_argument("--max-coverage", type=float, default=1.02,
                    help="nhiều alert hơn số request trong cửa sổ phiên = traffic lạ cùng IP hoặc alert trùng -> loại")
    ap.add_argument("--max-lag", type=float, default=2.0, help="trễ lịch tối đa (giây) của generator trong một phiên")
    ap.add_argument("--keep-low-coverage", action="store_true", help="giữ cả phiên bị đánh dấu (chỉ để phân tích)")
    a = ap.parse_args()
    paths = sorted({p for g in a.alerts for p in glob.glob(g)})
    missing = [g for g in a.alerts if not glob.glob(g)]
    if missing: print(f"CẢNH BÁO: không tìm thấy file alert nào khớp: {missing}")
    if not paths: sys.exit("Không có file alert nào để đọc.")
    t0 = time.time()
    alerts, dup = read_alerts(paths)
    sessions, orphans = load_sessions(a.batches)
    if not sessions: sys.exit("Không có phiên nào trong các batch đã cho.")
    kept_corr = dup.pop("kept_correlated_rule", 0)
    print(f"đọc {len(alerts)} alert SIEMLAB từ {len(paths)} file (bỏ: {dict(dup)}"
          + (f"; trong đó {kept_corr} alert của luật tương quan, giữ như sự kiện" if kept_corr else "")
          + f"); {len(sessions)} phiên, {len(orphans)} phiên mồ côi")

    # 2. đặc trưng trên toàn bộ luồng (thứ tự đầu vào được giữ)
    enr = F.enrich(alerts)

    # 3-4. gán nhãn theo khoảng thời gian
    iv = defaultdict(list)                                # srcip -> [(lo, hi, kind, idx)]
    for i, s in enumerate(sessions): iv[s["srcip"]].append((s["t_first"] - PRE, s["t_last"] + POST, "S", i))
    for i, o in enumerate(orphans): iv[o["srcip"]].append((o["t_start"] - PRE, o.get("t_end_plan", o["t_start"] + 900) + POST, "O", i))
    for v in iv.values(): v.sort()
    tmin = min(s["t_first"] for s in sessions) - 60; tmax = max(s["t_last"] for s in sessions) + 60
    rows, cnt = [], Counter()
    per_sess = Counter()
    unknown = []                                           # alert lạ trong khoảng batch: LUÔN liệt kê để xem là gì
    for e in enr:
        hits = [x for x in iv.get(e["srcip"], []) if x[0] <= e["event_epoch"] <= x[1]]
        if not hits:
            if not (tmin <= e["event_epoch"] <= tmax):
                cnt["outside_batches"] += 1
            elif str(e.get("url", "")).startswith(CANARY_PREFIX):
                cnt["canary_in_range"] += 1                # request kiểm sức khỏe của apply_rule.py (đã biết)
            else:
                cnt["unknown_in_range"] += 1
                unknown.append({k: e.get(k) for k in ("event_epoch", "srcip", "method", "url", "status", "rule_id", "alert_id")})
            continue
        if any(h[2] == "O" for h in hits): cnt["orphan"] += 1; continue
        if len(hits) > 1: cnt["ambiguous"] += 1; continue
        s = sessions[hits[0][3]]; per_sess[hits[0][3]] += 1
        r = {k: s.get(k) for k in META}
        r.update({k: e[k] for k in ("event_epoch", "srcip", "method", "url", "status", "rule_id", "rule_level", "alert_id")})
        r["t_rel"] = e["event_epoch"] - s["t_first"]
        r.update({c: e[c] for c in F.FEATURE_COLUMNS})
        rows.append((hits[0][3], r))

    # 5. coverage theo phiên
    sess_audit, low = [], set()
    for i, s in enumerate(sessions):
        n_ref = s.get("n_ok")                              # công cụ thật: không có -> không tính coverage
        cov = per_sess[i] / n_ref if n_ref else None
        why = []
        if cov is not None and not (a.min_coverage <= cov <= a.max_coverage): why.append("coverage")
        if s.get("failed"): why.append("failed")
        if (s.get("max_lag") or 0) > a.max_lag: why.append("lag")
        if why: low.add(i)
        sess_audit.append({"session_key": s["session_key"], "scenario": s["scenario"], "family": s["family"],
                           "label": s["label"], "split": s["split"], "srcip": s["srcip"], "alerts": per_sess[i],
                           "responses": n_ref, "coverage": cov, "max_lag": s.get("max_lag"), "excluded": why,
                           "params": s.get("params"), "duration": round(s["t_last"] - s["t_first"], 3)})
    kept = [r for i, r in rows if a.keep_low_coverage or i not in low]
    for r in kept: r.pop("alert_id", None)
    kept.sort(key=lambda r: (r["session_key"], r["event_epoch"]))
    seq = Counter()                                        # thứ tự sự kiện trong phiên (0 = alert đầu tiên)
    for r in kept: r["seq"] = seq[r["session_key"]]; seq[r["session_key"]] += 1

    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    cols = META + ["srcip", "event_epoch", "t_rel", "seq", "method", "url", "status", "rule_id", "rule_level"] + F.FEATURE_COLUMNS
    import csv
    with open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader()
        for r in kept: w.writerow({c: r[c] for c in cols})
    covs = [x["coverage"] for x in sess_audit if x["coverage"] is not None]
    audit = {"created": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "alert_files": paths, "batches": a.batches,
             "features_sha": hashlib.sha256(open(os.path.join(HERE, "features.py"), "rb").read()).hexdigest()[:16],
             "feature_columns": F.FEATURE_COLUMNS, "n_alerts_read": len(alerts), "dropped_on_read": dict(dup), "correlated_rule_events": kept_corr,
             "n_rows": len(kept), "excluded": dict(cnt),
             "excluded_sessions": {sessions[i]["session_key"]: sess_audit[i]["excluded"] for i in sorted(low)},
             "n_sessions_kept": len({r["session_key"] for r in kept}),
             "coverage_min": min(covs) if covs else None, "coverage_max": max(covs) if covs else None,
             "rows_by_split_label": {f"{k[0]}|{k[1]}": v for k, v in sorted(Counter((r["split"], r["label"]) for r in kept).items())},
             "unknown_in_range_alerts": unknown[:200], "sessions": sess_audit, "orphans": orphans}
    json.dump(audit, open(os.path.splitext(a.out)[0] + ".audit.json", "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"dataset: {len(kept)} dòng -> {a.out}  ({time.time() - t0:.1f}s)")
    print(f"loại alert: {dict(cnt)}; phiên bị đánh dấu (coverage ngoài [{a.min_coverage}, {a.max_coverage}] / failed / lag > {a.max_lag}s): {len(low)}"
          + (" (đã loại)" if low and not a.keep_low_coverage else ""))
    print(f"coverage theo phiên: min={audit['coverage_min']} max={audit['coverage_max']}")
    print("số dòng theo split|nhãn:", audit["rows_by_split_label"])
    if cnt["ambiguous"] or cnt["unknown_in_range"]:
        print("CẢNH BÁO: có alert không gán được nhãn trong khoảng thời gian của batch — xem lại sổ IP / traffic ngoài generator.")
        for u in unknown[:20]:
            print(f"  alert lạ: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(u['event_epoch']))}Z (+{u['event_epoch'] - tmin - 60:.1f} s so với "
                  f"phiên đầu) {u['srcip']} {u['method']} {u['url']} {u['status']} rule {u['rule_id']} id {u['alert_id']}")


if __name__ == "__main__":
    main()
