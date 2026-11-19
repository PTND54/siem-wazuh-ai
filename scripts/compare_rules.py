#!/usr/bin/env python3
"""compare_rules.py — bước 2b-3: luật đề xuất chạy trên Wazuh THẬT có giống mô phỏng (wazuh_sim) không?

  python3 scripts/compare_rules.py --data data/dataset_dev_rules1.csv \
      --alerts /wazuh-logs/alerts/alerts.json '/wazuh-logs/alerts/*/*/ossec-alerts-*.json*' [--proposals proposals]
  -> output/compare_<tên dataset>/{report.md, compare.json}

Đầu vào: dataset dựng bằng build_dataset.py TRONG LÚC luật đang áp (cột rule_id = rule Wazuh thực sự sinh alert cho
dòng log đó: 10001x hoặc 110xxx), alerts.json (lấy giờ Manager `timestamp` cho từng dòng log), và các hồ sơ đề xuất
đang ở trạng thái 'applied' (họ, N, T, id luật).

Với mỗi phiên và mỗi luật: tập dòng "thật" (rule_id == id luật) so với tập dòng mô phỏng theo 3 cách tính giờ:
  apache      — giờ Apache (event_usec), như rule_proposer/trainer dùng;
  manager     — giờ Manager (alert.timestamp, mili giây);
  manager_sec — giờ Manager làm tròn xuống giây (Wazuh so timeframe theo giây);
  joint       — giờ như manager_sec nhưng mô phỏng CHUNG mọi luật đang áp theo thứ tự nạp (wazuh_sim.joint_fires:
                danh sách đếm theo rule cuối cùng, sid trước nhóm, dấu khớp chặn cả luật khác) — thêm 26/10 sau run2b.
Báo: khớp từng dòng (số phiên trùng hoàn toàn), khớp mức phiên (bắt/không bắt), phân bố trễ Manager − Apache, mỗi chỗ
lệch kèm khoảng thời gian thực tế của N sự kiện tính đến dòng đó (để thấy lệch có phải do sát biên T không), và số dòng
mô phỏng cho >= 2 luật cùng khớp (Wazuh chỉ sinh MỘT alert cho mỗi sự kiện).
"""
import argparse, json, math, os, sys
from collections import Counter, OrderedDict, defaultdict
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import numpy as np
import pandas as pd
import wazuh_sim as W
from audit_coverage import _open, expand, siemlab_match
from rule_proposer import FAMILIES

VARIANTS = ("apache", "manager", "manager_sec", "joint")


def parse_ts(s):
    """'2026-10-21T11:21:33.123+0000' -> epoch giây (float)."""
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()


def read_alert_times(paths, lo, hi):
    """(srcip, usec, url, status) -> (rule_id, giờ Manager) cho alert SIEMLAB có giờ Apache trong [lo, hi]."""
    out, seen = {}, set()
    for p in paths:
        with _open(p) as f:
            for l in f:
                if "SIEMLAB" not in l: continue
                try: a = json.loads(l)
                except Exception: continue
                aid = a.get("id")
                if aid in seen: continue
                seen.add(aid)
                m = siemlab_match(a)
                if not m: continue
                usec = int(m[1])
                if not (lo <= usec / 1e6 <= hi): continue
                key = (m[2], usec, m[4], int(m[5]))
                if key not in out:
                    out[key] = (str(a["rule"]["id"]), parse_ts(a["timestamp"]))
    return out


def applied_rules(pdir):
    rules = OrderedDict()
    for fn in sorted(os.listdir(pdir)):
        if not fn.endswith(".json"): continue
        c = json.load(open(os.path.join(pdir, fn), encoding="utf-8"))
        if c.get("status") == "applied" and c.get("family") in FAMILIES:
            ap_t = [h.get("at", "") for h in c.get("history", []) if h.get("action") == "apply"]
            rules[c["family"]] = {"pid": c["proposal_id"], "rule_id": str(FAMILIES[c["family"]]["rule_id"]),
                                  "N": int(c["params"]["frequency"]), "T": int(c["params"]["timeframe"]),
                                  "applied_at": ap_t[-1] if ap_t else ""}
    # thứ tự nạp trong file luật AI = thứ tự áp (apply_rule nối khối vào cuối file)
    return OrderedDict(sorted(rules.items(), key=lambda kv: (kv[1]["applied_at"], int(kv[1]["rule_id"]))))


def joint_specs(rules):
    """Luật đang áp -> đặc tả cho wazuh_sim.joint_fires (cùng LEVEL và chuỗi group như rule_proposer.rule_xml)."""
    from rule_proposer import LEVEL
    out = []
    for f, r in rules.items():
        cond = FAMILIES[f]["cond"]
        d = {"id": int(r["rule_id"]), "level": LEVEL, "N": r["N"], "T": r["T"],
             "groups": f"ai_generated,siem10_{f},attack,ai_generated,"}
        val = cond.split(">")[1].split("<")[0]
        if "if_matched_sid" in cond: d["sid"] = int(val)
        else: d["group"] = val
        out.append(d)
    return out


def window_span(times, idx_member, pos, N):
    """Khoảng thời gian của N sự kiện cha tính đến (gồm) sự kiện thứ pos trong idx_member."""
    j = idx_member.index(pos) if pos in idx_member else None
    if j is None or j < N - 1: return None
    return round(times[idx_member[j]] - times[idx_member[j - N + 1]], 3)


def compare(df, times, rules):
    """df: các dòng của MỘT tập (đã sắp theo phiên, giờ Apache). times: {variant: array giờ}. Trả kết quả."""
    res = {v: {f: {"sessions": 0, "exact": 0, "session_agree": 0, "actual_detected": 0, "sim_detected": 0,
                   "actual_fires": 0, "sim_fires": 0, "mismatches": []} for f in rules} for v in VARIANTS}
    multi = Counter()
    for key, g in df.groupby("session_key", sort=False):
        ix = g.index.to_numpy()
        st = g.status.to_numpy(int)
        actual_rule = g.rule_id.astype(str).to_numpy()
        jf = W.joint_fires(times["manager_sec"][ix].tolist(), st, joint_specs(rules))
        for v in VARIANTS:
            t = times["manager_sec" if v == "joint" else v][ix]
            sim_any = defaultdict(int)
            for f, r in rules.items():
                mem = FAMILIES[f]["member"](st)
                pos = [int(k) for k in np.flatnonzero(mem)]
                if v == "joint":
                    sim = {k for k, x in enumerate(jf) if str(x) == r["rule_id"]}
                else:
                    fires = W.freq_fires(t[pos].tolist(), r["N"], r["T"]) if pos else []
                    sim = {pos[j] for j, x in enumerate(fires) if x}
                act = {int(k) for k in np.flatnonzero(actual_rule == r["rule_id"])}
                for k in sim: sim_any[k] += 1
                R = res[v][f]
                R["sessions"] += 1; R["actual_fires"] += len(act); R["sim_fires"] += len(sim)
                R["exact"] += act == sim; R["session_agree"] += bool(act) == bool(sim)
                R["actual_detected"] += bool(act); R["sim_detected"] += bool(sim)
                if act != sim and len(R["mismatches"]) < 200:
                    R["mismatches"].append({
                        "session": key, "scenario": g.scenario.iloc[0], "label": int(g.label.iloc[0]),
                        "only_actual": sorted(act - sim)[:10], "only_sim": sorted(sim - act)[:10],
                        "span_only_actual_s": [window_span(t, pos, k, r["N"]) for k in sorted(act - sim)[:5]],
                        "span_only_sim_s": [window_span(t, pos, k, r["N"]) for k in sorted(sim - act)[:5]],
                        "T": r["T"], "N": r["N"]})
            if v == "manager_sec":
                multi["events_with_2plus_sim_rules"] += sum(1 for c in sim_any.values() if c >= 2)
    return res, dict(multi)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", required=True); ap.add_argument("--alerts", required=True, nargs="+")
    ap.add_argument("--proposals", default=os.path.join(ROOT, "proposals"))
    ap.add_argument("--out", default=None)
    a = ap.parse_args(argv)
    rules = applied_rules(a.proposals)
    if not rules:
        sys.exit("Không có đề xuất nào ở trạng thái 'applied' trong " + a.proposals)
    df = pd.read_csv(a.data, low_memory=False, float_precision="round_trip")
    df = df.sort_values(["session_key", "event_epoch"], kind="mergesort").reset_index(drop=True)
    lo, hi = df.event_epoch.min() - 1, df.event_epoch.max() + 1
    amap = read_alert_times(expand(a.alerts, "alert"), lo, hi)
    keys = list(zip(df.srcip, (df.event_epoch * 1e6).round().astype("int64"), df.url, df.status.astype(int)))
    mgr = np.array([amap[k][1] if k in amap else np.nan for k in keys])
    rid_alert = [amap[k][0] if k in amap else None for k in keys]
    n_missing = int(np.isnan(mgr).sum())
    n_rule_diff = int(sum(1 for x, y in zip(rid_alert, df.rule_id.astype(str)) if x is not None and x != y))
    if n_missing:
        print(f"CẢNH BÁO: {n_missing} dòng dataset không tìm thấy alert tương ứng -> dùng giờ Apache cho các dòng đó")
        mgr = np.where(np.isnan(mgr), df.event_epoch.to_numpy(), mgr)
    times = {"apache": df.event_epoch.to_numpy(float), "manager": mgr, "manager_sec": np.floor(mgr)}
    lat = mgr - df.event_epoch.to_numpy(float)
    latency = {"median_s": float(np.median(lat)), "p95_s": float(np.quantile(lat, .95)), "p99_s": float(np.quantile(lat, .99)),
               "max_s": float(lat.max()), "min_s": float(lat.min())}
    res, multi = compare(df, times, rules)
    rule_counts = df.rule_id.astype(str).value_counts().to_dict()
    stem = os.path.splitext(os.path.basename(a.data))[0].replace("dataset_", "")
    out = a.out or os.path.join(ROOT, "output", f"compare_{stem}")
    os.makedirs(out, exist_ok=True)
    M = {"data": a.data, "rules": rules, "rows": len(df), "sessions": int(df.session_key.nunique()),
         "rows_without_alert": n_missing, "rows_rule_id_differs_from_alert": n_rule_diff, "rule_id_counts": rule_counts,
         "latency_manager_minus_apache": latency, "results": res, "interaction": multi}
    json.dump(M, open(os.path.join(out, "compare.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
    L = [f"# Luật thật so với mô phỏng — {os.path.basename(a.data)}", "",
         f"{M['rows']} dòng, {M['sessions']} phiên. Luật đang áp: " + ", ".join(f"{f} ({r['rule_id']}: N={r['N']}, T={r['T']}s)" for f, r in rules.items()),
         f"Alert theo rule trong dataset: {rule_counts}. Dòng không tìm thấy alert: {n_missing}.", "",
         f"Trễ Manager − Apache: trung vị {latency['median_s']:.3f} s, p95 {latency['p95_s']:.3f} s, p99 {latency['p99_s']:.3f} s, "
         f"max {latency['max_s']:.3f} s, min {latency['min_s']:.3f} s.", "",
         "| cách tính giờ | luật | phiên khớp từng dòng | phiên khớp bắt/không bắt | phiên thật bắt | phiên mô phỏng bắt | lần khớp thật | lần khớp mô phỏng |",
         "|---|---|---|---|---|---|---|---|"]
    for v in VARIANTS:
        for f, R in res[v].items():
            L.append(f"| {v} | {f} | {R['exact']}/{R['sessions']} | {R['session_agree']}/{R['sessions']} | {R['actual_detected']} | "
                     f"{R['sim_detected']} | {R['actual_fires']} | {R['sim_fires']} |")
    L += ["", f"Dòng mà mô phỏng độc lập (manager_sec) cho >= 2 luật cùng khớp (Wazuh chỉ sinh 1 alert): {multi.get('events_with_2plus_sim_rules', 0)}",
          "Thứ tự nạp dùng cho 'joint': " + " -> ".join(f"{f} ({r['rule_id']})" for f, r in rules.items()), "",
          "## Chỗ lệch (joint, tối đa 20 mỗi luật)", "",
          "Dòng = vị trí trong phiên (0-based). span = giây giữa sự kiện cha thứ 1 và thứ N tính đến dòng đó (so với T).", ""]
    for f, R in res["joint"].items():
        for mm in R["mismatches"][:20]:
            L.append(f"- {f} · {mm['session']} ({mm['scenario']}, nhãn {mm['label']}): chỉ thật {mm['only_actual']} span {mm['span_only_actual_s']}; "
                     f"chỉ mô phỏng {mm['only_sim']} span {mm['span_only_sim_s']} (T={mm['T']}, N={mm['N']})")
    open(os.path.join(out, "report.md"), "w", encoding="utf-8").write("\n".join(L) + "\n")
    print("\n".join(L[:12 + len(VARIANTS) * len(rules) + 3]))
    print(f"-> {out}/report.md")
    return M


if __name__ == "__main__":
    main()
