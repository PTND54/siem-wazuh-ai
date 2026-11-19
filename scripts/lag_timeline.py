#!/usr/bin/env python3
"""lag_timeline.py — vì sao generator bị trễ lịch (lag)? So hai batch CÙNG kế hoạch (cùng preset + seed, vd. dev1 và
dev_rules1) theo từng khung thời gian tính từ đầu batch.

  python3 scripts/lag_timeline.py --batches data/runs/dev1 data/runs/dev_rules1 \
      --alerts /wazuh-logs/alerts/alerts.json '/wazuh-logs/alerts/*/*/ossec-alerts-*.json*' [--bucket 60]

Mỗi khung, mỗi batch: số request/giây đã gửi, số phiên đang chạy, trễ lịch generator (p99, max — từ requests/*.jsonl),
trễ Manager − Apache của alert SIEMLAB (p95, max — từ alerts). Cùng kế hoạch mà một batch trễ hơn ở cùng khung ->
do môi trường lúc chạy (luật AI, ai-service, máy bận), không do kế hoạch. Trễ Manager tăng cùng lúc -> Manager quá tải.
"""
import argparse, glob, json, os, sys
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import warnings
import numpy as np
warnings.filterwarnings("ignore", "All-NaN")
from audit_coverage import _open, expand, siemlab_match


def load_batch(d):
    S = [json.loads(l) for l in open(os.path.join(d, "sessions.jsonl"), encoding="utf-8")]
    t0 = min(s["t_first"] for s in S if s.get("t_first"))
    req = []                                                   # (offset giây, lag)
    for p in glob.glob(os.path.join(d, "requests", "*.jsonl")):
        for l in open(p, encoding="utf-8"):
            r = json.loads(l)
            if r.get("t_sent"):
                req.append((r["t_sent"] - t0, r.get("lag") or 0.0))
    spans = [(s["t_first"] - t0, s["t_last"] - t0, s.get("max_lag") or 0) for s in S if s.get("t_first")]
    ips = {s["srcip"] for s in S}
    return {"name": os.path.basename(d.rstrip("/")), "t0": t0, "t1": max(s["t_last"] for s in S if s.get("t_last")),
            "req": np.array(req) if req else np.zeros((0, 2)), "spans": spans, "ips": ips,
            "lag_sessions": sum(1 for s in S if (s.get("max_lag") or 0) > 2.0), "n": len(S)}


def manager_latency(paths, batches):
    """offset (theo t0 của batch chứa nó) và trễ Manager − Apache cho alert SIEMLAB của các IP trong batch."""
    out = {b["name"]: [] for b in batches}
    seen = set()
    for p in paths:
        with _open(p) as f:
            for l in f:
                if "SIEMLAB" not in l:
                    continue
                try:
                    a = json.loads(l)
                except Exception:
                    continue
                if a.get("id") in seen:
                    continue
                seen.add(a.get("id"))
                m = siemlab_match(a)
                if not m:
                    continue
                te = int(m[1]) / 1e6
                for b in batches:
                    if b["t0"] - 1 <= te <= b["t1"] + 1 and m[2] in b["ips"]:
                        tm = datetime.strptime(a["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
                        out[b["name"]].append((te - b["t0"], tm - te))
                        break
    return {k: np.array(v) if v else np.zeros((0, 2)) for k, v in out.items()}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--batches", nargs="+", required=True)
    ap.add_argument("--alerts", nargs="*", default=[])
    ap.add_argument("--bucket", type=float, default=60.0)
    ap.add_argument("--monitor", default=None, help="CSV của setup/monitor.sh (ts,kind,key,value) — ghép theo batch CUỐI")
    a = ap.parse_args(argv)
    B = [load_batch(d) for d in a.batches]
    lat = manager_latency(expand(a.alerts, "alert"), B) if a.alerts else {}
    q = lambda x, p: f"{np.quantile(x, p):5.2f}" if len(x) else "    —"
    mx = lambda x: f"{x.max():5.2f}" if len(x) else "    —"
    for b in B:
        L = lat.get(b["name"], np.zeros((0, 2)))
        print(f"{b['name']}: {b['n']} phiên, {len(b['req'])} request, dài {b['t1'] - b['t0']:.0f} s, phiên lag > 2 s: {b['lag_sessions']}; "
              f"lag generator max {mx(b['req'][:, 1]) if len(b['req']) else '—'}; alert SIEMLAB khớp {len(L)}, "
              f"trễ Manager p95 {q(L[:, 1], .95) if len(L) else '—'} max {mx(L[:, 1]) if len(L) else '—'}; "
              f"bắt đầu {datetime.fromtimestamp(b['t0']).strftime('%Y-%m-%d %H:%M:%S')} (giờ máy chạy script)")
    end = max(b["t1"] - b["t0"] for b in B)
    hdr = "khung (s)  | " + " | ".join(f"{b['name'][:12]:>12s}: req/s phiên lag99 lagmax  mgr95 mgrmax" for b in B)
    print("\n" + hdr); print("-" * len(hdr))
    k = 0.0
    while k < end + a.bucket:
        row = [f"{k:5.0f}-{k + a.bucket:<5.0f}"]
        for b in B:
            R = b["req"]; m = (R[:, 0] >= k) & (R[:, 0] < k + a.bucket) if len(R) else np.zeros(0, bool)
            act = sum(1 for s0, s1, _ in b["spans"] if s0 < k + a.bucket and s1 >= k)
            L = lat.get(b["name"], np.zeros((0, 2)))
            ml = (L[:, 0] >= k) & (L[:, 0] < k + a.bucket) if len(L) else np.zeros(0, bool)
            lg = R[m, 1] if len(R) else np.zeros(0)
            lm = L[ml, 1] if len(L) else np.zeros(0)
            row.append(f"{'':>12s}  {m.sum() / a.bucket:5.1f} {act:5d} {q(lg, .99)} {mx(lg)}  {q(lm, .95)} {mx(lm)}")
        print(" | ".join(row))
        k += a.bucket
    if a.monitor:
        monitor_table(a.monitor, B[-1], a.bucket, end)


def _mib(v):
    v = v.strip()
    for u, f in (("GiB", 1024), ("MiB", 1), ("KiB", 1 / 1024), ("GB", 1000), ("MB", 1), ("kB", 1 / 1000), ("B", 1 / 2 ** 20)):
        if v.endswith(u):
            try:
                return float(v[:-len(u)]) * f
            except ValueError:
                return np.nan
    try:
        return float(v)
    except ValueError:
        return np.nan


def monitor_table(path, b, bucket, end):
    """Theo khung của batch b: RAM còn dùng được (min), swap (max), PSI (max), Redis đang ghi đĩa nền, container ngốn CPU."""
    rows = []
    for l in open(path, encoding="utf-8"):
        p = l.rstrip("\n").split(",", 3)
        if len(p) < 4 or p[0] == "ts":
            continue
        try:
            rows.append((float(p[0]) - b["t0"], p[1], p[2], p[3]))
        except ValueError:
            continue
    print(f"\nGiám sát ({os.path.basename(path)}, {len(rows)} mẫu) theo khung của {b['name']}:")
    print("khung (s)  | RAMcòn(MiB) swap(MiB) PSImem PSIio PSIcpu | redis ghi nền | CPU% cao nhất (container)")
    k = 0.0
    while k < end + bucket:
        R = [r for r in rows if k <= r[0] < k + bucket]
        num = lambda kind, key: np.array([float(r[3]) for r in R if r[1] == kind and r[2] == key and r[3].strip() not in ("", "nan")] or [np.nan])
        avail, swap = np.nanmin(num("sys", "mem_avail_mb")), np.nanmax(num("sys", "swap_used_mb"))
        pm, pi, pc = (np.nanmax(num("psi", x)) for x in ("memory_some_avg10", "io_some_avg10", "cpu_some_avg10"))
        rw = [r[2] for r in R if r[1] == "redis" and r[2] in ("aof_rewrite_in_progress", "rdb_bgsave_in_progress") and r[3].strip() == "1"]
        cpu = {}
        for r in R:
            if r[1] == "cpu":
                try:
                    cpu[r[2]] = max(cpu.get(r[2], 0.0), float(r[3]))
                except ValueError:
                    pass
        top = ", ".join(f"{n} {c:.0f}" for n, c in sorted(cpu.items(), key=lambda x: -x[1])[:3])
        f = lambda x, w=6: f"{x:{w}.0f}" if np.isfinite(x) else " " * (w - 1) + "—"
        g = lambda x: f"{x:6.1f}" if np.isfinite(x) else "     —"
        print(f"{k:5.0f}-{k + bucket:<5.0f}| {f(avail, 11)} {f(swap, 9)} {g(pm)} {g(pi)} {g(pc)} | "
              f"{('CÓ ' + '/'.join(sorted(set(x.split('_')[0] for x in rw)))) if rw else 'không':13s} | {top}")
        k += bucket


if __name__ == "__main__":
    main()
