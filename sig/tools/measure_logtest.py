#!/usr/bin/env python3
"""measure_logtest.py — lập bảng phát hiện / báo nhầm từ kết quả sig_eval.py (đo bằng logtest).

  python3 -B measure_logtest.py --run ../runs/<tên lần chạy> --sets dev benign_dev [--regress] [--sim]

Định nghĩa (như PREREG.md mục 3):
  dựng sẵn  = cấu hình base, alert của luật dựng sẵn xét nội dung (BUILTIN_CONTENT)
  chữ ký    = cấu hình sig, rule id 100100–100199
  hợp       = cấu hình sig, alert dựng sẵn xét nội dung HOẶC 1001xx (luật chữ ký L8 che dựng sẵn khi cùng khớp)
Khoảng tin cậy Wilson 95%.
"""
import argparse, collections, json, math, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__)); SIG = os.path.dirname(HERE)
BUILTIN_CONTENT = {str(i) for i in [31103, 31104, 31105, 31106, 31109, 31110, 31115, 31152, 31153, 31154,
                                    31164, 31165, 31166, 31167, 31168, 31169, 31170, 31171]} | {str(i) for i in range(31501, 31560)}


def is_sig(r):
    return r.get("rule_id", "") and r["rule_id"].isdigit() and 100100 <= int(r["rule_id"]) <= 100199 and r.get("alert")


def is_builtin(r):
    return r.get("rule_id") in BUILTIN_CONTENT and r.get("alert")


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"),) * 2
    p = k / n; d = 1 + z * z / n; c = p + z * z / (2 * n); h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (c - h) / d, (c + h) / d


def fmt(k, n):
    lo, hi = wilson(k, n)
    return f"{k:>4}/{n:<4} {100 * k / n:5.1f}% [{100 * lo:4.1f}–{100 * hi:5.1f}]" if n else "-"


def load(run, cfg, st):
    return [json.loads(l) for l in open(os.path.join(run, f"{cfg}_{st}.jsonl"), encoding="utf-8")]


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--run", required=True)
    ap.add_argument("--sets", nargs="*", default=["dev", "benign_dev"]); ap.add_argument("--regress", action="store_true")
    ap.add_argument("--json", default=None); ap.add_argument("--misses", type=int, default=0)
    a = ap.parse_args()
    out = {}
    for st in a.sets:
        C = [json.loads(l) for l in open(os.path.join(SIG, "payloads", st, "cases.jsonl"), encoding="utf-8")]
        B, S = load(a.run, "base", st), load(a.run, "sig", st)
        assert len(C) == len(B) == len(S), (st, len(C), len(B), len(S))
        rows = []
        for c, b, s in zip(C, B, S):
            assert b["n"] == s["n"]
            rows.append({**c, "base_rule": b.get("rule_id"), "sig_rule": s.get("rule_id"), "decoder": s.get("decoder"),
                         "logurl": s.get("url"), "status": s.get("status"),
                         "builtin": is_builtin(b), "sig": is_sig(s), "union": is_sig(s) or is_builtin(s)})
        out[st] = rows
        print(f"\n===== {st} ({len(rows)} ca)   decoder: {dict(collections.Counter(r['decoder'] for r in rows))}")
        keys = [("category",), ("category", "encoding")] + ([("category", "placement")] if st == "dev" else [])
        print(f"{'nhóm':<26} {'dựng sẵn':<28} {'chữ ký':<28} {'hợp':<28}")
        groups = collections.defaultdict(list)
        for r in rows:
            groups[("TẤT CẢ",)].append(r)
            for k in keys:
                groups[tuple(r[x] for x in k)].append(r)
        for g in sorted(groups, key=lambda x: (x != ("TẤT CẢ",), x)):
            rs = groups[g]; n = len(rs)
            print(f"{' / '.join(g):<26} {fmt(sum(r['builtin'] for r in rs), n):<28} {fmt(sum(r['sig'] for r in rs), n):<28} "
                  f"{fmt(sum(r['union'] for r in rs), n):<28}")
        print("  rule (base):", collections.Counter(r["base_rule"] for r in rows).most_common(12))
        print("  rule (sig): ", collections.Counter(r["sig_rule"] for r in rows).most_common(20))
        if a.misses:
            for r in [r for r in rows if not r["union"]][:a.misses] if not st.startswith("benign") else [r for r in rows if r["union"]]:
                print(f"   {'LỌT' if not st.startswith('benign') else 'BÁO NHẦM'} {r['category']:<10} {r['encoding']} st={r['status']} "
                      f"sig={r['sig_rule']} {r['logurl'][:120] if r['logurl'] else r['decoder']}")
    if a.regress:
        B, S = load(a.run, "base", "regress"), load(a.run, "sig", "regress")
        print(f"\n===== hồi quy generator ({len(S)} dòng khác nhau)")
        print("  dựng sẵn xét nội dung có alert:", sum(is_builtin(r) for r in B), collections.Counter(r["rule_id"] for r in B if is_builtin(r)).most_common(8))
        print("  luật chữ ký có alert:", sum(is_sig(r) for r in S), collections.Counter(r["rule_id"] for r in S if is_sig(r)).most_common(8))
        print("  alert bất kỳ — base:", sum(bool(r.get("alert")) for r in B), " sig:", sum(bool(r.get("alert")) for r in S))
        print("  rule (sig):", collections.Counter(r["rule_id"] for r in S).most_common(10))
    if a.json:
        json.dump(out, open(a.json, "w", encoding="utf-8"), ensure_ascii=False)


if __name__ == "__main__":
    main()
