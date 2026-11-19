#!/usr/bin/env python3
"""ci_payload.py — khoảng tin cậy 95% cho tập payload giữ riêng (p6) theo đơn vị PAYLOAD.

Bootstrap 1.000 lần, seed 12345, khoảng phân vị 2,5–97,5; mỗi tỉ lệ một lần lấy mẫu (numpy default_rng(12345)).
Hiệu giữa hai bộ luật: bootstrap ghép cặp trên cùng danh sách payload. Giá trị bình thường: đơn vị là giá trị (gộp F và E1).
  python3 -B tools/ci_payload.py > runs/ci_payload_v2.json
"""
import json, os, sys
from collections import defaultdict
import numpy as np

SIG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
rows = json.load(open(os.path.join(SIG, "runs", "p6_test2_measure.json")))["rows"]


def boot(a, b=None, reps=1000, seed=12345):
    a = np.array(a, float); rng = np.random.default_rng(seed); idx = rng.integers(0, len(a), (reps, len(a)))
    m = a[idx].mean(1) * 100 if b is None else (a[idx].mean(1) - np.array(b, float)[idx].mean(1)) * 100
    return [float(np.percentile(m, 2.5)), float(np.percentile(m, 97.5))]


out = {"method": "bootstrap theo payload, 1000 lần, seed 12345, phân vị 2,5-97,5", "test2": {}, "benign2": {}}
for cat in ["sqli", "xss", "traversal", "cmdi"]:
    for enc in ["E1", "E2", "E3"]:
        R = [r for r in rows if r["set"] == "test2" and r["category"] == cat and r["encoding"] == enc]
        s = [bool(r["real_sig"]) for r in R]; b = [bool(r["builtin"]) for r in R]; u = [bool(r["real_union"]) for r in R]
        out["test2"][f"{cat}/{enc}"] = {"n": len(R), "sig": sum(s), "builtin": sum(b), "union": sum(u),
                                       "sig_ci": boot(s), "builtin_ci": boot(b), "union_ci": boot(u),
                                       "diff": (sum(s) - sum(b)) * 100 / len(R), "diff_ci": boot(s, b)}
g = defaultdict(lambda: [False, False])
for r in rows:
    if r["set"] == "benign2":
        g[r["payload_sha256"]][0] |= bool(r["real_sig"]); g[r["payload_sha256"]][1] |= bool(r["builtin"])
s = [v[0] for v in g.values()]; b = [v[1] for v in g.values()]
out["benign2"] = {"n": len(s), "sig": sum(s), "builtin": sum(b), "sig_ci": boot(s), "builtin_ci": boot(b),
                  "diff": (sum(s) - sum(b)) * 100 / len(s), "diff_ci": boot(s, b)}
json.dump(out, sys.stdout, ensure_ascii=False, indent=1)
