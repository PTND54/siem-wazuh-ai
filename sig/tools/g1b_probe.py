#!/usr/bin/env python3
"""g1b_probe.py — kiểm luật AI 110030 (if_matched_group siemlab_observed, N=500/10 s) có đếm cả sự kiện access_log không.
Chỉ dùng wazuh-logtest với ruleset ĐANG CHẠY (không ghi file, không khởi động lại gì). Chạy trên HOST (WSL).
  python3 -B sig/tools/g1b_probe.py
Ba ca, mỗi ca một phiên logtest, một IP TEST-NET riêng:
  only   : 1000 dòng SIEMLAB 200                                  -> kỳ vọng 110030 ở SIEMLAB #500, #1000
  mix_q  : 1000 cặp SIEMLAB 200 + combined 200 có '?' (luật 31100) -> nếu combined KHÔNG được đếm: #500, #1000
  mix_s  : 1000 cặp SIEMLAB 200 + combined 200 không '?' (31108)
"""
import json, os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
from sig_probe import ex, BIN, cl, sl  # noqa: E402
from replay_logtest import parse  # noqa: E402


def run(feed):
    rc, out = ex([f"{BIN}/wazuh-logtest"], inp="".join(l + "\n" for _, l in feed), timeout=900)
    res = parse(out)
    return [(lab, r.get("rule_id")) for (lab, _), r in zip(feed, res)], len(res)


cases = {
    "only": [(f"SIEMLAB #{i + 1}", sl(i, "192.0.2.41", f"/o{i}.html", 200)) for i in range(1000)],
    "mix_q": sum([[(f"SIEMLAB #{i + 1}", sl(i, "192.0.2.42", f"/q{i}.html", 200)),
                   (f"combined #{i + 1}", cl("192.0.2.42", f"/q{i}.html?x={i}", 200))] for i in range(1000)], []),
    "mix_s": sum([[(f"SIEMLAB #{i + 1}", sl(i, "192.0.2.43", f"/s{i}.html", 200)),
                   (f"combined #{i + 1}", cl("192.0.2.43", f"/s{i}.html", 200))] for i in range(1000)], []),
}
out = {}
for name, feed in cases.items():
    t = time.time(); r, n = run(feed)
    fired = [lab for lab, rid in r if rid == "110030"]
    other = sorted({rid for _, rid in r if rid not in ("100010", "110030", "31100", "31108")})
    out[name] = {"parsed": n, "lines": len(feed), "110030_at": fired, "other_rules": other, "s": round(time.time() - t, 1)}
    print(name, json.dumps(out[name], ensure_ascii=False), flush=True)
json.dump(out, open(os.path.join(os.path.dirname(HERE), "runs", "g1b_probe.json"), "w"), indent=1)
