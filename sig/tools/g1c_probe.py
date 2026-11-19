#!/usr/bin/env python3
"""g1c_probe.py — kiểm với ruleset ĐANG CHẠY (bộ luật cuối đã cài) rằng ba luật AI bắn đúng vị trí khi sự kiện SIEMLAB xen với
sự kiện access_log của cùng request, cùng IP. Chỉ dùng wazuh-logtest (không ghi file, không khởi động lại gì).
  python3 -B sig/tools/g1c_probe.py
Kỳ vọng: 110020 ở SIEMLAB #15, #30 (404); 110011 ở SIEMLAB #12, #24 (401); 110030 ở SIEMLAB #500, #1000 (200); không có 31151.
"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
from sig_probe import ex, BIN, cl, sl, g1_mix, g1_only  # noqa: E402
from replay_logtest import parse  # noqa: E402


def run(feed):
    rc, out = ex([f"{BIN}/wazuh-logtest"], inp="".join(l + "\n" for _, l in feed), timeout=900)
    return [(lab, r.get("rule_id")) for (lab, _), r in zip(feed, parse(out))]


mix200 = sum([[(f"SIEMLAB #{i + 1}", sl(i, "192.0.2.52", f"/q{i}.html", 200)),
               (f"combined #{i + 1}", cl("192.0.2.52", f"/q{i}.html?x={i}", 200))] for i in range(1000)], [])
cases = {"only_404": (g1_only(404), "110020", ["SIEMLAB #15", "SIEMLAB #30"]),
         "mix_404": (g1_mix(404), "110020", ["SIEMLAB #15", "SIEMLAB #30"]),
         "mix_401": (g1_mix(401), "110011", ["SIEMLAB #12", "SIEMLAB #24"]),
         "mix_200": (mix200, "110030", ["SIEMLAB #500", "SIEMLAB #1000"])}
out, ok = {}, True
for name, (feed, rid, exp) in cases.items():
    r = run(feed)
    fired = [lab for lab, x in r if x == rid]
    others = sorted({x for _, x in r if x and x not in ("100010", "100011", "100012", "31100", "31101", "31108", rid)})
    good = fired == exp and not others and len(r) == len(feed)
    ok &= good
    out[name] = {"lines": len(feed), "parsed": len(r), "rule": rid, "fired_at": fired, "expected": exp, "other_rules": others, "ok": good}
    print(name, json.dumps(out[name], ensure_ascii=False), flush=True)
json.dump(out, open(os.path.join(os.path.dirname(HERE), "runs", "g1c_probe.json"), "w"), indent=1)
print("KẾT QUẢ:", "ĐẠT" if ok else "KHÔNG ĐẠT")
