#!/usr/bin/env python3
"""proposal_diff.py — bước 2c: so bộ luật vừa đề xuất (rules.json của rule_proposer) với bộ đang áp (đề xuất 'applied').
  python3 scripts/proposal_diff.py --rules output/rules_dev_rules3/rules.json [--proposals proposals]
Chỉ in, không đổi gì. Bộ đang áp là bộ CHÍNH THỨC; đề xuất từ batch mới (purpose=demo) chỉ minh họa quy trình."""
import argparse, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
from compare_rules import applied_rules
from rule_proposer import FAMILIES


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rules", required=True); ap.add_argument("--proposals", default=os.path.join(os.path.dirname(HERE), "proposals"))
    a = ap.parse_args(argv)
    M = json.load(open(a.rules, encoding="utf-8"))
    cur = applied_rules(a.proposals)
    new = M.get("chosen", {})
    sel = M["results"]["SELECT"]
    print(f"Đề xuất từ {os.path.basename(M['data'])} (mục đích: {M.get('purpose', 'official')}, nhãn: {M.get('label_source', 'truth')}), "
          f"chọn trên {M.get('select_name') or '+'.join(M['select_splits'])}: "
          f"cả bộ bắt {sel['union']['detected']}/{sel['union']['attack_sessions']}, báo nhầm {sel['union']['false_alarm']}/"
          f"{sel['union']['benign_sessions']} (ngưỡng {M['allowed_false_alarm_sessions']})")
    print(f"{'họ':10s} {'đang áp (chính thức)':24s} {'đề xuất mới':16s} so sánh")
    same = 0
    for f in FAMILIES:
        c = cur.get(f); n = new.get(f)
        cs = f"N={c['N']} T={c['T']}s ({c['rule_id']})" if c else "—"
        ns = f"N={n['N']} T={n['T']}s" if n else "—"
        if not c and not n:
            continue
        verdict = ("giống" if c and n and c["N"] == n["N"] and c["T"] == n["T"] else
                   "MỚI (chưa áp họ này)" if n and not c else "đề xuất mới KHÔNG dùng họ này" if c and not n else "KHÁC tham số")
        same += verdict == "giống"
        print(f"{f:10s} {cs:24s} {ns:16s} {verdict}")
    w = M.get("proposals_written") or []
    print(f"đề xuất mới được ghi: {w or '(không — trùng fingerprint với đề xuất đã có)'}")
    if M.get("purpose") == "demo":
        print("-> MINH HỌA: không áp. Người duyệt xem bằng `apply_rule.py show <pid>`; apply_rule chặn purpose=demo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
