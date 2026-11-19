#!/usr/bin/env python3
"""sig_sim_all.py — mô phỏng (re của Python) một phiên bản bộ luật trên MỌI dữ liệu phát triển đã xem:
PayloadsAllTheThings (dev), SecLists (tập kiểm tra sơ bộ khi soạn luật), hai tập bình thường dùng khi soạn luật, hồi quy generator.
  python3 -B sig_sim_all.py [--gen sig_rules_gen.py] [--miss sqli]
Dòng log lấy từ các lần gửi thật (runs/p3a_*, runs/p5_test/*) nên URL đúng như Apache ghi.
"""
import argparse, collections, importlib.util, json, os, re, sys
HERE = os.path.dirname(os.path.abspath(__file__)); SIG = os.path.dirname(HERE)
URLRX = re.compile(r'^\S+ \S+ \S+ \[[^\]]+\] "\S+ (\S+) HTTP\S+" (\d{3}) ')


def load_gen(path):
    spec = importlib.util.spec_from_file_location("g", path); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return [(rid, re.compile(m.pat(p))) for rid, _, _, p in m.RULES]


def pairs(cases_file, access_files, filt=lambda c: True):
    C = [json.loads(l) for l in open(cases_file, encoding="utf-8")]
    out = []
    for af, f in access_files:
        cs = [c for c in C if f(c)]
        A = open(af, encoding="latin-1").read().splitlines()
        assert len(cs) == len(A), (af, len(cs), len(A))
        out += [(c, URLRX.match(a).group(1)) for c, a in zip(cs, A)]
    return out


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--gen", default=os.path.join(HERE, "sig_rules_gen.py"))
    ap.add_argument("--miss", default=None); ap.add_argument("--fp", action="store_true")
    a = ap.parse_args()
    R = load_gen(a.gen)
    P = os.path.join(SIG, "payloads"); RU = os.path.join(SIG, "runs")
    sets = {
        "PATT (dev)": pairs(f"{P}/dev/cases.jsonl", [(f"{RU}/p3a_dev/access_log.txt", lambda c: True)]),
        "SecLists": pairs(f"{P}/test/cases.jsonl", [(f"{RU}/p5_test/{k}/access_log.txt", (lambda k: lambda c: c["category"] == k)(k))
                                                     for k in ("sqli", "xss", "traversal", "cmdi")]),
        "benign_dev": pairs(f"{P}/benign_dev/cases.jsonl", [(f"{RU}/p3a_benign_dev/access_log.txt", lambda c: True)]),
        "benign_test": pairs(f"{P}/benign_test/cases.jsonl", [(f"{RU}/p5_test/benign/access_log.txt", lambda c: True)]),
    }
    hit = lambda u: next((rid for rid, rx in R if rx.search(u)), None)
    for nm, ps in sets.items():
        g = collections.defaultdict(lambda: [0, 0]); rules = collections.Counter()
        for c, u in ps:
            h = hit(u); g[c["category"]][0] += h is not None; g[c["category"]][1] += 1; g["TẤT CẢ"][0] += h is not None; g["TẤT CẢ"][1] += 1
            if h: rules[h] += 1
            if a.miss and nm != "PATT (dev)" and c["category"] == a.miss and not h and c["encoding"] == "E1":
                print("   LỌT", nm, u[:140])
            if a.fp and nm.startswith("benign") and h:
                print("   BÁO NHẦM", nm, h, u)
        print(f"{nm:<12} " + "  ".join(f"{k} {v[0]}/{v[1]} {100 * v[0] / v[1]:.1f}%" for k, v in sorted(g.items())))
    n = h_ = 0; rc = collections.Counter()
    for ln in open(f"{RU}/p3_regress/gen_distinct_access.log", encoding="latin-1"):
        m = URLRX.match(ln); n += 1; x = hit(m.group(1)) if m else None
        if x: h_ += 1; rc[x] += 1
    print(f"hồi quy generator: {h_}/{n} dòng khớp {dict(rc)}")


if __name__ == "__main__":
    main()
