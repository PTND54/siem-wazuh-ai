#!/usr/bin/env python3
"""build_payloads_v2.py — dựng tập giữ riêng của đánh giá cuối (FuzzDB) và tập bình thường mới (benign2), theo PREREG.md.
KHÔNG in nội dung payload; chỉ in số lượng và thống kê hình dạng (độ dài, tỉ lệ dòng có ký tự đặc biệt).

  python3 -I build_payloads_v2.py --src src --out payloads [--stats-only]
"""
import argparse, collections, hashlib, json, os, random, re, statistics, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_payloads import build_cases, h, norm, MAXLEN  # noqa: E402

PH = re.compile(r"\{[A-Za-z_]{2,12}\}")
SPECIAL = set("<>()'\";=%|&`$/\\")


def read(path):
    raw = open(path, "rb").read().decode("utf-8", "replace").splitlines()
    kept, drop = [], collections.Counter()
    for s in raw:
        s = s.rstrip("\r\n")
        if not s.strip(): drop["rỗng"] += 1; continue
        if len(s) > MAXLEN: drop["dài"] += 1; continue
        if "�" in s: drop["không UTF-8"] += 1; continue
        if s.startswith("# "): drop["chú thích"] += 1; continue
        if PH.search(s): drop["chỗ giữ chỗ {..}"] += 1; continue
        kept.append(s)
    return kept, drop


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--src", default="src"); ap.add_argument("--out", default="payloads")
    ap.add_argument("--seed", type=int, default=20261116); ap.add_argument("--n", type=int, default=120)
    ap.add_argument("--stats-only", action="store_true")
    a = ap.parse_args()
    seen = set()
    for st in ("dev", "test"):                       # PayloadsAllTheThings + SecLists = dữ liệu phát triển
        for fn in os.listdir(os.path.join(a.src, st)):
            for s in open(os.path.join(a.src, st, fn), "rb").read().decode("utf-8", "replace").splitlines():
                seen.add(norm(s.replace("{FILE}", "etc/passwd")))
    man = [l.split() for l in open(os.path.join(a.src, "manifest_test2.txt"), encoding="utf-8") if not l.startswith("fetched")]
    # SỬA ĐỔI 1 (trước khi gửi, PREREG mục 4): bỏ file tài liệu JHADDIX_XSS_WITH_CONTEXT.doc (68% dòng là văn xuôi)
    man = [m for m in man if "JHADDIX_XSS_WITH_CONTEXT" not in m[2]]
    # SỬA ĐỔI 2: điền chỗ giữ chỗ {cmd} của command-injection-template bằng lệnh lấy ngẫu nhiên từ FuzzDB Commands-Linux/Windows
    fills = []
    for fn in ("cmdfill__Commands-Linux.txt", "cmdfill__Commands-Windows.txt"):
        fills += [x.strip() for x in open(os.path.join(a.src, "test2", fn), encoding="utf-8", errors="replace") if x.strip() and not x.startswith("#")]
    rf = random.Random(a.seed + 1)
    pools, summ = collections.defaultdict(list), {"seed": a.seed, "files": [], "drop": {}}
    for _, cat, name, sha, *_ in man:
        p = os.path.join(a.src, "test2", f"{cat}__{name}")
        assert hashlib.sha256(open(p, "rb").read()).hexdigest() == sha, p
        if "command-injection-template" in name:
            tpl = [s.rstrip("\r\n") for s in open(p, encoding="utf-8", errors="replace") if s.strip()]
            raw_inst = [PH.sub(c, s) for s in tpl for c in rf.sample(fills, 2)]
            kept, drop = [x for x in raw_inst if len(x) <= MAXLEN], collections.Counter({"mẫu x 2 lệnh": len(raw_inst)})
        else:
            kept, drop = read(p)
        L = [len(x) for x in kept]
        summ["files"].append({"category": cat, "file": name, "sha256": sha, "kept": len(kept),
                              "median_len": statistics.median(L) if L else 0,
                              "frac_has_special": round(sum(any(c in SPECIAL for c in x) for x in kept) / max(len(kept), 1), 2),
                              "frac_has_space_no_special": round(sum((" " in x) and not any(c in SPECIAL for c in x) for x in kept) / max(len(kept), 1), 2)})
        summ["drop"][name] = dict(drop)
        pools[cat] += [(x, name) for x in kept]
    for f in summ["files"]:
        print(f"  {f['category']:<9} {f['file']:<55} giữ {f['kept']:>5}  dài TV {f['median_len']:>5}  có ký tự đặc biệt {f['frac_has_special']:.2f}  "
              f"có khoảng trắng nhưng không ký tự đặc biệt {f['frac_has_space_no_special']:.2f}  bỏ {summ['drop'][f['file']]}")
    rnd = random.Random(a.seed); items, info = [], {}
    for cat in ("sqli", "xss", "traversal", "cmdi"):
        u, s2, ov = [], set(), 0
        for x, src in pools[cat]:
            if x in s2: continue
            s2.add(x)
            if norm(x) in seen: ov += 1; continue
            u.append((x, src))
        u = sorted(u); rnd.shuffle(u); pick = u[:a.n]
        info[cat] = {"unique_after_filters": len(u) + ov, "removed_overlap_with_dev": ov, "eligible": len(u), "sampled": len(pick),
                     "by_file": dict(collections.Counter(s for _, s in pick))}
        items += [(cat, x, s) for x, s in pick]
    summ["test2"] = info; print(json.dumps(info, ensure_ascii=False, indent=1))
    braw = [l.rstrip("\r\n").split("\t", 1) for l in open(os.path.join(a.src, "benign2_raw.txt"), encoding="utf-8") if l.strip()]
    bitems = [(f"ctx{c.strip()}", v, "benign2_raw") for c, v in braw]
    summ["benign2"] = {"values": len(bitems), "by_ctx": dict(collections.Counter(c for c, _, _ in bitems))}
    if a.stats_only:
        return
    out = {"test2": build_cases(items, "test2", ["E1", "E2", "E3"]), "benign2": build_cases(bitems, "benign2", ["F", "E1"])}
    for st, cases in out.items():
        d = os.path.join(a.out, st); os.makedirs(d, exist_ok=True); fn = os.path.join(d, "cases.jsonl")
        with open(fn, "w", encoding="utf-8") as f:
            for c in cases: f.write(json.dumps(c, ensure_ascii=False) + "\n")
        summ.setdefault("out", {})[st] = {"cases": len(cases), "sha256": hashlib.sha256(open(fn, "rb").read()).hexdigest(),
                                          "max_url_len": max(c["url_len"] for c in cases)}
    json.dump(summ, open(os.path.join(a.out, "summary_v2.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps(summ["out"], ensure_ascii=False, indent=1), json.dumps(summ["benign2"], ensure_ascii=False))


if __name__ == "__main__":
    main()
