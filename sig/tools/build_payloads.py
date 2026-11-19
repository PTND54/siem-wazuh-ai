#!/usr/bin/env python3
"""build_payloads.py — dựng tập ca đo phát triển (URL) từ danh sách payload công khai + tập bình thường khó.

  python3 -I build_payloads.py --src src --out payloads [--n-attack 120] [--seed 20261115]

Đầu vào: src/manifest.txt + src/{dev,test}/<loại>__<file> (tải nguyên văn, sha256 ghi trong manifest).
  dev  = PayloadsAllTheThings (được xem khi viết luật)
  test = SecLists (GIỮ RIÊNG: script này chỉ in SỐ LƯỢNG, không in nội dung; không ai đọc trước khi chốt luật)
Đầu ra (mỗi dòng JSON một ca): payloads/dev/cases.jsonl, payloads/test/cases.jsonl, payloads/benign_dev/cases.jsonl,
  payloads/benign_test/cases.jsonl, payloads/summary.json (chỉ số lượng + sha256).

Một ca = (payload, vị trí, kiểu mã hóa). Đơn vị đo là ca (request).
Kiểu mã hóa của payload tấn công (đã chốt trước khi dựng tập):
  E1 "trình duyệt": mã hóa đúng tập ký tự mà trình duyệt mã hóa theo chuẩn WHATWG URL
      (query của URL http: C0, khoảng trắng, " # < > ' và ký tự ngoài ASCII; path: C0, khoảng trắng, " # < > ? ` { } ^
      và ngoài ASCII). Ký tự % giữ nguyên (payload đã mã hóa sẵn vẫn là chính nó).
  E2 "mã hóa toàn bộ": mọi ký tự ngoài [A-Za-z0-9-._~] thành %XX.
  E3 "mã hóa hai lần": E2 rồi % thành %25.
Tập bình thường khó dùng hai kiểu của người dùng thật: F "form" (application/x-www-form-urlencoded, khoảng trắng -> +)
  và E1 "gõ trên thanh địa chỉ".
Vị trí: SQLi/XSS/lệnh -> giá trị một tham số query trên trang có thật; traversal -> xen kẽ query và đường dẫn (/static/...).
Tên tham số và trang chọn theo băm payload, KHÔNG theo loại tấn công (luật không được dựa vào tên tham số).
"""
import argparse, collections, hashlib, json, os, random, sys
from urllib.parse import quote, quote_plus

PAGES = ["/index.html", "/about.html", "/contact.html", "/products/p-0042.html", "/products/p-0217.html",
         "/api/v1/item3.json"]
PARAMS = ["q", "id", "page", "search", "item", "file", "cmd", "lang", "ref", "view", "name", "next"]
MAXLEN = 400

QUERY_SET = set(' "#<>\'')            # WHATWG special-query percent-encode set (cộng C0, DEL, ngoài ASCII)
PATH_SET = set(' "#<>?`{}^')          # WHATWG path percent-encode set


def enc_browser(s, where):
    S = QUERY_SET if where == "query" else PATH_SET
    out = []
    for ch in s:
        o = ord(ch)
        if o < 0x21 or o >= 0x7f or ch in S:
            out.append("".join(f"%{b:02X}" for b in ch.encode("utf-8")))
        else:
            out.append(ch)
    return "".join(out)


def enc_full(s):
    return quote(s, safe="")


def enc_double(s):
    return enc_full(s).replace("%", "%25")


def h(s):
    return hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()


def norm(s):
    return " ".join(s.lower().split())


def read_list(path):
    raw = open(path, "rb").read().decode("utf-8", "replace").splitlines()
    kept, drop = [], collections.Counter()
    for ln in raw:
        s = ln.rstrip("\r\n")
        if not s.strip():
            drop["rỗng"] += 1; continue
        if len(s) > MAXLEN:
            drop[f"dài > {MAXLEN}"] += 1; continue
        if "\ufffd" in s:
            drop["không phải UTF-8"] += 1; continue
        if "{FILE}" in s:                       # chỗ giữ chỗ của PayloadsAllTheThings -> tệp đích cố định
            s = s.replace("{FILE}", "etc/passwd"); drop["thay {FILE} -> etc/passwd (vẫn giữ)"] += 1
        kept.append(s)
    return kept, drop


def build_cases(items, setname, encs):
    """items: list (category, payload, source_file). Trả list ca."""
    cases = []
    for k, (cat, p, src) in enumerate(items):
        hp = int(h(p)[:8], 16)
        page, param = PAGES[hp % len(PAGES)], PARAMS[(hp // 7) % len(PARAMS)]
        where = "path" if (cat == "traversal" and k % 2 == 1) else "query"
        for e in encs:
            if e == "E1":
                v = enc_browser(p, where)
            elif e == "E2":
                v = enc_full(p)
            elif e == "E3":
                v = enc_double(p)
            elif e == "F":
                v = quote_plus(p, safe="")
            url = f"/static/{v}" if where == "path" else f"{page}?{param}={v}"
            cases.append({"cid": f"{setname}-{k:04d}-{e}", "set": setname, "category": cat, "source": src,
                          "payload_sha256": h(p), "placement": where, "encoding": e, "url": url,
                          "url_len": len(url)})
    return cases


def sample(lst, n, rnd):
    lst = sorted(lst)
    rnd.shuffle(lst)
    return lst[:n]


# ---------------------------------------------------------------- tập bình thường khó (nhóm tự viết)
BENIGN = {
    "sql_words": ["select a plan", "union station hotels", "drop shipping guide", "insert coin", "order by price",
                  "where to buy shoes", "join us today", "update firmware", "delete account help", "table for two",
                  "1 or 2 people", "and or not logic", "null pointer exception", "sleep tips for babies",
                  "benchmark results 2026", "information about schema markup", "version 1.2.3", "from a to z",
                  "having fun", "group by size", "select all", "union jack flag", "drop down menu", "exec summary",
                  "char limit", "case when then"],
    "quote": ["O'Brien", "don't stop", "rock 'n' roll", "it's 5 o'clock", "McDonald's menu", "children's books",
              "Let's go", "he said \"hello\"", "the 90's"],
    "tech": ["how to use <script> tag", "a<b and b>c", "<br> vs <br/>", "javascript: void(0) meaning",
             "onload event example", "alert dialog css", "document.cookie tutorial", "img alt text",
             "iframe embed youtube", "svg icons", "C++ vs C#", "1+1=2", "50% off", "x > 5 && y < 3", "array[0]",
             "{\"json\": true}", "<b>bold</b>", "select * from users tutorial", "prompt engineering",
             "confirm password", "eval function python"],
    "shell_words": ["cat food", "ping pong table", "curl hair tips", "wget alternative", "bash party ideas",
                    "id card renewal", "whoami game", "sleep 8 hours", "nc state university", "1;2;3", "a|b|c",
                    "tom & jerry", "rock && roll", "$5 deals", "uname meaning", "ls means", "echo dot"],
    "paths": ["/docs/a/b", "report.pdf", "../index.html", "/products/../index.html", "C:\\Users\\public",
              "file.tar.gz", "./config", "/etc/hosts file explained", "images/2026/11/a.png"],
    "urls": ["https://example.com/a?b=c", "http://localhost:8080/", "//cdn.example.com/x.js", "mailto:a@b.com"],
    "misc": ["điện thoại giá rẻ", "áo sơ mi nam", "học lập trình", "100%", "a=b", "#hashtag", "email@example.com",
             "+84 912 345 678", "2026-11-15", "name;desc", "1|2|3", "--help", "/*", "*/", "~user"],
}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", default="src"); ap.add_argument("--out", default="payloads")
    ap.add_argument("--n-attack", type=int, default=120); ap.add_argument("--seed", type=int, default=20261115)
    a = ap.parse_args()
    man = [l.split() for l in open(os.path.join(a.src, "manifest.txt"), encoding="utf-8") if not l.startswith("fetched")]
    pools = {"dev": collections.defaultdict(list), "test": collections.defaultdict(list)}
    summary = {"seed": a.seed, "n_attack_per_category": a.n_attack, "maxlen": MAXLEN, "sources": [], "dropped": {}}
    for st, cat, name, sha, *_ in man:
        path = os.path.join(a.src, st, f"{cat}__{name}")
        real = hashlib.sha256(open(path, "rb").read()).hexdigest()
        if real != sha:
            sys.exit(f"sha256 lệch: {path}")
        kept, drop = read_list(path)
        summary["sources"].append({"set": st, "category": cat, "file": name, "sha256": sha, "kept": len(kept)})
        summary["dropped"][f"{st}/{name}"] = dict(drop)
        for p in kept:
            pools[st][cat].append((p, name))
    # bỏ trùng trong tập, rồi bỏ khỏi test mọi payload trùng (sau chuẩn hóa) với BẤT KỲ payload dev nào
    devnorm = {norm(p) for cat in pools["dev"] for p, _ in pools["dev"][cat]}
    rnd = random.Random(a.seed)
    out = {}
    for st in ("dev", "test"):
        items, info = [], {}
        for cat in ("sqli", "xss", "traversal", "cmdi"):
            seen, uniq, overlap = set(), [], 0
            for p, src in pools[st][cat]:
                if p in seen:
                    continue
                seen.add(p)
                if st == "test" and norm(p) in devnorm:
                    overlap += 1; continue
                uniq.append((p, src))
            pick = sample(uniq, a.n_attack, rnd)
            info[cat] = {"unique": len(uniq), "removed_overlap_with_dev": overlap, "sampled": len(pick)}
            items += [(cat, p, src) for p, src in pick]
        out[st] = build_cases(items, st, ["E1", "E2", "E3"])
        summary[st] = info
    # tập bình thường khó: tách theo GIÁ TRỊ (không theo ca), mỗi nhóm con chia đôi dev/test
    bdev, btest = [], []
    for sub, vals in BENIGN.items():
        v = sample(vals, len(vals), rnd)
        half = (len(v) + 1) // 2
        bdev += [(sub, x, "nhom_tu_viet") for x in v[:half]]
        btest += [(sub, x, "nhom_tu_viet") for x in v[half:]]
    out["benign_dev"] = build_cases(bdev, "benign_dev", ["F", "E1"])
    out["benign_test"] = build_cases(btest, "benign_test", ["F", "E1"])
    summary["benign"] = {"dev_values": len(bdev), "test_values": len(btest),
                         "subtypes": {k: len(v) for k, v in BENIGN.items()}}
    for st, cases in out.items():
        d = os.path.join(a.out, st); os.makedirs(d, exist_ok=True)
        fn = os.path.join(d, "cases.jsonl")
        with open(fn, "w", encoding="utf-8") as f:
            for c in cases:
                f.write(json.dumps(c, ensure_ascii=False) + "\n")
        summary.setdefault("files", {})[st] = {"cases": len(cases), "sha256": hashlib.sha256(open(fn, "rb").read()).hexdigest(),
                                               "max_url_len": max(c["url_len"] for c in cases),
                                               "by_category": dict(collections.Counter(c["category"] for c in cases))}
    json.dump(summary, open(os.path.join(a.out, "summary.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(json.dumps({k: summary[k] for k in ("dev", "test", "benign", "files")}, ensure_ascii=False, indent=1))
    print("dropped:", json.dumps(summary["dropped"], ensure_ascii=False))


if __name__ == "__main__":
    main()
