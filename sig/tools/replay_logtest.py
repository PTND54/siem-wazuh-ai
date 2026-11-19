#!/usr/bin/env python3
"""replay_logtest.py — phát một file dòng log qua wazuh-logtest trên Manager đang chạy, ghi kết quả từng dòng.

Chạy trên HOST (WSL, cần docker), thư mục nào cũng được. Chỉ dùng thư viện chuẩn.
  python3 -B replay_logtest.py --in lines.log --out result.jsonl [--chunk 500] [--keep-ip] [--limit N]

KHÔNG ghi gì vào Manager, không restart, không tạo alert thật: wazuh-logtest chỉ mở một phiên thử trong analysisd.
Mỗi khối (--chunk dòng) là MỘT phiên logtest riêng. Mặc định mỗi dòng được gán một IP nguồn khác nhau trong ba dải
TEST-NET (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) để luật tần suất cùng-IP không chen vào phép đo từng request.
Dòng có ký tự ngoài ASCII in được bị BỎ QUA và đếm riêng (không đoán cách logtest xử lý chúng).
Kết quả mỗi dòng: decoder, url, status, rule_id, level, description, groups, alert (có "Alert to be generated" không).
"""
import argparse, collections, json, os, re, subprocess, sys, time

POOL = [f"{net}.{h}" for net in ("192.0.2", "198.51.100", "203.0.113") for h in range(1, 255)]
P1 = "**Phase 1: Completed pre-decoding."
P2 = "**Phase 2: Completed decoding."
P3 = "**Phase 3: Completed filtering (rules)."
FIELD = re.compile(r"^\s*([\w.\-][\w.\- ]*?): '(.*)'\s*$")


def fields(text):
    d = {}
    for ln in text.splitlines():
        m = FIELD.match(ln)
        if m and m.group(1) not in d:
            d[m.group(1)] = m.group(2)
    return d


def parse(out):
    """Tách output của wazuh-logtest thành list dict, mỗi dict ứng với một dòng log đã gửi."""
    res = []
    for b in out.split(P1)[1:]:
        pre, _, rest = b.partition(P2)
        dec, _, rule = rest.partition(P3)
        f1, f2, f3 = fields(pre), fields(dec), fields(rule) if rule else {}
        res.append({"full_event": f1.get("full event"), "decoder": f2.get("name"), "url": f2.get("url"),
                    "status": f2.get("id"), "srcip": f2.get("srcip"), "rule_id": f3.get("id"),
                    "level": int(f3["level"]) if f3.get("level", "").isdigit() else None,
                    "description": f3.get("description"), "groups": f3.get("groups"),
                    "alert": "**Alert to be generated" in rule})
    return res


def run_logtest(cmd, lines, timeout):
    p = subprocess.run(cmd, input="".join(l + "\n" for l in lines), capture_output=True, text=True, timeout=timeout)
    return p.stdout + p.stderr


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="inp", required=True); ap.add_argument("--out", required=True)
    ap.add_argument("--chunk", type=int, default=500); ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--keep-ip", action="store_true", help="giữ IP nguồn gốc (mặc định: mỗi dòng một IP TEST-NET riêng)")
    ap.add_argument("--container", default="siem10-wazuh.manager-1")
    ap.add_argument("--timeout", type=int, default=600)
    a = ap.parse_args(argv)
    if a.chunk > len(POOL):
        sys.exit(f"--chunk tối đa {len(POOL)} (số IP TEST-NET)")
    cmd = ["docker", "exec", "-i", a.container, "/var/ossec/bin/wazuh-logtest"]
    raw = open(a.inp, "rb").read().split(b"\n")
    items, skipped = [], 0
    for n, b in enumerate(raw, 1):
        if not b.strip():
            continue
        if any(c < 0x20 or c > 0x7e for c in b):
            skipped += 1; continue
        items.append((n, b.decode("ascii")))
    if a.limit:
        items = items[:a.limit]
    print(f"{len(items)} dòng sẽ gửi, {skipped} dòng bỏ qua (ký tự ngoài ASCII in được); khối {a.chunk} dòng")
    t0, done, bad_chunks = time.time(), 0, 0
    cnt, dec = collections.Counter(), collections.Counter()
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fo:
        for c0 in range(0, len(items), a.chunk):
            part = items[c0:c0 + a.chunk]
            sent = []
            for k, (n, ln) in enumerate(part):
                sent.append(ln if a.keep_ip else re.sub(r"^\S+", POOL[k], ln, count=1))
            out = run_logtest(cmd, sent, a.timeout)
            if c0 == 0:
                open(a.out + ".raw_first_chunk.txt", "w", encoding="utf-8").write(out)
            res = parse(out)
            if len(res) != len(sent):          # lệch số khối: gửi lại từng dòng để không gán nhầm kết quả
                bad_chunks += 1
                print(f"  khối {c0 // a.chunk}: {len(res)} kết quả / {len(sent)} dòng — gửi lại từng dòng")
                res = []
                for s in sent:
                    r = parse(run_logtest(cmd, [s], a.timeout))
                    res.append(r[0] if len(r) == 1 else {"error": f"{len(r)} khối cho 1 dòng"})
            for (n, ln), s, r in zip(part, sent, res):
                r = dict(r); fe = r.pop("full_event", None)
                r.update({"n": n, "line": ln, "sent_ip": s.split(" ", 1)[0], "echo_ok": fe == s})
                fo.write(json.dumps(r, ensure_ascii=False) + "\n")
                cnt[(r.get("rule_id"), r.get("level"), r.get("description"), r.get("alert"))] += 1
                dec[r.get("decoder")] += 1
            done += len(part)
            print(f"  {done}/{len(items)} dòng, {time.time() - t0:.0f} s", flush=True)
    print(f"\nXong: {done} dòng, {time.time() - t0:.0f} s, {bad_chunks} khối phải gửi lại -> {a.out}")
    print("decoder:", dict(dec))
    print(f"{'rule':>7} {'level':>5} {'alert':>5} {'số dòng':>8}  mô tả")
    for (rid, lv, ds, al), v in sorted(cnt.items(), key=lambda x: -x[1]):
        print(f"{str(rid):>7} {str(lv):>5} {str(al):>5} {v:>8}  {ds}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
