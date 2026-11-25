#!/usr/bin/env python3
"""demo_send.py — gửi request tuần tự tới apache-target, in kết quả TỪNG request, để thấy lúc nguồn bị chặn.
Chạy trong image lab, mỗi lần một IP riêng (chỉ thư viện chuẩn):
  docker run --rm --network siem10_net --ip 172.30.90.X -v "$PWD/ar:/workspace/ar:ro" -v "$PWD/sig:/workspace/sig:ro" \
    siem-ai-lab:local python3 -I /workspace/ar/tools/demo_send.py --wordlist /usr/share/dirb/wordlists/common.txt --rate 1
  ... --cases /workspace/sig/payloads/test2/cases.jsonl --category sqli --encoding E1 --rate 1
Mỗi request một kết nối mới, timeout ngắn. Dừng khi có --stop-after request liên tiếp không được phản hồi.
"""
import argparse, http.client, json, socket, time, urllib.parse
from datetime import datetime

UA = "Mozilla/5.0 (X11; Linux x86_64) siem10-lab"


def load(a):
    if a.wordlist:
        out = []
        for l in open(a.wordlist, encoding="latin-1"):
            w = l.strip()
            if w and not w.startswith("#"):
                out.append("/" + urllib.parse.quote(w, safe="/._-~"))
        return out[a.skip:]
    if a.cases:
        cs = [json.loads(l) for l in open(a.cases, encoding="utf-8") if l.strip()]
        cs = [c for c in cs if (a.category is None or c.get("category") == a.category) and (a.encoding is None or c.get("encoding") == a.encoding)]
        return [c["url"] for c in cs][a.skip:]
    return list(a.urls)


def my_ip(target):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 80)); return s.getsockname()[0]
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--wordlist"); g.add_argument("--cases"); g.add_argument("--urls", nargs="+")
    ap.add_argument("--category"); ap.add_argument("--encoding")
    ap.add_argument("--skip", type=int, default=0); ap.add_argument("--limit", type=int, default=300)
    ap.add_argument("--rate", type=float, default=1.0); ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--stop-after", type=int, default=5); ap.add_argument("--target", default="apache-target")
    a = ap.parse_args()
    urls = load(a)[:a.limit]
    gap = 1.0 / a.rate if a.rate > 0 else 0
    print(f"nguồn {my_ip(a.target)} -> {a.target}, {len(urls)} request, {a.rate} req/s, timeout {a.timeout} s", flush=True)
    ok_n, last_ok, miss = 0, 0, 0
    for k, u in enumerate(urls, 1):
        t = time.time(); st = None
        try:
            c = http.client.HTTPConnection(a.target, 80, timeout=a.timeout)
            c.request("GET", u, headers={"User-Agent": UA, "Accept": "*/*", "Connection": "close"})
            r = c.getresponse(); r.read(); st = r.status; c.close()
        except (OSError, http.client.HTTPException):
            st = None
        stamp = datetime.now().strftime("%H:%M:%S")
        if st is None:
            miss += 1
            print(f"{stamp}  #{k:>3}  ---  {u[:80]}   <- không phản hồi", flush=True)
        else:
            ok_n += 1; last_ok = k; miss = 0
            print(f"{stamp}  #{k:>3}  {st}  {u[:80]}", flush=True)
        if miss >= a.stop_after:
            print(f"==> NGUỒN BỊ CHẶN: request cuối có phản hồi là #{last_ok}; sau đó {miss} request liên tiếp không được "
                  f"phản hồi (timeout {a.timeout} s).", flush=True)
            return
        d = gap - (time.time() - t)
        if d > 0:
            time.sleep(d)
    print(f"==> gửi hết {len(urls)} request, {ok_n} có phản hồi.", flush=True)


if __name__ == "__main__":
    main()
