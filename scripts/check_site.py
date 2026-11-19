#!/usr/bin/env python3
"""check_site.py — so sánh mã trạng thái KỲ VỌNG (site_model) với Apache THẬT.

  python3 scripts/check_site.py --host apache-target --port 80
Thoát 0 nếu khớp hết; 1 nếu có lệch (khi đó KHÔNG sinh dữ liệu, vì nhãn/giả định sẽ sai).
Kiểm cả mọi URL "đặc biệt" (redirect, 403, 500, 401/200 với auth) và mẫu URL wordlist (đều phải 404).
"""
import argparse, base64, http.client, os, random, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import site_model as S
import scenarios as SC


def get(host, port, url, auth=None, method="GET", src=None):
    h = {"User-Agent": "check-site/1"}
    if auth:
        h["Authorization"] = "Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    c = http.client.HTTPConnection(host, port, timeout=10, source_address=(src, 0) if src else None)
    try:
        c.request(method, url, headers=h)
        r = c.getresponse(); r.read()
        return r.status
    finally:
        c.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="apache-target"); ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--sample", type=int, default=400, help="số URL wordlist ngẫu nhiên mỗi kiểu để kiểm 404")
    ap.add_argument("--src-ip", default=None, help="gửi từ IP nguồn này (dùng kiểm tra IP alias)")
    ap.add_argument("--ping", action="store_true", help="chỉ GET /about.html một lần từ --src-ip rồi thoát")
    a = ap.parse_args()
    if a.ping:
        print("status", get(a.host, a.port, "/about.html", src=a.src_ip)); return
    cases = []  # (mô tả, url, auth, method, kỳ vọng)
    for u in S.CORE + S.ASSETS + S.API + S.EXTRA_OK + S.PAGES[:25]:
        cases.append(("ok", u, None, "GET", 200))
    for u in S.REDIR: cases.append(("redirect", u, None, "GET", 301))
    for u in S.FORB: cases.append(("forbidden", u, None, "GET", 403))
    for u in S.DIRS: cases.append(("dir /", u, None, "GET", 403))
    for u in S.DIRS_NOSLASH: cases.append(("dir no /", u, None, "GET", 301))
    for u in S.FLAKY: cases.append(("flaky", u, None, "GET", 500))
    cases += [("priv no cred", S.PRIV, None, "GET", 401),
              ("priv bad cred", S.PRIV, ("student", "sai-mat-khau"), "GET", 401),
              ("priv bad user", S.PRIV, ("nobody", "x"), "GET", 401),
              ("priv good cred", S.PRIV, (S.GOOD_USER, S.GOOD_PASS), "GET", 200),
              ("HEAD ok", "/index.html", None, "HEAD", 200),
              ("favicon", "/favicon.ico", None, "GET", 404),
              ("dir có / (Indexes tắt)", "/static/", None, "GET", 403),
              ("dir không / (mod_dir)", "/static", None, "GET", 301),
              ("/private không / chưa đăng nhập", "/private", None, "GET", 401),
              ("/private không / đã đăng nhập", "/private", (S.GOOD_USER, S.GOOD_PASS), "GET", 301),
              ("/private/x đã đăng nhập", "/private/nope.html", (S.GOOD_USER, S.GOOD_PASS), "GET", 404),
              ("/private/x chưa đăng nhập", "/private/nope.html", None, "GET", 401),
              ("prefix của redirect", "/old/page-3.html", None, "GET", 404),
              ("prefix của 403", "/admin/x.php", None, "GET", 404)]
    r = random.Random(1)
    for style in ("A", "B"):
        for _ in range(a.sample):
            u = SC.wordlist_path(r, style)
            cases.append((f"wordlist {style}", u, None, "GET", S.status_of(u)))
    bad, n = [], 0
    for d, u, au, m, exp in cases:
        n += 1
        try: got = get(a.host, a.port, u, au, m, a.src_ip)
        except Exception as e: got = f"ERR {e!r}"
        if got != exp: bad.append((d, m, u, exp, got))
        # mô hình phải đồng ý với kỳ vọng ghi tay ở trên (trừ các ca đặc biệt không có trong model)
        if d.startswith(("ok", "redirect", "forbidden", "flaky", "dir")) and S.status_of(u) != exp:
            bad.append((d + " [model]", m, u, exp, S.status_of(u)))
    print(f"đã kiểm {n} ca, lệch {len(bad)}")
    for b in bad[:40]: print("  LỆCH", b)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
