#!/usr/bin/env python3
"""site_model.py — NGUỒN SỰ THẬT DUY NHẤT về website mục tiêu.

Từ file này sinh ra: (1) cây htdocs, (2) cấu hình Apache (redirect/403/500/auth),
(3) bảng "URL -> mã trạng thái kỳ vọng" mà generator và check_site.py dùng.
Nếu sửa site, sửa ở đây rồi chạy lại:  python3 apache/gen_site.py

check_site.py so sánh bảng kỳ vọng với Apache THẬT; lệch thì dừng, vì khi đó
nhãn/giả định của generator không còn đúng.
"""
import re

# ---------------------------------------------------------------- tài nguyên
PAGES = [f"/products/p-{i:04d}.html" for i in range(300)]
CORE = ["/index.html", "/about.html", "/contact.html"]
VALID = PAGES + CORE                                           # trang người dùng thật hay vào
ASSETS = ([f"/static/a{i:02d}.css" for i in range(4)] + [f"/static/img{i:02d}.png" for i in range(12)]
          + [f"/static/app{i}.js" for i in range(4)])
API = [f"/api/v1/item{i}.json" for i in range(6)]
EXTRA_OK = ["/robots.txt", "/sitemap.xml"]
REDIR = ["/old", "/blog", "/docs", "/news", "/shop", "/help", "/login-old", "/legacy.html"] + [f"/r{i}" for i in range(4)]
FORB = ["/admin/", "/backup/", "/.htaccess", "/.htpasswd", "/cgi-bin/", "/conf/", "/logs/",
        "/private-old/", "/tmp/", "/db/", "/include/", "/config/", "/test/", "/internal/"]
FLAKY = ["/api/flaky", "/api/report", "/search-report"]        # luôn trả 500 (mô phỏng backend lỗi)
PRIV = "/private/"                                              # Basic Auth

GOOD_USER, GOOD_PASS = "student", "LabOnly-2026"                # mật khẩu LAB, không phải bí mật thật
EXTRA_USERS = {"alice": "Lab-alice-2026", "bob": "Lab-bob-2026"}

# Thư mục thật trên đĩa: có dấu "/" -> 403 (Indexes tắt, không có index.html); không dấu "/" -> mod_dir 301
DIRS = ["/static/", "/api/", "/api/v1/", "/products/"]
DIRS_NOSLASH = [d.rstrip("/") for d in DIRS]
OK_SET = set(VALID) | set(ASSETS) | set(API) | set(EXTRA_OK)
REDIR_SET, FORB_SET, FLAKY_SET = set(REDIR), set(FORB), set(FLAKY)
DIR_SET, DIR_NS_SET = set(DIRS), set(DIRS_NOSLASH)


def status_of(url, cred=None):
    """Mã trạng thái KỲ VỌNG của Apache cho GET url. cred: None | 'good' | 'bad'."""
    if url == "/private" or url.startswith("/private/"):     # Basic Auth phủ cả thư mục: chưa đăng nhập -> 401 cho MỌI đường dẫn con
        if cred != "good":
            return 401
        return 200 if url == PRIV else (301 if url == "/private" else 404)
    if url in OK_SET:
        return 200
    if url in REDIR_SET:
        return 301
    if url in FORB_SET:
        return 403
    if url in FLAKY_SET:
        return 500
    if url in DIR_SET:
        return 403
    if url in DIR_NS_SET:
        return 301
    return 404


# ---------------------------------------------------------------- Apache conf
def _alt(paths):
    return "|".join(re.escape(p) for p in paths)


def apache_conf():
    return f"""# ====== SINH TỰ ĐỘNG từ scripts/site_model.py — đừng sửa tay ======
# Biến (đặt bằng Define trong Dockerfile): SIEM_HTDOCS, SIEM_HTPASSWD
# %r (dòng yêu cầu GỐC) thay vì %U: %U ghi URL SAU khi mod_dir chuyển nội bộ, nên /private/ thành công bị ghi là
# /private/index.html còn 401 thì /private/ -> cùng một URL hiện ra hai dạng theo mã trạng thái (phát hiện khi test).
LogFormat "SIEMLAB %{{usec}}t %a \\"%r\\" %>s %B" siemlab
CustomLog "logs/siem.log" siemlab

# Mặc định httpd bật Options Indexes -> /static/ trả danh sách thư mục (200). Tắt để hành vi xác định.
<Directory "${{SIEM_HTDOCS}}">
    Options -Indexes +FollowSymLinks
    AllowOverride None
    Require all granted
</Directory>

# 301: khớp TUYỆT ĐỐI (RedirectMatch có neo ^$), tránh /old khớp tiền tố /old/page-1.html
RedirectMatch 301 "^({_alt(REDIR)})$" /index.html

# 403: khớp tuyệt đối từng đường dẫn
<LocationMatch "^({_alt(FORB)})$">
    Require all denied
</LocationMatch>

# 500: backend giả lỗi
RewriteEngine On
RewriteRule "^({_alt(FLAKY)})$" - [R=500,L]

# 401/200: Basic Auth cho /private/
<Directory "${{SIEM_HTDOCS}}/private">
    AuthType Basic
    AuthName "SIEM Lab Restricted"
    AuthUserFile "${{SIEM_HTPASSWD}}"
    Require valid-user
</Directory>
"""


# ---------------------------------------------------------------- htdocs
_PNG = bytes.fromhex("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000d49444154789c6360f8cfc0f01f0005000201a5f645400000000049454e44ae426082")


def write_htdocs(root):
    import os, json
    def w(rel, data, mode="w"):
        p = os.path.join(root, rel.lstrip("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, mode, **({} if "b" in mode else {"encoding": "utf-8"})) as f:
            f.write(data)
    nav = '<nav><a href="/index.html">Home</a> <a href="/about.html">About</a> <a href="/contact.html">Contact</a></nav>'
    for i, p in enumerate(PAGES):
        rel = [PAGES[(i + k) % len(PAGES)] for k in (1, 7, 13)]
        body = "".join(f'<p><a href="{r}">{r}</a></p>' for r in rel)
        filler = ("Lorem ipsum dolor sit amet. " * (5 + i % 17))
        w(p, f"<!doctype html><title>Product {i}</title>{nav}<h1>Product {i}</h1><p>{filler}</p>{body}")
    for p in CORE:
        w(p, f"<!doctype html><title>{p}</title>{nav}<h1>{p}</h1>" + "".join(f'<a href="{x}">{x}</a> ' for x in PAGES[:20]))
    for i in range(4):
        w(f"/static/a{i:02d}.css", "body{font-family:sans-serif}" + "/* pad */" * (10 + i * 40))
        w(f"/static/app{i}.js", "console.log('app');" + "//pad\n" * (5 + i * 30))
    for i in range(12):
        w(f"/static/img{i:02d}.png", _PNG + b"\0" * (200 * i), "wb")
    for i in range(6):
        w(f"/api/v1/item{i}.json", json.dumps({"id": i, "name": f"item{i}", "tags": ["a"] * (i + 1)}))
    w("/robots.txt", "User-agent: *\nDisallow: /admin/\nDisallow: /private/\n")
    w("/sitemap.xml", '<?xml version="1.0"?><urlset>' + "".join(f"<url><loc>{p}</loc></url>" for p in PAGES[:50]) + "</urlset>")
    w("/private/index.html", "<!doctype html><title>Private</title><h1>Private area (lab)</h1>")
