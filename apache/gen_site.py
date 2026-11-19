#!/usr/bin/env python3
"""Sinh apache/htdocs, apache/httpd-siemlab.conf, apache/.htpasswd từ scripts/site_model.py.
Chạy:  python3 apache/gen_site.py   (cần lệnh `htpasswd` để sinh .htpasswd; nếu thiếu, giữ file có sẵn)"""
import os, shutil, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
import site_model as S

shutil.rmtree(os.path.join(HERE, "htdocs"), ignore_errors=True)
S.write_htdocs(os.path.join(HERE, "htdocs"))
open(os.path.join(HERE, "httpd-siemlab.conf"), "w", encoding="utf-8").write(S.apache_conf())
if shutil.which("htpasswd"):
    pw = os.path.join(HERE, ".htpasswd")
    if os.path.exists(pw): os.remove(pw)
    users = {S.GOOD_USER: S.GOOD_PASS, **S.EXTRA_USERS}
    first = True
    for u, p in users.items():
        subprocess.check_call(["htpasswd", "-B" + ("c" if first else "") + "b", pw, u, p], stderr=subprocess.DEVNULL); first = False
print("ok: htdocs, httpd-siemlab.conf, .htpasswd")
