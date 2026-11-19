#!/usr/bin/env python3
"""Kiểm thử đầu-cuối KHÔNG cần Docker/Apache: một máy chủ HTTP nhỏ (trả mã theo site_model, có Basic Auth, ghi log
định dạng SIEMLAB, đóng kết nối keep-alive nhàn rỗi sau 1 s) + executor thật + audit_coverage (cả tầng alert giả lập,
có tình huống IP được tái sử dụng). Chạy:  python3 tests/test_pipeline.py   (Linux: dùng IP nguồn 127.0.0.x)"""
import base64, json, os, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import scenarios as SC, site_model as S, traffic as TR

TMP = tempfile.mkdtemp(); LOG = os.path.join(TMP, "siem.log"); lk = threading.Lock()


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"; timeout = 1.0            # đóng kết nối nhàn rỗi sau 1 s (giống KeepAliveTimeout)

    def _do(self, body=True):
        cred = None
        ah = self.headers.get("Authorization")
        if ah:
            u, p = base64.b64decode(ah.split()[1]).decode().split(":", 1)
            cred = "good" if (u, p) == (S.GOOD_USER, S.GOOD_PASS) else "bad"
        st = S.status_of(self.path, cred); data = b"x" * 20
        self.send_response(st); self.send_header("Content-Length", str(len(data))); self.end_headers()
        if body: self.wfile.write(data)
        with lk:
            open(LOG, "a").write(f'SIEMLAB {int(time.time() * 1e6)} {self.client_address[0]} "{self.requestline}" {st} {len(data) if body else 0}\n')

    def do_GET(self): self._do()
    def do_HEAD(self): self._do(False)
    def log_message(self, *a): pass


def main():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H); port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    fails = []
    # phiên: login có nhịp > 1 s (buộc phải mở lại kết nối keep-alive) + scan nhanh, mỗi phiên một IP
    bdir = os.path.join(TMP, "batch"); os.makedirs(os.path.join(bdir, "requests"))
    rows = []
    for ip, name, k in (("127.0.0.21", "typo_login", 1), ("127.0.0.22", "scan_fast", 0)):
        s = SC.build_session(name, "pipe", "t", k)
        s["reqs"] = [q for q in s["reqs"] if q.t <= 12.0]                # rút ngắn cho test nhanh
        s["keepalive"] = True
        res = TR.execute_session(s, "127.0.0.1", port, ip, os.path.join(bdir, "requests", s["run_id"] + ".jsonl"))
        if res["n_err"]: fails.append(f"{name}: {res['n_err']} request lỗi")
        rows.append({"run_id": s["run_id"], "scenario": name, "srcip": ip, **res})
        reqs = [json.loads(l) for l in open(os.path.join(bdir, "requests", s["run_id"] + ".jsonl"))]
        bad = [r for r in reqs if r["status"] != S.status_of(r["url"], r["cred"])]
        if bad: fails.append(f"{name}: {len(bad)} mã nhận khác mô hình")
        if name == "typo_login" and not any(r["retry"] for r in reqs): fails.append("không hề phải thử lại keep-alive (test không phủ nhánh retry)")
    open(os.path.join(bdir, "sessions.jsonl"), "w").write("".join(json.dumps(r) + "\n" for r in rows))
    time.sleep(.3)
    # alert giả lập: đủ mọi dòng trừ 1 dòng; thêm 5 alert của CÙNG IP nhưng ngoài cửa sổ phiên (IP tái sử dụng sau đó)
    lines = open(LOG).read().splitlines()
    alerts = [json.dumps({"rule": {"id": "100012"}, "full_log": l}) for l in lines[1:]]
    first = lines[0].split()
    for i in range(5):
        alerts.append(json.dumps({"rule": {"id": "x"}, "full_log": f'SIEMLAB {int(first[1]) + int(3600e6) + i} {first[2]} "GET {first[4]} HTTP/1.1" {first[-2]} 0'}))
    open(os.path.join(TMP, "alerts.json"), "w").write("\n".join(alerts) + "\n")
    out = subprocess.run([sys.executable, os.path.join(ROOT, "scripts", "audit_coverage.py"), "--batch", bdir,
                          "--siem-log", LOG, "--alerts", os.path.join(TMP, "alerts.json")], capture_output=True, text=True).stdout
    n = len(lines)
    if f"TỔNG {n}/{n} = 1.0000" not in out: fails.append("tầng 1->2 không đủ 100%")
    if f"TỔNG {n - 1}/{n} " not in out: fails.append(f"tầng 2->3 phải là {n - 1}/{n} (alert ngoài cửa sổ không được tính)")
    if fails: print(out)
    for f in fails: print("  LỖI:", f)
    print("OK" if not fails else "THẤT BẠI"); sys.exit(1 if fails else 0)


main()
