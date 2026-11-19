#!/usr/bin/env python3
"""send_payloads.py — gửi một tập ca (URL) tới apache-target từ MỘT IP, ghi nhật ký từng request, rồi trích đúng các dòng
access_log và siem.log mà Apache ghi cho lần gửi này.

Chạy trong image lab, mỗi lần một container có IP riêng (dải .201–.250, KHÔNG chạy cùng lúc run_tools.sh / run_batch.py):
  docker run --rm --network siem10_net --ip 172.30.90.230 \
    -v "$SIG:/workspace/sig" -v siem10_apache_logs:/apache-logs:ro siem-ai-lab:local \
    python3 -I /workspace/sig/tools/send_payloads.py --cases /workspace/sig/payloads/dev/cases.jsonl \
      --run /workspace/sig/runs/<tên> [--rate 5] [--limit N]

Chỉ thư viện chuẩn. Một kết nối giữ lâu (mở lại khi Apache đóng). Gửi TUẦN TỰ để thứ tự dòng log = thứ tự ca.
Ghi:  <run>/sent.jsonl      mỗi ca: cid, url, t_send, status, bytes, error
      <run>/access_log.txt  các dòng access_log mới của IP này (từ vị trí cuối file lúc bắt đầu)
      <run>/siem_log.txt    các dòng siem.log mới của IP này
      <run>/meta.json       IP, thời điểm đầu/cuối (UTC), số ca, số dòng log, đối chiếu thứ tự
"""
import argparse, http.client, json, os, socket, sys, time
from datetime import datetime, timezone

UA = "Mozilla/5.0 (X11; Linux x86_64) siem10-lab"


def my_ip(target):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 80)); return s.getsockname()[0]
    finally:
        s.close()


def size(p):
    try:
        return os.path.getsize(p)
    except OSError:
        return None


def tail_from(p, off, ip):
    if off is None or not os.path.exists(p):
        return []
    with open(p, "rb") as f:
        f.seek(off)
        data = f.read()
    pre = (ip + " ").encode()
    out = []
    for ln in data.split(b"\n"):
        if ln.startswith(pre) or (b" " + pre) in ln[:40]:
            out.append(ln.decode("latin-1"))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cases", required=True); ap.add_argument("--run", required=True)
    ap.add_argument("--target", default="apache-target"); ap.add_argument("--rate", type=float, default=5.0)
    ap.add_argument("--limit", type=int, default=0); ap.add_argument("--logs", default="/apache-logs")
    ap.add_argument("--settle", type=float, default=5.0, help="giây chờ Apache ghi xong log trước khi trích")
    ap.add_argument("--category", default=None, help="chỉ gửi ca của loại này (sqli|xss|traversal|cmdi)")
    ap.add_argument("--encoding", default=None, help="chỉ gửi ca có kiểu mã hóa này (E1|E2|E3|F)")
    a = ap.parse_args()
    cases = [json.loads(l) for l in open(a.cases, encoding="utf-8") if l.strip()]
    cases = [c for c in cases if (a.category is None or c["category"] == a.category) and (a.encoding is None or c["encoding"] == a.encoding)]
    if a.limit:
        cases = cases[:a.limit]
    os.makedirs(a.run, exist_ok=True)
    if os.path.exists(os.path.join(a.run, "sent.jsonl")):
        sys.exit(f"{a.run}/sent.jsonl đã có — dùng thư mục run mới, không ghi đè")
    ip = my_ip(a.target)
    acc, sie = os.path.join(a.logs, "access_log"), os.path.join(a.logs, "siem.log")
    off_acc, off_sie = size(acc), size(sie)
    t0 = datetime.now(timezone.utc)
    print(f"IP {ip}, {len(cases)} ca, {a.rate} req/s, bắt đầu {t0.isoformat()}", flush=True)
    gap = 1.0 / a.rate if a.rate > 0 else 0
    conn, n_err = None, 0
    with open(os.path.join(a.run, "sent.jsonl"), "w", encoding="utf-8") as fo:
        for k, c in enumerate(cases):
            t = time.time()
            rec = {"cid": c["cid"], "url": c["url"], "t_send": round(t, 6)}
            for attempt in (1, 2):
                try:
                    if conn is None:
                        conn = http.client.HTTPConnection(a.target, 80, timeout=15)
                    conn.request("GET", c["url"], headers={"User-Agent": UA, "Accept": "*/*"})
                    r = conn.getresponse(); body = r.read()
                    rec.update(status=r.status, bytes=len(body))
                    if r.getheader("Connection", "").lower() == "close" or r.will_close:
                        conn.close(); conn = None
                    break
                except (http.client.HTTPException, OSError) as e:
                    if conn is not None:
                        conn.close()
                    conn = None
                    if attempt == 2:
                        rec.update(status=None, error=f"{type(e).__name__}: {e}"); n_err += 1
            fo.write(json.dumps(rec, ensure_ascii=False) + "\n")
            if (k + 1) % 200 == 0:
                print(f"  {k + 1}/{len(cases)}", flush=True)
            d = gap - (time.time() - t)
            if d > 0:
                time.sleep(d)
    if conn is not None:
        conn.close()
    time.sleep(a.settle)
    t1 = datetime.now(timezone.utc)
    la, ls = tail_from(acc, off_acc, ip), tail_from(sie, off_sie, ip)
    open(os.path.join(a.run, "access_log.txt"), "w", encoding="latin-1").write("".join(l + "\n" for l in la))
    open(os.path.join(a.run, "siem_log.txt"), "w", encoding="latin-1").write("".join(l + "\n" for l in ls))
    sent = [json.loads(l) for l in open(os.path.join(a.run, "sent.jsonl"), encoding="utf-8")]
    n_ok = sum(1 for s in sent if s.get("status") is not None)
    meta = {"ip": ip, "cases_file": a.cases, "n_cases": len(cases), "n_responses": n_ok, "n_errors": n_err,
            "start_utc": t0.isoformat(), "end_utc": t1.isoformat(), "rate": a.rate,
            "access_log_lines": len(la), "siem_log_lines": len(ls), "offsets": {"access_log": off_acc, "siem.log": off_sie}}
    json.dump(meta, open(os.path.join(a.run, "meta.json"), "w", encoding="utf-8"), indent=1)
    print(json.dumps(meta, ensure_ascii=False))
    ok = len(la) == n_ok and len(ls) == n_ok
    print("ĐỐI CHIẾU:", "ĐẠT" if ok else "LỆCH", f"(phản hồi {n_ok}, access_log {len(la)}, siem.log {len(ls)})")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
