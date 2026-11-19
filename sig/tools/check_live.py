#!/usr/bin/env python3
"""check_live.py — kiểm luồng luật chữ ký trên đường thật sau khi bật access_log cho agent. Chạy trên HOST (WSL).
  python3 -B sig/tools/check_live.py [--no-requests]

1. Agent đang đọc file nào (ossec.log "Analyzing file"), trạng thái logcollector (events/drops từng file, đọc bằng JSON).
2. Số alert decoder web-accesslog trong alerts.json theo từng phút gần đây (phát hiện việc phát lại access_log cũ).
3. (trừ khi --no-requests) gửi 2 request từ host tới 127.0.0.1:8080, mỗi cái gắn mã kiểm riêng: một request thường, một request
   có payload SQLi; đợi rồi tìm alert của chúng. Kỳ vọng: thường -> chỉ 1 alert SIEMLAB; payload -> SIEMLAB + 1001xx.
Không đổi cấu hình nào. 2 request sinh 2 alert SIEMLAB ngoài mọi batch (như canary của apply_rule.py).
"""
import argparse, collections, json, subprocess, sys, time, urllib.request, urllib.error
from datetime import datetime, timezone

MGR, AGT = "siem10-wazuh.manager-1", "wazuh-agent"


def sh(c, args, t=120):
    p = subprocess.run(["docker", "exec", c] + args, capture_output=True, text=True, timeout=t)
    return p.stdout + p.stderr


def alerts_tail(n=20000):
    out = []
    for ln in sh(MGR, ["tail", "-n", str(n), "/var/ossec/logs/alerts/alerts.json"]).splitlines():
        try:
            out.append(json.loads(ln))
        except Exception:
            pass
    return out


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--no-requests", action="store_true"); ap.add_argument("--wait", type=float, default=15)
    a = ap.parse_args()
    print("## agent đang đọc:")
    print("\n".join(sh(AGT, ["sh", "-c", "grep 'Analyzing file' /var/ossec/logs/ossec.log | tail -3"]).splitlines()))
    st = sh(AGT, ["cat", "/var/ossec/var/run/wazuh-logcollector.state"])
    try:
        j = json.loads(st)
        for scope in ("global", "interval"):
            for f in j[scope]["files"]:
                print(f"  logcollector {scope}: {f['location']} events={f['events']} drops={[t['drops'] for t in f['targets']]}")
    except Exception as e:
        print("  không đọc được logcollector.state:", e, st[:200])
    A = alerts_tail()
    web = collections.Counter(x["timestamp"][:16] for x in A if (x.get("decoder") or {}).get("name") == "web-accesslog")
    print(f"## alert web-accesslog theo phút (trong {len(A)} alert cuối): {sorted(web.items())[-10:] or 'không có'}")
    if a.no_requests:
        return 0
    tag = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    reqs = {"thuong": f"/index.html?chk={tag}a", "payload": f"/index.html?chk={tag}b&q=1%27%20union%20select%201,2--"}
    for k, u in reqs.items():
        try:
            code = urllib.request.urlopen("http://127.0.0.1:8080" + u, timeout=10).status
        except urllib.error.HTTPError as e:
            code = e.code
        print(f"## gửi {k}: {u} -> {code}")
    time.sleep(a.wait)
    A = alerts_tail(3000); ok = True
    for k, u in reqs.items():
        key = u.split("&")[0]
        hits = [(x["rule"]["id"], x["rule"]["level"], (x.get("decoder") or {}).get("name")) for x in A if key in x.get("full_log", "")]
        if k == "thuong":
            good = sorted(h[2] for h in hits) == ["siemlab"]
        else:
            good = sorted(h[2] for h in hits) == ["siemlab", "web-accesslog"] and any(h[0].startswith("1001") for h in hits)
        ok &= good
        print(f"  {k}: {hits} -> {'ĐẠT' if good else 'KHÔNG ĐẠT'}")
    print("KẾT QUẢ:", "ĐẠT" if ok else "KHÔNG ĐẠT")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
