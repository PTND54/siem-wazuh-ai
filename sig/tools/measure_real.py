#!/usr/bin/env python3
"""measure_real.py — nối các lần gửi (send_payloads.py) với alert thật của Manager và cờ AI theo phiên.

Chạy trên HOST (WSL), từ ~/siem-wazuh-ai:
  python3 -B sig/tools/measure_real.py --runs sig/runs/p5_dev_* [--logtest-base sig/runs/p5b_dev] --out sig/runs/p5_dev_measure.json

Mỗi thư mục run = một phiên (một IP). Với mỗi ca:
  - real_sig   : có alert web-accesslog với rule 100100–100199 cho đúng URL đã gửi (đường thật)
  - real_union : có alert web-accesslog của luật xét nội dung (1001xx hoặc dựng sẵn xét nội dung) cho URL đó
  - builtin    : (nếu có --logtest-base) kết quả cấu hình base khi phát lại CHÍNH các dòng access_log của lần gửi qua logtest
Kiểm đường SIEMLAB: số alert SIEMLAB của IP = số phản hồi. Cờ AI: số tài liệu ai-enriched-alerts-* của IP có ai.flag = true.
Chỉ đọc (docker exec grep alerts.json; truy vấn indexer 127.0.0.1:9200 bằng tài khoản lab).
"""
import argparse, base64, collections, glob, json, os, ssl, subprocess, sys, urllib.request
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
from measure_logtest import BUILTIN_CONTENT, wilson  # noqa: E402

MGR = "siem10-wazuh.manager-1"


def alerts_for(ip):
    cmd = (f"grep -hF '\"srcip\":\"{ip}\"' /var/ossec/logs/alerts/alerts.json "
           f"/var/ossec/logs/alerts/2026/*/ossec-alerts-*.json 2>/dev/null")
    out = subprocess.run(["docker", "exec", MGR, "sh", "-c", cmd], capture_output=True, text=True, timeout=600).stdout
    seen, res = set(), []
    for ln in out.splitlines():
        try:
            a = json.loads(ln)
        except Exception:
            continue
        if a.get("id") in seen:
            continue
        seen.add(a.get("id")); res.append(a)
    return res


def es(ip, start, end):
    """Tài liệu ai-enriched-alerts-* có srcip = ip và event_time (giờ Apache) trong [start - 5 s, end + 5 s]."""
    from datetime import datetime, timedelta
    f = lambda s, d: (datetime.fromisoformat(s) + timedelta(seconds=d)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    q = {"size": 0, "query": {"bool": {"filter": [{"term": {"srcip": ip}},
                                                  {"range": {"event_time": {"gte": f(start, -5), "lte": f(end, 5)}}}]}},
         "aggs": {"flag": {"terms": {"field": "ai.flag"}}}}
    req = urllib.request.Request("https://127.0.0.1:9200/ai-enriched-alerts-*/_search", data=json.dumps(q).encode(),
                                 method="POST", headers={"Content-Type": "application/json"})
    req.add_header("Authorization", "Basic " + base64.b64encode(b"admin:SecretPassword").decode())
    try:
        r = json.loads(urllib.request.urlopen(req, timeout=20, context=ctx).read())
        b = {str(x["key_as_string"] if "key_as_string" in x else x["key"]).lower(): x["doc_count"] for x in r["aggregations"]["flag"]["buckets"]}
        return {"total": r["hits"]["total"]["value"], "flagged": b.get("true", 0) + b.get("1", 0)}
    except Exception as e:
        return {"error": str(e)[:200]}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", nargs="+", required=True); ap.add_argument("--logtest-base", default=None)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    allrows, sessions = [], []
    for rd in sorted(a.runs):
        meta = json.load(open(os.path.join(rd, "meta.json")))
        sent = [json.loads(l) for l in open(os.path.join(rd, "sent.jsonl"), encoding="utf-8")]
        cases = {json.loads(l)["cid"]: json.loads(l) for l in open(meta["cases_file"].replace("/workspace/sig", os.path.dirname(HERE)), encoding="utf-8")}
        ip = meta["ip"]
        # chỉ alert trong khoảng của lần gửi (giờ Manager): IP trong dải .2xx có thể đã được dùng ở các ngày trước
        from datetime import datetime, timedelta
        t0 = datetime.fromisoformat(meta["start_utc"]) - timedelta(seconds=5)
        t1 = datetime.fromisoformat(meta["end_utc"]) + timedelta(seconds=180)
        A_all = alerts_for(ip)
        A = [x for x in A_all if t0 <= datetime.strptime(x["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z") <= t1]
        siem = [x for x in A if (x.get("decoder") or {}).get("name") == "siemlab"]
        web = collections.defaultdict(list)
        for x in A:
            if (x.get("decoder") or {}).get("name") == "web-accesslog":
                web[(x.get("data") or {}).get("url")].append(x["rule"]["id"])
        base = None
        if a.logtest_base:
            bp = os.path.join(a.logtest_base, f"base_{os.path.basename(rd)}.jsonl")
            if os.path.exists(bp):
                base = [json.loads(l) for l in open(bp, encoding="utf-8")]
        for k, s in enumerate(sent):
            c = cases[s["cid"]]; u = s["url"].replace("\\", "\\\\"); rids = web.get(u, [])
            row = {**c, "session": os.path.basename(rd), "status": s.get("status"), "web_rules": rids,
                   "real_sig": any(r.isdigit() and 100100 <= int(r) <= 100199 for r in rids),
                   "real_union": any((r.isdigit() and 100100 <= int(r) <= 100199) or r in BUILTIN_CONTENT for r in rids)}
            if base is not None:
                b = base[k]; row["builtin"] = bool(b.get("alert")) and b.get("rule_id") in BUILTIN_CONTENT
            allrows.append(row)
        n_ok = sum(1 for s in sent if s.get("status") is not None)
        ai = es(ip, meta["start_utc"], meta["end_utc"])
        sess = {"session": os.path.basename(rd), "ip": ip, "n": len(sent), "alerts_ip_all_days": len(A_all),
                "siemlab_alerts": len(siem), "siemlab_ok": len(siem) == n_ok,
                "web_alerts": sum(len(v) for v in web.values()), "ai": ai, "rate": meta.get("rate"),
                "start_utc": meta["start_utc"], "end_utc": meta["end_utc"]}
        sessions.append(sess); print(json.dumps(sess, ensure_ascii=False))
    print("\n== theo loại (đường thật)")
    g = collections.defaultdict(list)
    for r in allrows:
        st = r["set"] + ("[" + r["session"] + "]" if r["session"].startswith("slow") else "")
        g[(st, r["category"])].append(r); g[(st, r["category"], r["encoding"])].append(r)
    for k in sorted(g):
        rs = g[k]; n = len(rs)
        cols = [("chữ ký", "real_sig"), ("hợp", "real_union")] + ([("dựng sẵn", "builtin")] if "builtin" in rs[0] else [])
        txt = "  ".join(f"{nm} {sum(r[f] for r in rs):>4}/{n:<4} {100 * sum(r[f] for r in rs) / n:5.1f}%" for nm, f in cols)
        print(f"  {' / '.join(k):<28} {txt}")
    json.dump({"sessions": sessions, "rows": allrows}, open(a.out, "w", encoding="utf-8"), ensure_ascii=False)
    print("->", a.out)


if __name__ == "__main__":
    main()
