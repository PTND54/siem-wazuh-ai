#!/usr/bin/env python3
"""ar_watch.py — nối kết luận AI vào Active Response mà không sửa scripts/ai_service.py. Chạy trong container ar-watch.

Mỗi AR_POLL_S giây hỏi ai-enriched-alerts-*: IP nào có >= AR_MIN_FLAGGED alert ai.flag=true với event_time trong
AR_WINDOW_S giây gần nhất. Với mỗi IP như vậy (trừ AR_WHITELIST, và không lặp lại trong AR_COOLDOWN_S giây) ghi một dòng
  SIEM10AI srcip=<ip> flagged=<n> window=<giây> maxscore=<điểm cao nhất>
vào AR_LOG. Agent đọc file này -> decoder siem10-aiwatch -> luật 100250 (level 10) -> firewall-drop.
Ngưỡng nhiều alert (không chặn ở alert bị gắn cờ đầu tiên): mô hình báo nhầm ở mức phiên, chặn ở cờ đầu tiên sẽ chặn
nhầm người dùng. Chỉ dùng thư viện chuẩn.
"""
import base64, json, os, ssl, time, urllib.request
from datetime import datetime, timezone

URL = os.environ.get("INDEXER_URL", "https://wazuh.indexer:9200").rstrip("/")
AUTH = "Basic " + base64.b64encode(f"{os.environ.get('INDEXER_USERNAME', 'admin')}:{os.environ.get('INDEXER_PASSWORD', 'SecretPassword')}".encode()).decode()
CA = os.environ.get("INDEXER_CA", "/certs/root-ca.pem")
K = int(os.environ.get("AR_MIN_FLAGGED", "10"))
W = int(os.environ.get("AR_WINDOW_S", "60"))
COOL = int(os.environ.get("AR_COOLDOWN_S", "180"))
POLL = float(os.environ.get("AR_POLL_S", "3"))
WL = {x.strip() for x in os.environ.get("AR_WHITELIST", "").split(",") if x.strip()}
OUT = os.environ.get("AR_LOG", "/var/log/ar-watch/ai_block.log")


def context():
    if os.path.exists(CA):
        c = ssl.create_default_context(cafile=CA)
    else:
        c = ssl.create_default_context(); c.verify_mode = ssl.CERT_NONE
    c.check_hostname = False
    return c


CTX = context()
BODY = {"size": 0,
        "query": {"bool": {"filter": [{"term": {"ai.flag": True}}, {"range": {"event_time": {"gte": f"now-{W}s"}}}]}},
        "aggs": {"ip": {"terms": {"field": "srcip", "size": 100, "min_doc_count": K},
                        "aggs": {"mx": {"max": {"field": "ai.score"}}}}}}


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def search():
    req = urllib.request.Request(URL + "/ai-enriched-alerts-*/_search", data=json.dumps(BODY).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": AUTH})
    with urllib.request.urlopen(req, timeout=10, context=CTX) as r:
        return json.loads(r.read())


def main():
    os.makedirs(os.path.dirname(OUT), exist_ok=True); open(OUT, "a").close()
    print(f"{now()} ar-watch: chặn khi một IP có >= {K} alert ai.flag=true trong {W} s; cooldown {COOL} s; "
          f"whitelist {sorted(WL)}; ghi {OUT}", flush=True)
    last, err = {}, 0
    while True:
        try:
            buckets = search().get("aggregations", {}).get("ip", {}).get("buckets", [])
            if err:
                print(f"{now()} indexer trả lời lại bình thường", flush=True)
            err = 0
            for b in buckets:
                ip, n = b["key"], b["doc_count"]
                mx = (b.get("mx") or {}).get("value") or 0.0
                if ip in WL or time.time() - last.get(ip, 0) < COOL:
                    continue
                last[ip] = time.time()
                line = f"SIEM10AI srcip={ip} flagged={n} window={W} maxscore={mx:.3f}"
                with open(OUT, "a") as f:
                    f.write(line + "\n")
                print(f"{now()} -> {line}", flush=True)
        except Exception as e:
            err += 1
            if err in (1, 10) or err % 100 == 0:
                print(f"{now()} lỗi hỏi indexer ({type(e).__name__}: {e}); thử lại", flush=True)
        time.sleep(POLL)


if __name__ == "__main__":
    main()
