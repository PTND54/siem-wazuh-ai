#!/usr/bin/env python3
"""traffic.py — EXECUTOR: gửi các Req của một phiên tới Apache THẬT, từ một IP nguồn riêng.

Ghi lại từng request đã gửi (kế hoạch vs thực tế, mã nhận được, lỗi) để sau này đối chiếu với
siem.log / alerts.json (coverage audit). Không biết gì về nhãn ngoài việc ghi vào manifest.

Dùng riêng 1 phiên để gỡ lỗi:
  python3 scripts/traffic.py --host apache-target --port 80 --scenario scan_fast --seed 1 --split dbg --k 0 --src-ip 172.30.90.40
"""
import argparse, base64, http.client, json, os, random, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scenarios as SC
import site_model as S

BAD_USERS = ["student", "admin", "root", "alice", "bob", "test", "user", "guest"]
BAD_PASS = ["123456", "password", "admin", "letmein", "qwerty", "student", "welcome", "Passw0rd!", "abc123", "iloveyou"]


def auth_header(cred, rng):
    if cred is None:
        return None
    if cred == "good":
        u, p = S.GOOD_USER, S.GOOD_PASS
    else:
        u, p = rng.choice(BAD_USERS), rng.choice(BAD_PASS)
        if (u, p) == (S.GOOD_USER, S.GOOD_PASS) or S.EXTRA_USERS.get(u) == p:
            p += "x"
    return "Basic " + base64.b64encode(f"{u}:{p}".encode()).decode()


def execute_session(sess, host, port, src_ip, log_path, t_start=None, timeout=10.0):
    """Gửi cả phiên. Trả dict tóm tắt. t_start: epoch bắt đầu (mặc định bây giờ)."""
    rng = random.Random(f"auth|{sess['run_id']}")
    t0 = time.time() if t_start is None else t_start
    n_ok = n_err = 0; max_lag = 0.0; conn = None
    os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
    with open(log_path, "w", encoding="utf-8") as lf:
        for i, q in enumerate(sess["reqs"]):
            wait = t0 + q.t - time.time()
            if wait > 0:
                time.sleep(wait)
            lag = max(0.0, time.time() - (t0 + q.t)); max_lag = max(max_lag, lag)
            hdr = {"User-Agent": sess["ua"], "Accept": "*/*"}
            ah = auth_header(q.cred, rng)
            if ah: hdr["Authorization"] = ah
            if not sess["keepalive"]: hdr["Connection"] = "close"
            ts, status, err, retried = time.time(), None, None, 0
            for attempt in (0, 1):
                reused = conn is not None
                try:
                    if conn is None:
                        conn = http.client.HTTPConnection(host, port, timeout=timeout,
                                                          source_address=(src_ip, 0) if src_ip else None)
                    conn.request(q.method, q.url, headers=hdr)
                    r = conn.getresponse(); r.read(); status = r.status; err = None
                    if r.will_close or not sess["keepalive"]:
                        conn.close(); conn = None
                    n_ok += 1
                    break
                except Exception as e:
                    err = repr(e)[:120]
                    try: conn and conn.close()
                    except Exception: pass
                    conn = None
                    # Chỉ thử lại khi kết nối keep-alive CŨ bị Apache đóng (KeepAliveTimeout) trước khi request tới nơi,
                    # như trình duyệt. Không thử lại khi timeout: request có thể đã được xử lý -> trùng dòng log.
                    if reused and attempt == 0 and isinstance(e, (http.client.RemoteDisconnected, BrokenPipeError,
                                                                  ConnectionResetError)):
                        retried = 1; continue
                    n_err += 1
                    break
            lf.write(json.dumps({"i": i, "t_plan": q.t, "t_sent": round(ts, 6), "lag": round(lag, 4), "m": q.method,
                                 "url": q.url, "cred": q.cred, "status": status, "err": err, "retry": retried}) + "\n")
    if conn: conn.close()
    return {"n_planned": len(sess["reqs"]), "n_ok": n_ok, "n_err": n_err, "max_lag": round(max_lag, 3),
            "t_first": round(t0, 6), "t_last": round(time.time(), 6)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="apache-target"); ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--scenario", required=True, choices=sorted(SC.SCEN)); ap.add_argument("--seed", default="1")
    ap.add_argument("--split", default="dbg"); ap.add_argument("--k", type=int, default=0)
    ap.add_argument("--shift", action="store_true"); ap.add_argument("--src-ip", default=None)
    ap.add_argument("--log", default="/tmp/traffic_dbg.jsonl")
    a = ap.parse_args()
    s = SC.build_session(a.scenario, a.seed, a.split, a.k, a.shift)
    print(f"{s['run_id']} label={s['label']} n={len(s['reqs'])} dur={s['duration']:.1f}s peak={s['peak_rps']}rps params={s['params']}")
    print(execute_session(s, a.host, a.port, a.src_ip, a.log))


if __name__ == "__main__":
    main()
