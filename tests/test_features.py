#!/usr/bin/env python3
"""Kiểm tra WindowState (O(1)) so với bản tham chiếu ngây thơ O(n^2) viết độc lập, trên dữ liệu ngẫu nhiên
và trên các phiên thật của scenarios.py. Chạy:  python3 tests/test_features.py"""
import math, os, random, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))
import features as F
import scenarios as SC
import site_model as S
from collections import Counter


def ref(events):
    """Tham chiếu: tính lại từ đầu mỗi sự kiện. events: list (t,url,status) cùng IP, t không giảm."""
    out, hist_status = [], [e[2] for e in events]
    for i, (t, u, s) in enumerate(events):
        L = i
        while L > 0 and events[L - 1][0] >= t - 60: L -= 1
        w = events[L:i + 1]; n = len(w)
        d = [w[k + 1][0] - w[k][0] for k in range(n - 1)]
        mean = sum(d) / len(d) if d else 60.0
        if len(d) >= 2 and mean > 0:
            var = sum((x - mean) ** 2 for x in d) / len(d); cv = math.sqrt(var) / mean if var > 1e-12 else 0.0
        else: cv = 0.0
        cl = lambda lo, hi: sum(1 for x in w if lo <= x[2] < hi) / n
        run = 0
        for k in range(i, -1, -1):
            if events[k][2] == 401: run += 1
            else: break
        urls = Counter(x[1] for x in w)
        sa = sum(1 for k in range(L + 1, i + 1) if events[k - 1][2] == 401 and events[k][2] == 200)
        L10 = sum(1 for x in w if x[0] >= t - 10)
        ent = -sum(v / len(u) * math.log2(v / len(u)) for v in Counter(u).values()) if u else 0.0
        out.append({"count_60s": n, "count_10s": L10, "distinct_urls": len(urls), "distinct_status": len({x[2] for x in w}),
                    "max_url_share": max(urls.values()) / n, "mean_interval": mean, "interval_cv": cv,
                    "r2xx": cl(200, 300), "r3xx": cl(300, 400), "r401": sum(1 for x in w if x[2] == 401) / n,
                    "r403": sum(1 for x in w if x[2] == 403) / n, "r404": sum(1 for x in w if x[2] == 404) / n,
                    "r5xx": cl(500, 600), "fail_streak": min(run, n), "succ_after_fail": sa,
                    "url_length": len(u), "url_entropy": ent, "path_depth": u.count("/")})
    return out


def compare(events, tag):
    st, bad = F.WindowState(), 0
    got = [st.push(*e) for e in events]
    exp = ref(events)
    for i, (g, x) in enumerate(zip(got, exp)):
        for k in F.FEATURE_COLUMNS:
            if not math.isclose(g[k], x[k], rel_tol=1e-7, abs_tol=1e-6):
                bad += 1
                if bad <= 5: print(f"  LỆCH {tag} i={i} {k}: online={g[k]} ref={x[k]}")
    return bad


def main():
    bad = 0
    r = random.Random(7)
    pool = ["/a", "/b", "/c/d", "/e.php", "/private/"]
    for trial in range(60):          # ngẫu nhiên, gồm thời điểm trùng nhau và khoảng trống > 60 s
        t, ev = 1000.0, []
        for _ in range(r.randint(1, 250)):
            t += r.choice([0, 0, .01, .2, 1, 5, 30, 59.99, 60, 61, 130]) * r.random() if r.random() < .9 else 0
            ev.append((t, r.choice(pool), r.choice([200, 200, 401, 401, 404, 403, 301, 500, 405])))
        bad += compare(ev, f"rand{trial}")
    for name in SC.SCEN:             # phiên thật của các kịch bản (trạng thái theo mô hình site)
        s = SC.build_session(name, 3, "t", 0)
        ev = [(1e9 + q.t, q.url, S.status_of(q.url, q.cred)) for q in s["reqs"]]
        bad += compare(ev, name)
    # enrich() == đẩy tuần tự, giữ thứ tự đầu vào, tách theo srcip
    evs = []
    for ip, name in (("10.0.0.1", "scan_fast"), ("10.0.0.2", "monitor")):
        s = SC.build_session(name, 5, "t", 0)
        evs += [dict(srcip=ip, event_epoch=2e9 + q.t, url=q.url, status=S.status_of(q.url, q.cred)) for q in s["reqs"]]
    r.shuffle(evs)
    en = F.enrich(evs)
    for a, b in zip(evs, en): assert a["url"] == b["url"] and a["event_epoch"] == b["event_epoch"]
    for ip in ("10.0.0.1", "10.0.0.2"):
        sub = sorted([e for e in evs if e["srcip"] == ip], key=lambda e: e["event_epoch"])
        exp = ref([(e["event_epoch"], e["url"], e["status"]) for e in sub])
        got = sorted([e for e in en if e["srcip"] == ip], key=lambda e: e["event_epoch"])
        for g, x in zip(got, exp):
            for k in F.FEATURE_COLUMNS:
                if not math.isclose(g[k], x[k], rel_tol=1e-7, abs_tol=1e-6): bad += 1
    # dump/load rebuild trạng thái đúng
    st = F.WindowState(); evl = [(1000 + i * .7, f"/p{i % 9}", 401 if i % 3 else 200) for i in range(200)]
    for e in evl[:120]: st.push(*e)
    st2 = F.WindowState.load(st.dump())
    a, b = st.push(*evl[120]), st2.push(*evl[120])
    if any(not math.isclose(a[k], b[k], rel_tol=1e-9, abs_tol=1e-9) for k in F.FEATURE_COLUMNS): bad += 1; print("  LỆCH dump/load")
    try:
        st.push(1.0, "/x", 200); bad += 1; print("  không báo lỗi khi đến ngược thời gian")
    except ValueError:
        pass
    print("OK" if bad == 0 else f"THẤT BẠI: {bad} lệch"); sys.exit(1 if bad else 0)


main()
