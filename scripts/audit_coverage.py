#!/usr/bin/env python3
"""audit_coverage.py — đối chiếu 3 tầng để biết dữ liệu mất ở đâu:

  (1) request generator đã gửi  ->  (2) dòng trong siem.log của Apache  ->  (3) alert trong alerts.json của Wazuh

  python3 scripts/audit_coverage.py --batch data/runs/smoke1 --siem-log /apache-logs/siem.log
  python3 scripts/audit_coverage.py --batch data/runs/dev1 --siem-log /apache-logs/siem.log \
          --alerts /wazuh-logs/alerts/alerts.json /wazuh-logs/alerts/2026/Oct/ossec-alerts-20.json.gz

Mất ở tầng 1->2: generator/Apache (lỗi mạng, Apache quá tải). Mất ở tầng 2->3: agent/analysisd (giới hạn eps,
rule không phủ mã trạng thái, decoder không khớp). Mỗi tầng đếm RIÊNG theo kịch bản và mã HTTP, vì mất không đều
(ví dụ chỉ mất phiên tốc độ cao) sẽ làm lệch tập huấn luyện mà không ai biết.

Mọi so khớp đều theo (srcip, CỬA SỔ THỜI GIAN của phiên): pool IP được tái sử dụng sau cooldown, nên so theo srcip
thuần sẽ cộng nhầm alert của phiên khác cùng IP. Alert rotate qua nửa đêm nằm ở file .json.gz: truyền thêm vào --alerts.
Batch công cụ thật (data/runs/tools) không có log từng request: chỉ báo số dòng siem.log và số alert theo phiên.
Phiên mồ côi (có trong started.jsonl nhưng không có trong sessions.jsonl = bị ngắt giữa chừng) được liệt kê để loại.
Thoát 1 nếu coverage tầng nào < --min-coverage (mặc định 0.99).
"""
import argparse, bisect, glob, gzip, json, os, re, sys
from collections import Counter, defaultdict

LINE = re.compile(r'SIEMLAB (\d+) (\S+) "(\S+) (\S+) \S+" (\d+) (\d+)')
BASE_RULES = {str(i) for i in range(100010, 100020)}     # rule quan sát gốc (mỗi mã HTTP một rule)


def siemlab_match(a):
    """Alert sinh từ MỘT dòng log SIEMLAB, bất kể rule nào khớp sau cùng -> match LINE (hoặc None).
    Wazuh chỉ sinh MỘT alert cho mỗi sự kiện, theo rule khớp sâu nhất trong cây: khi một luật tương quan
    (vd. 110xxx, if_matched_sid + frequency) khớp, sự kiện đó thành alert 110xxx THAY CHO alert 10001x, và alert này
    không mang nhóm siemlab_observed (đã kiểm trên alert thật của v9: 140 dòng log chỉ có alert 110xxx). Vì vậy nhận
    alert theo decoder (siemlab) hoặc nhóm siemlab_observed, không theo id rule."""
    if (a.get("decoder") or {}).get("name") != "siemlab" and "siemlab_observed" not in a.get("rule", {}).get("groups", []):
        return None
    return LINE.search(a.get("full_log", ""))
PRE, POST = 2.0, 10.0          # nới cửa sổ phiên: lệch đồng hồ nhỏ + request cuối còn đang xử lý


def _open(p):
    return gzip.open(p, "rt", errors="replace") if p.endswith(".gz") else open(p, errors="replace")


def read_siem(paths):
    by_ip = defaultdict(list)                       # ip -> list (t, url, status), sắp theo t
    for p in paths:
        with _open(p) as f:
            for l in f:
                m = LINE.search(l)
                if m: by_ip[m[2]].append((int(m[1]) / 1e6, m[4], int(m[5])))
    for v in by_ip.values(): v.sort()
    return by_ip


def expand(patterns, what):
    """Mở rộng glob (kể cả khi shell không mở rộng vì nằm trong container); cảnh báo mẫu không khớp."""
    paths = sorted({p for g in patterns for p in glob.glob(g)})
    miss = [g for g in patterns if not glob.glob(g)]
    if miss: print(f"CẢNH BÁO: không tìm thấy file {what} nào khớp: {miss}")
    if not paths: sys.exit(f"Không có file {what} nào để đọc.")
    return paths


def read_alerts(paths):
    by_ip = defaultdict(list)                       # ip -> list (t, url, status, rule_id), t = thời điểm Apache
    seen = set()                                    # alerts.json là bản của ngày hiện tại trong alerts/YYYY/Mon/ -> trùng id
    for p in paths:
        with _open(p) as f:
            for l in f:
                if "SIEMLAB" not in l: continue
                try: a = json.loads(l)
                except Exception: continue
                aid = a.get("id")
                if aid is not None:                 # alert không có id (dữ liệu tự tạo): không bỏ trùng
                    if aid in seen: continue
                    seen.add(aid)
                m = LINE.search(a.get("full_log", ""))
                if m: by_ip[m[2]].append((int(m[1]) / 1e6, m[4], int(m[5]), a.get("rule", {}).get("id")))
    for v in by_ip.values(): v.sort()
    return by_ip


def window(rows, lo, hi):
    i = bisect.bisect_left(rows, (lo,)); j = bisect.bisect_right(rows, (hi, "￿"))
    return rows[i:j]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch", required=True); ap.add_argument("--siem-log", required=True, nargs="+")
    ap.add_argument("--alerts", default=None, nargs="+"); ap.add_argument("--min-coverage", type=float, default=0.99)
    a = ap.parse_args()
    sess = []
    for l in open(os.path.join(a.batch, "sessions.jsonl"), encoding="utf-8"):
        try: sess.append(json.loads(l))
        except Exception: pass
    siem = read_siem(expand(a.siem_log, "siem.log"))
    alerts = read_alerts(expand(a.alerts, "alert")) if a.alerts else None
    tot1, hit1, tot2, hit2 = Counter(), Counter(), Counter(), Counter()
    worst, lag, extra, n_err, tools = [], [], 0, 0, []
    for s in sess:
        if "t_first" not in s: continue              # tool bị skipped
        lo, hi = s["t_first"] - PRE, s["t_last"] + POST
        lines = window(siem.get(s["srcip"], []), lo, hi)
        got = Counter((u, st) for _, u, st in lines)
        if alerts is not None:
            al = Counter((u, st) for _, u, st, _ in window(alerts.get(s["srcip"], []), lo, hi))
            for key, c in got.items():
                tot2[(s["scenario"], key[1])] += c; hit2[(s["scenario"], key[1])] += min(c, al.get(key, 0))
        rq = os.path.join(a.batch, "requests", s["run_id"] + ".jsonl")
        if not os.path.exists(rq):                   # công cụ thật: không có log từng request
            tools.append((s["run_id"], len(lines), sum(1 for _ in window(alerts.get(s["srcip"], []), lo, hi)) if alerts else None))
            continue
        reqs = [json.loads(l) for l in open(rq, encoding="utf-8")]
        sent = [r for r in reqs if r["status"] is not None]; n_err += len(reqs) - len(sent)
        left = Counter(got); miss = 0
        for r in sent:
            key = (r["url"], r["status"]); tot1[(s["scenario"], r["status"])] += 1
            if left[key] > 0: left[key] -= 1; hit1[(s["scenario"], r["status"])] += 1
            else: miss += 1
        extra += sum(left.values())                  # dòng log không ứng với request nào đã ghi (trùng lặp? phiên khác?)
        worst.append((round(miss / max(len(sent), 1), 4), s["run_id"], len(sent), miss))
        lag += [r["lag"] for r in reqs if r.get("lag") is not None]

    def show(title, tot, hit):
        print(f"\n== {title} ==")
        sc = defaultdict(lambda: [0, 0]); st = defaultdict(lambda: [0, 0])
        for (s, c), n in tot.items():
            sc[s][0] += n; sc[s][1] += hit[(s, c)]; st[c][0] += n; st[c][1] += hit[(s, c)]
        print("  theo kịch bản:", {k: f"{v[1]}/{v[0]}" for k, v in sorted(sc.items())})
        print("  theo mã HTTP :", {k: f"{v[1]}/{v[0]}" for k, v in sorted(st.items())})
        N, H = sum(tot.values()), sum(hit.values())
        print(f"  TỔNG {H}/{N} = {H / max(N, 1):.4f}")
        return H / max(N, 1) if N else 1.0

    c1 = show("Tầng 1->2: generator -> siem.log", tot1, hit1) if tot1 else 1.0
    c2 = show("Tầng 2->3: siem.log -> alerts.json", tot2, hit2) if alerts is not None else 1.0
    if tot1:
        worst.sort(reverse=True)
        print(f"\nRequest lỗi mạng (không tới Apache): {n_err}. Dòng siem.log thừa trong cửa sổ phiên: {extra}")
        print("Phiên thiếu nhiều nhất (tỉ lệ, run_id, đã gửi, thiếu):", worst[:5])
    if lag: print(f"Trễ lịch của generator: p50={sorted(lag)[len(lag) // 2]:.3f}s  max={max(lag):.3f}s")
    if tools:
        print("\nCông cụ thật (run_id, số dòng siem.log, số alert):")
        for t in tools: print("  ", t)
    st_path = os.path.join(a.batch, "started.jsonl")
    if os.path.exists(st_path):
        # mồ côi = lần khởi động (run_id, srcip, t_start) không có phiên hoàn tất tương ứng. So cả srcip/thời điểm vì
        # phiên bị ngắt được chạy lại với CÙNG run_id nhưng IP/thời điểm khác.
        done = {(s["run_id"], s["srcip"], round(s["t_first"], 3)) for s in sess if "t_first" in s}
        orphan = [json.loads(l) for l in open(st_path, encoding="utf-8") if l.strip()]
        orphan = [o for o in orphan if (o["run_id"], o["srcip"], round(o["t_start"], 3)) not in done]
        if orphan:
            print(f"\nPhiên MỒ CÔI (bị ngắt): {len(orphan)}. Loại khỏi dataset mọi dòng của srcip trong [t_start-{PRE:.0f}s, t_end_plan+{POST:.0f}s]:")
            for o in orphan[:20]:
                lo, hi = o["t_start"] - PRE, o.get("t_end_plan", o["t_start"] + 900) + POST   # bản cũ không có t_end_plan: giả định tối đa 900 s
                n = len(window(siem.get(o["srcip"], []), lo, hi))
                print(f"   {o['run_id']:34s} {o['srcip']:15s} {lo:.1f}-{hi:.1f}  ({n} dòng siem.log)")
    sys.exit(0 if min(c1, c2) >= a.min_coverage else 1)


if __name__ == "__main__":
    main()
