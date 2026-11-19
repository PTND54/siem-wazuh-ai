#!/usr/bin/env python3
"""run_batch.py — lập lịch và chạy nhiều phiên song song, mỗi phiên một IP nguồn riêng.

  python3 scripts/run_batch.py --preset smoke --dry-run            # chỉ in kế hoạch + ước lượng thời gian
  python3 scripts/run_batch.py --preset smoke  --batch-id smoke1   # chạy thật (trong container lab)
  python3 scripts/run_batch.py --preset dev    --batch-id dev1 --resume

Điểm quan trọng:
  * Mỗi phiên = 1 srcip. Pool IP được TÁI SỬ DỤNG sau `cooldown` giây (mặc định 300 > 120 s timeframe
    của luật tần suất và > 60 s cửa sổ đặc trưng), nên các phiên khác nhau không dính cửa sổ của nhau.
  * Ngân sách tốc độ: tổng peak_rps của các phiên chạy chồng nhau <= --rps-budget (mặc định 150),
    để không vượt giới hạn eps của agent/analysisd (đo thật ở bước coverage audit, không giả định).
  * Thứ tự: train -> val -> test (-> stress). Kế hoạch (IP + thời điểm) được tính trước, xác định theo seed.
  * Resume: phiên đã có trong sessions.jsonl thì bỏ qua. Mọi phiên được ghi vào started.jsonl LÚC BẮT ĐẦU, nên
    phiên bị ngắt giữa chừng (traffic đã vào siem.log nhưng không có dòng trong sessions.jsonl) vẫn được nhận diện
    là "mồ côi" và phải loại khỏi dataset, thay vì thành dữ liệu không nhãn.
  * lockbox: cùng phân phối với train (không shift), seed NGẪU NHIÊN sinh lần đầu và lưu ở data/.lockbox_seed (không
    nằm trong code), nên không ai mô phỏng/nhìn trước được các phiên lockbox. Chỉ chạy khi có --confirm-lockbox.
"""
import argparse, hashlib, heapq, ipaddress, json, os, random, secrets, subprocess, sys, threading, time, traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import scenarios as SC
import traffic as TR

PRESETS = {  # split -> số phiên MỖI kịch bản (benign + malicious); stress riêng
    "smoke":   dict(seed="smoke", splits={"train": 1}, shift=False, stress=1),
    "dev":     dict(seed="dev", splits={"train": 5, "val": 2, "test": 3}, shift=False, stress=2),
    # test 10 phiên/kịch bản: chỉ số theo phiên với 6 phiên/kịch bản có khoảng tin cậy quá rộng
    "full":    dict(seed="full", splits={"train": 18, "val": 6, "test": 10}, shift=False, stress=6),
    "shift":   dict(seed="shift", splits={"shift": 8}, shift=True, stress=3),
    # lockbox 30 phiên/kịch bản (28/10, chốt TRƯỚC khi chạy; bản 26/10 là 10): 450 phiên + 18 stress, ~1 giờ
    "lockbox": dict(seed=None, splits={"lockbox": 30}, shift=False, stress=9),   # seed: xem lockbox_seed()
}


def lockbox_seed(out_root):
    p = os.path.join(os.path.dirname(os.path.abspath(out_root)), ".lockbox_seed")
    if not os.path.exists(p):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(secrets.token_hex(16))
    return "lockbox-" + open(p).read().strip()


def code_digest():
    h = hashlib.sha256()
    for f in ("site_model.py", "scenarios.py", "traffic.py", "run_batch.py"):
        h.update(open(os.path.join(HERE, f), "rb").read())
    return h.hexdigest()[:16]


def make_sessions(preset, seed=None):
    p = dict(PRESETS[preset]); out = []
    if seed is not None: p["seed"] = seed
    if p["seed"] is None: raise ValueError("preset này cần seed (lockbox: dùng lockbox_seed())")
    base = SC.BENIGN + SC.MALICIOUS
    rng = random.Random(f"order|{p['seed']}")
    for split, n in p["splits"].items():
        blk = [SC.build_session(name, p["seed"], split, k, p["shift"]) for name in base for k in range(n)]
        rng.shuffle(blk); out += blk
    blk = [SC.build_session(name, p["seed"], "stress", k, p["shift"]) for name in SC.STRESS for k in range(p["stress"])]
    rng.shuffle(blk); out += blk
    return out


def parse_ips(spec):
    a, b = spec.split("-")
    lo = ipaddress.ip_address(a)
    hi = ipaddress.ip_address(b) if "." in b else ipaddress.ip_address(".".join(a.split(".")[:3] + [b]))
    return [str(ipaddress.ip_address(x)) for x in range(int(lo), int(hi) + 1)]


LEDGER = "_ip_ledger.jsonl"     # dùng CHUNG cho mọi batch trong --out: IP nào được dùng đến lúc nào


def ledger_free(out, ips, cooldown, t0):
    """Offset (giây, tính từ t0) sớm nhất mỗi IP được dùng lại, theo sổ ghi của MỌI batch trước đó.
    Không có sổ này thì batch mới sẽ dùng ngay IP mà batch trước (vd. 'verify') vừa dùng vài phút trước,
    và cửa sổ 60 s của hai phiên khác batch sẽ dính nhau khi dựng dataset."""
    last = {}
    p = os.path.join(out, LEDGER)
    if os.path.exists(p):
        for l in open(p, encoding="utf-8"):
            try: d = json.loads(l)
            except Exception: continue
            last[d["ip"]] = max(last.get(d["ip"], 0.0), d["t_end"])
    return {ip: max(0.0, last[ip] + cooldown - t0) if ip in last else 0.0 for ip in ips}


def plan_schedule(sessions, ips, cooldown, budget, max_parallel, first_free=0.0):
    """Xếp lịch tham lam theo thứ tự đầu vào. Trả list (session, ip, start_offset_s).
    first_free: số (mọi IP) hoặc dict ip -> offset sớm nhất được dùng."""
    ff = first_free if isinstance(first_free, dict) else {ip: first_free for ip in ips}
    # khóa phụ là số nguyên của IP (không phải chuỗi: "…90.100" < "…90.32" theo thứ tự chữ)
    free = [(ff.get(ip, 0.0), int(ipaddress.ip_address(ip)), ip) for ip in ips]; heapq.heapify(free)
    placed = []        # (start, end, peak)
    plan, last_start = [], 0.0
    for s in sessions:
        dur = s["duration"] + 3.0
        t_ip, _, ip = heapq.heappop(free)
        st = max(last_start, t_ip)
        while True:
            ov = [(a, b, pk) for a, b, pk in placed if a < st + dur and b > st]
            load = sum(pk for _, _, pk in ov) + s["peak_rps"]
            if (load <= budget or not ov) and len(ov) < max_parallel:
                break
            st = min(b for _, b, _ in ov)           # chờ phiên kết thúc sớm nhất rồi thử lại
        placed.append((st, st + dur, s["peak_rps"])); last_start = st
        heapq.heappush(free, (st + dur + cooldown, int(ipaddress.ip_address(ip)), ip))
        plan.append((s, ip, st))
    return plan


def summarize(plan):
    n = len(plan); ev = sum(len(s["reqs"]) for s, _, _ in plan)
    end = max(st + s["duration"] for s, _, st in plan)
    by = {}
    for s, _, _ in plan:
        d = by.setdefault((s["split"], s["family"]), 0); by[(s["split"], s["family"])] = d + 1
    ips = len({ip for _, ip, _ in plan})
    return n, ev, end, ips, by


def add_aliases(ips, iface, prefix):
    for ip in ips:
        r = subprocess.run(["ip", "addr", "add", f"{ip}/{prefix}", "dev", iface], capture_output=True, text=True)
        if r.returncode and "File exists" not in r.stderr:
            sys.exit(f"Không thêm được IP alias {ip} trên {iface}: {r.stderr.strip()}\n"
                     f"Cần cap NET_ADMIN (xem docker-compose: service lab) hoặc dùng --no-alias với IP có sẵn.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--preset", required=True, choices=PRESETS)
    ap.add_argument("--batch-id", default=None); ap.add_argument("--out", default="data/runs")
    ap.add_argument("--host", default="apache-target"); ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--ips", default="172.30.90.32-172.30.90.200"); ap.add_argument("--iface", default="eth0")
    ap.add_argument("--prefix", type=int, default=24); ap.add_argument("--no-alias", action="store_true")
    ap.add_argument("--cooldown", type=float, default=300.0); ap.add_argument("--rps-budget", type=float, default=150.0)
    ap.add_argument("--max-parallel", type=int, default=40); ap.add_argument("--max-sessions", type=int, default=0)
    ap.add_argument("--resume", action="store_true"); ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--confirm-lockbox", action="store_true")
    a = ap.parse_args()
    if a.preset == "lockbox" and not a.confirm_lockbox and not a.dry_run:
        sys.exit("lockbox là bộ giữ kín cho đánh giá cuối cùng. Chạy lại với --confirm-lockbox nếu thật sự muốn sinh nó.")
    batch = a.batch_id or a.preset
    bdir = os.path.join(a.out, batch); man = os.path.join(bdir, "sessions.jsonl"); rdir = os.path.join(bdir, "requests")
    if a.preset == "lockbox":
        if a.dry_run: sys.exit("lockbox không hỗ trợ --dry-run (để không lộ seed/phiên trước khi đánh giá cuối).")
        sessions = make_sessions(a.preset, lockbox_seed(a.out))
    else:
        sessions = make_sessions(a.preset)
    if a.max_sessions: sessions = sessions[:a.max_sessions]
    done, prior = set(), os.path.exists(os.path.join(bdir, "started.jsonl"))
    if prior and not a.dry_run:
        # Kiểm theo started.jsonl chứ không theo sessions.jsonl: lần chạy trước có thể bị giết trước khi phiên nào xong,
        # khi đó vẫn đã có traffic trong siem.log từ các IP của pool.
        if not a.resume: sys.exit(f"{bdir} đã có lần chạy trước. Dùng --resume hoặc --batch-id khác.")
        if os.path.exists(man):
            for l in open(man, encoding="utf-8"):
                try: done.add(json.loads(l)["run_id"])
                except Exception: pass      # dòng cuối ghi dở khi tiến trình bị giết
        sessions = [s for s in sessions if s["run_id"] not in done]
    ips = parse_ips(a.ips)
    T0 = time.time() + 3.0
    # Sổ IP chung: IP vừa dùng ở batch/lần chạy trước (kể cả phiên bị ngắt) phải nghỉ đủ cooldown.
    plan = plan_schedule(sessions, ips, a.cooldown, a.rps_budget, a.max_parallel,
                         first_free=ledger_free(a.out, ips, a.cooldown, T0))
    if not plan: print("Không còn phiên nào để chạy."); return
    n, ev, end, nip, by = summarize(plan)
    print(f"preset={a.preset} batch={batch}: {n} phiên, {ev} request, dùng {nip}/{len(ips)} IP, "
          f"ước lượng thời gian chạy ~{end / 60:.1f} phút (ngân sách {a.rps_budget:.0f} rps, cooldown {a.cooldown:.0f}s)")
    for (sp, fam), c in sorted(by.items()): print(f"   {sp:8s} {fam:7s} {c}")
    if a.dry_run: return
    if not a.no_alias: add_aliases(sorted({ip for _, ip, _ in plan}), a.iface, a.prefix)
    os.makedirs(rdir, exist_ok=True)
    meta = {"preset": a.preset, "batch": batch, "code_digest": code_digest(), "python": sys.version.split()[0],
            "args": vars(a), "started": time.time(), "n_sessions": n, "resumed": prior}
    open(os.path.join(bdir, "batch.jsonl"), "a", encoding="utf-8").write(json.dumps(meta) + "\n")   # 1 dòng / lần chạy
    started = os.path.join(bdir, "started.jsonl")
    lock = threading.Lock(); results = []; fails = {"consec": 0}

    ledger = os.path.join(a.out, LEDGER)

    def run_one(s, ip, t_start):
        with lock:
            # t_end_plan = thời điểm kết thúc dự kiến (request cuối + 3 s, như sổ IP). Phiên bị ngắt chỉ có traffic trong
            # [t_start, t_end_plan] (thực tế dừng sớm hơn): đủ để loại chính xác phần dở dang khỏi dataset.
            open(started, "a", encoding="utf-8").write(json.dumps({"run_id": s["run_id"], "srcip": ip, "t_start": t_start,
                                                                   "t_end_plan": t_start + s["duration"] + 3.0}) + "\n")
            # ghi trước thời điểm kết thúc DỰ KIẾN: nếu tiến trình bị giết, lần sau vẫn biết IP này bận tới khi nào
            open(ledger, "a", encoding="utf-8").write(json.dumps({"ip": ip, "t_end": t_start + s["duration"] + 3.0,
                                                                  "batch": batch, "run_id": s["run_id"]}) + "\n")
        try:
            res = TR.execute_session(s, a.host, a.port, ip, os.path.join(rdir, s["run_id"] + ".jsonl"), t_start=t_start)
        except Exception:                   # lỗi không phải mạng (đĩa đầy...): báo rõ, không chết lặng trong thread
            with lock:
                fails["consec"] += 1
                print(f"!! {s['run_id']} lỗi:\n{traceback.format_exc()}")
            return
        row = {k: s[k] for k in ("run_id", "scenario", "family", "label", "split", "shift", "seed", "params", "ua", "keepalive")}
        row.update(srcip=ip, digest=SC.session_digest(s), peak_rps=s["peak_rps"], **res)
        row["failed"] = res["n_err"] > 0.3 * max(res["n_planned"], 1)
        with lock:
            open(ledger, "a", encoding="utf-8").write(json.dumps({"ip": ip, "t_end": res["t_last"], "batch": batch,
                                                                  "run_id": s["run_id"]}) + "\n")
            open(man, "a", encoding="utf-8").write(json.dumps(row) + "\n")
            results.append(row)
            fails["consec"] = fails["consec"] + 1 if row["failed"] else 0
            print(f"[{len(results)}/{n}] {s['run_id']:34s} {ip:15s} n={res['n_ok']}/{res['n_planned']} err={res['n_err']} lag={res['max_lag']}")

    T0 = max(T0, time.time() + 1.0); threads = []
    for s, ip, off in plan:
        if fails["consec"] >= 5: print("5 phiên liên tiếp lỗi mạng -> dừng (Apache có chạy không? đúng --host/--port?)"); break
        w = T0 + off - time.time()
        if w > 0: time.sleep(w)
        th = threading.Thread(target=run_one, args=(s, ip, T0 + off), daemon=True); th.start(); threads.append(th)
    for th in threads: th.join()
    bad = [r for r in results if r["failed"]]
    print(f"xong: {len(results)} phiên, {len(bad)} phiên lỗi mạng; manifest: {man}")


if __name__ == "__main__":
    main()
