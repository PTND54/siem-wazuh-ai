#!/usr/bin/env python3
"""Kiểm ai_service.py trên alerts.json tổng hợp có đủ ca khó:
alert đến lệch thứ tự (reorder buffer), trùng id (file xoay vòng chồng nhau), agent đọc lại (id mới, cùng dòng log),
alert tương quan 110xxx THAY CHO alert gốc (như Wazuh thật: vào cửa sổ đặc trưng như alert gốc), alert thứ hai cùng dòng
log của rule khác (index, mang điểm sự kiện, KHÔNG vào cửa sổ), alert không phải SIEMLAB, dòng ghi dở,
xoay vòng alerts.json, dừng đột ngột rồi khởi động lại (Redis thật nếu có redis-server / REDIS_URL, nếu không thì RAM),
sự kiện trễ, model sai danh sách đặc trưng / features.py đổi, ghi indexer lỗi rồi thử lại.
Đối chiếu chính: đặc trưng + điểm online == features.enrich offline + model trên cùng sự kiện (cùng code path trainer).
  python3 tests/test_ai_service.py            # REDIS_URL=redis://redis:6379/15 để dùng Redis của stack (khóa tiền tố riêng, tự xóa)"""
import json, math, os, random, shutil, socket, subprocess, sys, tempfile, time, uuid
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import numpy as np
import features as F
import ai_service as AS

fails = []
def check(c, m):
    if not c: fails.append(m); print("  LỖI:", m)

T = tempfile.mkdtemp()
RID = {200: "100010", 401: "100011", 404: "100012", 403: "100013"}

# ---------------------------------------------------------------- sự kiện + model nhỏ
r = random.Random(1)
events = []
for k in range(40):
    ip = f"172.30.90.{40 + k}"; t = 1.8e9 + k * 37.0
    kind = k % 4
    for j in range(r.randint(20, 120)):
        t += r.expovariate(1 / (0.15 if kind else 3.0))
        st = (404 if r.random() < .8 else 200) if kind == 1 else 401 if kind == 2 else (200 if r.random() < .9 else 404)
        events.append({"srcip": ip, "event_epoch": round(t, 6), "url": f"/p{r.randint(0, 60)}", "status": st, "label": int(kind > 0)})
events.sort(key=lambda e: e["event_epoch"])
ref = F.enrich(events)                                       # tham chiếu offline (đúng code path build_dataset)
X = np.array([[e[c] for c in F.NO_URL_COLUMNS] for e in ref]); y = np.array([e["label"] for e in events])
from sklearn.ensemble import RandomForestClassifier
rf = RandomForestClassifier(30, random_state=0, min_samples_leaf=3).fit(X, y)
p_ref = np.round(rf.predict_proba(X)[:, 1], 9)
code_sha = AS.sha16(os.path.join(ROOT, "scripts", "features.py"))
bundle = {"format": "siem10-trainer-v1", "model": rf, "features": list(F.NO_URL_COLUMNS), "n_features_in": 15,
          "thresholds": {"f1": 0.5, "fp5": 0.8}, "score_decimals": 9, "versions": {"sklearn": "x"},
          "dataset": {"sha256": "ab" * 32, "features_sha_dataset": code_sha}}
import joblib
MP = os.path.join(T, "model.joblib"); joblib.dump(bundle, MP)
M = AS.load_model(MP)

def usec(e): return int(round(e["event_epoch"] * 1e6))
def alert(e, aid, rid=None, groups=None, decoder="siemlab"):
    rid = rid or RID[e["status"]]
    return json.dumps({"id": aid, "timestamp": "2026-10-21T00:00:00.000+0000",
                       "rule": {"id": rid, "level": 5, "description": "x", "groups": groups or ["siemlab", "siemlab_observed"]},
                       "agent": {"name": "apache-lab-agent"}, **({"decoder": {"name": decoder}} if decoder else {}),
                       "full_log": f'SIEMLAB {usec(e)} {e["srcip"]} "GET {e["url"]} HTTP/1.1" {e["status"]} 10'})

# thứ tự trong file: theo thời gian nhưng xáo trộn cục bộ (< 1 s) như agent/analysisd thật
order = sorted(range(len(events)), key=lambda i: events[i]["event_epoch"] + r.uniform(0, 0.9))
lines, n_corr, n_dup = [], 0, 0
EV_ID = {}                                                                             # i -> id alert mang sự kiện
for n, i in enumerate(order):
    e = events[i]
    if e["status"] == 401 and n % 7 == 0 and i > 2:
        # luật tương quan đã duyệt khớp: Wazuh sinh alert 110011 THAY CHO 100011, không có nhóm siemlab_observed
        lines.append(alert(e, f"c{i}", "110011", ["ai_generated", "authentication_failed", "attack"])); n_corr += 1
        EV_ID[i] = f"c{i}"
    else:
        lines.append(alert(e, f"a{i}")); EV_ID[i] = f"a{i}"
    if n % 97 == 0: lines.append(alert(e, EV_ID[i]))                                  # trùng id
    if n % 89 == 0 and EV_ID[i][0] == "a": lines.append(alert(e, f"re{i}"))           # agent đọc lại: id mới, cùng dòng
    if e["status"] == 401 and n % 11 == 0 and EV_ID[i][0] == "a":                      # (phòng xa) cùng dòng có thêm alert rule khác
        lines.append(alert(e, f"d{i}", "110011", ["web_auth", "siemlab_observed", "ai_generated"])); n_dup += 1
    if n % 131 == 0:                                                                   # SIEMLAB nhưng decoder khác, không nhóm: bỏ
        lines.append(alert(e, f"x{i}", "31108", ["web", "accesslog"], decoder="web-accesslog"))
    if n % 150 == 0: lines.append(json.dumps({"id": f"o{n}", "rule": {"id": "502", "groups": ["ossec"]}, "full_log": "ossec: Manager started."}))
    if n % 151 == 0: lines.append(json.dumps({"id": f"s{n}", "rule": {"id": "31101", "groups": ["web"]}, "full_log": "SIEMLAB không khớp"}))

def write(path, ls, mode="w"):
    with open(path, mode) as f: f.write("".join(l + "\n" for l in ls))

def by_id(docs):
    out = {}
    for d in docs:
        check(d["_id"] not in out, f"tài liệu trùng {d['_id']}"); out[d["_id"]] = d
    return out

def compare(docs, tag):
    D = by_id(docs)
    evd = {k: v for k, v in D.items() if not v["ai"]["duplicate"]}
    check(set(evd) == set(EV_ID.values()), f"[{tag}] thiếu/thừa sự kiện: {len(evd)} vs {len(events)}")
    nc = sum(v["ai"]["kind"] == "correlated" for v in evd.values())
    check(nc == n_corr, f"[{tag}] sự kiện mang alert tương quan {nc} != {n_corr}")
    worst_f = worst_p = 0.0; flag_mis = 0
    for i in range(len(events)):
        d = evd.get(EV_ID[i])
        if d is None: continue
        for c in F.NO_URL_COLUMNS:
            worst_f = max(worst_f, abs(d["ai"]["features"][c] - ref[i][c]))
        worst_p = max(worst_p, abs(d["ai"]["score"] - p_ref[i]))
        flag_mis += d["ai"]["flags"]["fp5"] != (p_ref[i] >= 0.8)
    check(worst_f < 1e-9, f"[{tag}] đặc trưng online khác offline: max|Δ|={worst_f}")
    check(worst_p < 1e-9 and flag_mis == 0, f"[{tag}] điểm/cờ online khác offline: max|Δ|={worst_p}, lệch cờ {flag_mis}")
    dup = [v for v in D.values() if v["ai"]["duplicate"]]
    check(len(dup) == n_dup, f"[{tag}] số alert thứ hai cùng dòng {len(dup)} != {n_dup}")
    for v in dup:
        b = evd.get("a" + v["_id"][1:])
        check(b is not None and v["ai"]["score"] == b["ai"]["score"] and "features" not in v["ai"], f"[{tag}] alert cùng dòng sai: {v['_id']}")
    check(not any(k[0] == "x" for k in D), f"[{tag}] nhận nhầm alert không do decoder siemlab")
    return D

def svc(path, store, out, **kw):
    return AS.Service(M, store, AS.FileSink(out), path, op="fp5", reorder=2.0, idle_flush=1e9, **kw)   # chỉ --once mới xả hết

def read_out(p): return [json.loads(l) for l in open(p)] if os.path.exists(p) else []

# ---------------------------------------------------------------- 1. một lượt
A1 = os.path.join(T, "alerts1.json"); write(A1, lines)
O1 = os.path.join(T, "o1.jsonl")
s1 = svc(A1, AS.MemoryStore(), O1); s1.run(once=True, poll=0)
D1 = compare(read_out(O1), "một lượt")
c = s1.c
check(c["dup_id"] >= 1 and c["dup_line"] >= 1 and c["ignored_non_siemlab"] >= 1 and c["ignored_no_match"] + c["ignored_other_group"] >= 1,
      f"thống kê lọc/bỏ trùng sai: {dict(c)}")
check(c["late"] == 0, f"không được có sự kiện trễ khi xáo trộn < reorder: {c['late']}")
ev_t = [D1[f"a{i}"]["event_time"] for i in range(3)]
check(all(x.endswith("Z") and len(x) == 27 for x in ev_t), f"event_time sai định dạng: {ev_t}")
check(D1["a0"]["ai"]["model_sha"] == M["model_sha"] and D1["a0"]["ai"]["threshold"] == 0.8, "thiếu thông tin model/ngưỡng trong tài liệu")

# 1b. nạp file từng đoạn nhỏ (như tail thật): thứ tự lệch giữa các đoạn chỉ được sửa nhờ reorder buffer
A1b = os.path.join(T, "alerts1b.json"); O1b = os.path.join(T, "o1b.jsonl"); open(A1b, "w").close()
s1b = svc(A1b, AS.MemoryStore(), O1b)
for i in range(0, len(lines), 25):
    write(A1b, lines[i:i + 25], "a"); s1b.step(); s1b.flush_outbox()
s1b.run(once=True, poll=0)
compare(read_out(O1b), "nạp từng đoạn")
check(s1b.c["late"] == 0, f"nạp từng đoạn: xáo trộn < reorder không được sinh sự kiện trễ ({s1b.c['late']})")

# ---------------------------------------------------------------- 2. dòng ghi dở + xoay vòng + dừng đột ngột / khởi động lại
redis_proc = None
def get_store(prefix):
    global redis_proc
    url = os.environ.get("REDIS_URL")
    if not url and shutil.which("redis-server"):
        if redis_proc is None:
            s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
            redis_proc = subprocess.Popen(["redis-server", "--port", str(port), "--save", "", "--appendonly", "no"],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.5)
            get_store.url = f"redis://127.0.0.1:{port}/0"
        url = get_store.url
    if url:
        try:
            return AS.RedisStore(url, prefix), "redis"
        except Exception as e:
            print("  (không kết nối được Redis:", e, "-> dùng RAM)")
    return get_store.mem, "memory"
get_store.mem = AS.MemoryStore()

prefix = f"aitest:{uuid.uuid4().hex[:8]}:"
store, kind = get_store(prefix)
print(f"  kho trạng thái cho kiểm thử khởi động lại: {kind}")
D2 = os.path.join(T, "d2"); os.makedirs(D2); A2 = os.path.join(D2, "alerts.json"); O2 = os.path.join(T, "o2.jsonl")
cut1, cut2 = int(len(lines) * .35), int(len(lines) * .7)
write(A2, lines[:cut1])
with open(A2, "a") as f: f.write(lines[cut1][:40])                                    # dòng đang ghi dở
sA = svc(A2, store, O2)
for _ in range(3): sA.step(); sA.flush_outbox()
check(len(sA.buf) > 0, "phải còn sự kiện trong buffer lúc 'chết' (để kiểm tra khôi phục)")
with open(A2, "a") as f: f.write(lines[cut1][40:] + "\n")
write(A2, lines[cut1 + 1:cut2], "a")
for _ in range(2): sA.step(); sA.flush_outbox()
check(len(sA.buf) > 0, "phải còn sự kiện trong buffer lúc chết")
del sA                                                                                  # chết đột ngột: không xả buffer
sB = svc(A2, store, O2)                                                                 # khởi động lại từ checkpoint
sB.step(); sB.flush_outbox()
os.rename(A2, os.path.join(D2, "ossec-alerts-21.json"))                                 # xoay vòng khi đang chạy
write(A2, lines[cut2:])
sB.run(once=True, poll=0)
docs2 = read_out(O2)
compare(docs2, f"khởi động lại + xoay vòng ({kind})")
check(sB.c["skip_already_done"] >= 1, f"khởi động lại phải bỏ qua alert đã xử lý sau checkpoint: {dict(sB.c)}")
if kind == "redis":
    check(store.outbox_len() == 0 and store.get_ckpt()["offset"] > 0, "outbox/checkpoint Redis sai sau khi chạy xong")
    for k in store.r.scan_iter(prefix + "*"): store.r.delete(k)

# ---------------------------------------------------------------- 3. sự kiện trễ
A3 = os.path.join(T, "alerts3.json"); O3 = os.path.join(T, "o3.jsonl")
e0 = {"srcip": "10.9.9.9", "url": "/a", "status": 404}
seq = [dict(e0, event_epoch=1.8e9 + x) for x in (0, 1, 2, 10, 11)] + [dict(e0, event_epoch=1.8e9 + 3)]   # cái cuối trễ 8 s
write(A3, [alert(e, f"L{n}") for n, e in enumerate(seq[:5])])
s3 = svc(A3, AS.MemoryStore(), O3)
s3.step(force=True)                                                 # 5 sự kiện đầu đã xử lý (sự kiện cuối t=+11)
write(A3, [alert(seq[5], "L5")], "a")                               # đến sau, nhưng thời gian Apache = +3
s3.run(once=True, poll=0)
D3 = by_id(read_out(O3))
check(D3["L5"]["ai"]["late"] and not D3["L4"]["ai"]["late"] and s3.c["late"] == 1, "sự kiện trễ phải được đánh dấu ai.late")
s3b = svc(A3, AS.MemoryStore(), os.path.join(T, "o3b.jsonl")); s3b.run(once=True, poll=0)   # đọc cả file một lượt
check(s3b.c["late"] == 0, "cùng sự kiện đó nếu đọc chung một lượt thì reorder buffer phải xếp lại được (không bị coi là trễ)")
check(D3["L5"]["ai"]["features"]["count_60s"] == 6, "sự kiện trễ vẫn phải vào cửa sổ (thời gian kẹp về sự kiện cuối)")

# ---------------------------------------------------------------- 4. chặn model sai
for bad, msg in ((dict(bundle, features=list(reversed(F.NO_URL_COLUMNS))), "danh sách đặc trưng"),
                 (dict(bundle, dataset={"sha256": "x", "features_sha_dataset": "deadbeef"}), "features.py hiện tại"),
                 (dict(bundle, format="khác"), "không phải model")):
    p = os.path.join(T, "bad.joblib"); joblib.dump(bad, p)
    try:
        AS.load_model(p); check(False, f"phải từ chối model ({msg})")
    except SystemExit as e:
        check(msg in str(e), f"thông báo sai: {e}")
p2 = os.path.join(T, "bad2.joblib"); joblib.dump(dict(bundle, dataset={"sha256": "x", "features_sha_dataset": "deadbeef"}), p2)
AS.load_model(p2, allow_feature_mismatch=True)                                       # cho phép khi người dùng chủ động

# ---------------------------------------------------------------- 5. OpenSearch: bulk + lỗi -> giữ outbox
class FakeOS:
    def __init__(self): self.calls, self.fail = [], True
    def bulk(self, body):
        self.calls.append(body)
        if self.fail:
            raise ConnectionError("indexer chưa sẵn sàng")
        return {"errors": False, "items": []}
fake = FakeOS()
A5 = os.path.join(T, "alerts5.json"); write(A5, lines[:200])
s5 = AS.Service(M, AS.MemoryStore(), AS.OpenSearchSink("http://x", "u", "p", None, client=fake), A5, idle_flush=0.0)
s5.run(once=True, poll=0)
n_out = s5.store.outbox_len()
check(n_out > 0 and s5.c["sink_errors"] >= 1, "indexer lỗi: outbox phải được giữ")
fake.fail = False; s5._flush_safe()
check(s5.store.outbox_len() == 0, "thử lại phải xả outbox")
body = [b for call in fake.calls[-3:] for b in call]
heads = [b["index"] for b in body if "index" in b]
check(heads and all(h["_index"].startswith("ai-enriched-alerts-2027.") or h["_index"].startswith("ai-enriched-alerts-2026.") for h in heads)
      and all(h["_id"] for h in heads), f"bulk header sai: {heads[:2]}")
check(all("_id" not in b for b in body if "index" not in b), "_id không được nằm trong thân tài liệu")

if redis_proc: redis_proc.terminate()
print("OK" if not fails else f"THẤT BẠI {len(fails)}"); sys.exit(1 if fails else 0)
