#!/usr/bin/env python3
"""Kiểm rule_proposer.py trên dữ liệu tổng hợp: chọn (N, T) đúng là tối ưu dưới ràng buộc báo nhầm (so vét cạn độc
lập), họ chỉ có benign (5xx) / không có alert (4xx khác) không được đề xuất và có lý do, ghép tham lam giữ cả bộ dưới
ngưỡng và thêm họ tăng nhiều nhất trước, CHỈ val quyết định (đổi test không đổi lựa chọn), mô phỏng theo phiên = gọi
wazuh_sim trực tiếp, hồ sơ đọc được bằng apply_rule (định dạng, sha XML, id), verify khớp ở dòng N, chạy lại không tạo
đề xuất trùng.   python3 tests/test_rule_proposer.py"""
import json, math, os, random, shutil, sys, tempfile
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import numpy as np, pandas as pd
import rule_proposer as RP
import wazuh_sim as W

fails = []
def check(c, m):
    if not c: fails.append(m); print("  LỖI:", m)

r = random.Random(7)
rows = []
def sess(key, sc, lab, split, ip, t0, gen):
    t = t0
    for k, (dt, st, url) in enumerate(gen()):
        t += dt
        rows.append({"session_key": key, "scenario": sc, "label": lab, "split": split, "event_epoch": round(t, 6),
                     "status": st, "srcip": ip, "method": "GET", "url": url})

def auth():      return [(r.uniform(.2, .6), 401, "/private/") for _ in range(r.randint(25, 60))]
def scan():      return [(r.uniform(.02, .1), 404 if r.random() < .9 else 301, f"/x{r.randint(0, 9999)}") for _ in range(r.randint(80, 200))]
def mistakes():  return [(r.uniform(2, 6), 404 if r.random() < .5 else 200, f"/dead{r.randint(0, 3)}") for _ in range(r.randint(20, 40))]
def api():       return [(r.uniform(.5, 2), 500 if r.random() < .3 else 200, "/api") for _ in range(r.randint(30, 60))]
def crawler():   return [(r.uniform(.3, 1), 301 if r.random() < .2 else 200, f"/p{r.randint(0, 99)}") for _ in range(r.randint(40, 80))]
def burst():     return [(r.uniform(.001, .01), 200, "/") for _ in range(r.randint(300, 600))]

T0 = 1.8e9; n = 0
for split, reps in (("val", 5), ("test", 4), ("train", 3)):
    for sc, lab, g in (("auth", 1, auth), ("scan", 1, scan), ("mistakes", 0, mistakes), ("api", 0, api), ("crawler", 0, crawler), ("burst", 0, burst)):
        for i in range(reps):
            n += 1; sess(f"X/{split}_{sc}_{i}", sc, lab, split, f"10.9.{n // 250}.{n % 250}", T0 + n * 1000, g)
df = pd.DataFrame(rows)
T = tempfile.mkdtemp(); D = os.path.join(T, "dataset_syn.csv"); df.to_csv(D, index=False)
PR = os.path.join(T, "proposals"); OUT = os.path.join(T, "out")

def run(path=D):
    import io
    from contextlib import redirect_stdout
    with redirect_stdout(io.StringIO()):
        return RP.main(["--data", path, "--proposals", PR, "--out", OUT])

M = run()
V = RP.Sessions(df[df.split.isin(["train", "val"])], "train+val")
allowed = M["allowed_false_alarm_sessions"]
check(allowed == math.floor(0.05 * V.n_ben), f"ngưỡng phiên sai: {allowed}")

# 1. mô phỏng theo phiên == gọi wazuh_sim trực tiếp
for fam, N, Tw in (("r401", 5, 30), ("web_scan", 12, 10), ("any", 50, 10), ("r3xx", 2, 60)):
    nf, pos, ttd = V.simulate(fam, N, Tw)
    for k, key in enumerate(V.keys):
        s = df[df.session_key == key].sort_values("event_epoch", kind="mergesort")
        m = RP.FAMILIES[fam]["member"](s.status.to_numpy())
        win = Tw if V.label[k] == 1 else Tw + RP.SEC_SLACK          # v3: benign xấu nhất T+1 s, tấn công T
        f = W.freq_fires(s.event_epoch.to_numpy()[m].tolist(), N, win) if m.sum() >= N else []
        if sum(f) != nf[k]:
            check(False, f"simulate lệch wazuh_sim: {fam} N={N} T={Tw} {key}"); break

# 2. tổ hợp chọn là TỐI ƯU: vét cạn mọi tổ hợp (mỗi họ: tắt hoặc mọi điểm lưới, KHÔNG bỏ điểm bị trội)
fired = {f: {(N, Tw): V.simulate(f, N, Tw)[0] > 0 for Tw in RP.T_GRID for N in RP.N_GRID} for f in RP.FAMILIES}
att, ben = V.label == 1, V.label == 0
import itertools
best = None
act = [f for f in RP.FAMILIES if any(((v & ben).sum() <= allowed and (v & att).any()) for v in fired[f].values())]
opts = {f: [None] + [k for k, v in fired[f].items() if (v & ben).sum() <= allowed and (v & att).any()] for f in act}
for combo in itertools.product(*[opts[f] for f in act]):
    u = np.zeros(len(V.keys), bool)
    for f, k in zip(act, combo):
        if k: u |= fired[f][k]
    if (u & ben).sum() > allowed: continue
    key = ((u & att).sum(), -(u & ben).sum(), -sum(k is not None for k in combo))
    best = key if best is None or key > best else best
u = np.zeros(len(V.keys), bool)
for f, p in M["chosen"].items(): u |= fired[f][(p["N"], p["T"])]
got = ((u & att).sum(), -(u & ben).sum(), -len(M["chosen"]))
check(tuple(map(int, got)) == tuple(map(int, best)), f"tổ hợp chọn {got} khác tối ưu vét cạn {best}")
check(M["results"]["SELECT"]["union"]["false_alarm"] <= allowed, "cả bộ vượt ngưỡng báo nhầm")
for f in M["chosen"]:
    check(M["results"]["SELECT"]["rules"][f]["unique_detected"] >= 1, f"{f}: luật trong bộ phải đóng góp riêng >= 1 phiên")

# 3. họ chỉ có benign / không có alert: không đề xuất, có lý do + số liệu
check("r5xx" not in M["chosen"] and M["selection_info"]["r5xx"]["val_member_alerts"] > 0 and M["selection_info"]["r5xx"]["reason"],
      f"5xx (chỉ benign) không được đề xuất: {M['selection_info']['r5xx']}")
check("other" not in M["chosen"] and M["selection_info"]["other"]["val_member_alerts"] == 0, "4xx khác (không có alert) không được đề xuất")

# 4. joint_search trên dữ liệu dựng tay: ghép tham lam sẽ chọn A (bắt 3) rồi kẹt; tối ưu là B + C (bắt 4)
class Stub:
    label = np.array([1, 1, 1, 1, 0, 0, 0]); keys = list(range(7))
def pt(att_bits, ben_bits, N=2):
    a = sum(1 << i for i in att_bits); b = sum(1 << i for i in ben_bits)
    fired = np.zeros(7, bool); fired[list(att_bits)] = True; fired[[4 + i for i in ben_bits]] = True
    return {"N": N, "T": 10, "att": a, "ben": b, "ttd_med": 1.0, "fired": fired, "ttd": np.ones(7)}
cs = {"r401": [pt({0, 1, 2}, {0})], "web_scan": [pt({0, 1}, set())], "r3xx": [pt({2, 3}, {1})], "r5xx": [], "other": [], "any": []}
pick, st = RP.joint_search(Stub(), cs, 1)
check(set(pick) == {"web_scan", "r3xx"}, f"joint_search phải chọn web_scan + r3xx (bắt 4, báo nhầm 1), được {list(pick)} {st}")
pick, st = RP.joint_search(Stub(), cs, 2)
check(st["best_key"] == (4, -2, -2) or st["best_key"][0] == 4, f"ngưỡng 2: {st}")
# ràng buộc báo nhầm của CẢ BỘ phải được giữ: 2 luật mỗi luật báo nhầm 1 phiên, ngưỡng 1 -> chỉ được chọn 1 luật
pick, st = RP.joint_search(Stub(), {"r401": [pt({0, 1}, {0})], "web_scan": [pt({2, 3}, {1})]}, 1)
check(len(pick) == 1 and st["best_key"] == (2, -1, -1), f"cả bộ vượt ngưỡng báo nhầm: {list(pick)} {st}")
for f in RP.FAMILIES:
    check(all(bin(p["ben"]).count("1") <= allowed and p["att"] for p in RP.candidates(V, f, allowed)), f"{f}: điểm ứng viên vượt ngưỡng/không bắt gì")
# bỏ điểm bị trội không làm mất tối ưu: điểm trội giữ, điểm bị trội bỏ
keep = RP.candidates(V, "web_scan", allowed)
for p in keep:
    for q in keep:
        if p is not q:
            check(not ((q["att"] | p["att"]) == q["att"] and (q["ben"] | p["ben"]) == p["ben"]), "còn điểm bị trội trong danh sách")

# 5. CHỈ tập chọn (train+val) quyết: đổi nhãn + dữ liệu test không đổi lựa chọn
df2 = df.copy(); te = df2.split == "test"
df2.loc[te, "label"] = 1 - df2.loc[te, "label"]; df2.loc[te, "status"] = 404
D2 = os.path.join(T, "dataset_syn2.csv"); df2.to_csv(D2, index=False)
shutil.rmtree(PR); M2 = run(D2)
check(M2["chosen"] == M["chosen"] and M2["set"] == M["set"], "lựa chọn không được phụ thuộc test")
shutil.rmtree(PR); M = run()

# 6. hồ sơ đọc được bằng apply_rule; verify khớp ở dòng N; hồi quy đạt
import apply_rule as AR
AR.PROPOSALS = PR
pids = M["proposals_written"]
check(len(pids) == len(M["set"]) and len(pids) > 0, f"số đề xuất {len(pids)} != số họ trong bộ {len(M['set'])}")
for pid in pids:
    c, x = AR.load(pid)
    ids = AR.rule_ids(x)
    fam = c["family"]
    check(ids == [str(RP.FAMILIES[fam]["rule_id"])], f"{pid}: id luật {ids}")
    check(c["regression"]["passed"] and c["regression"]["decision_split"] == "train+val", f"{pid}: hồi quy phải đạt trên tập chọn")
    v = c["verify"]
    Nf = c["params"]["frequency"]
    check(v and len(v["lines"]) == Nf + 1 and v["expect_fire_at"] == ([Nf] if Nf > 2 else [2, 3]),
          f"{pid}: verify phải khớp ở dòng N: {v and v['expect_fire_at']}")
    check(all(AR_line.startswith("SIEMLAB ") for AR_line in v["lines"]), "dòng verify phải đúng định dạng SIEMLAB")
    check(f'frequency="{c["params"]["frequency"]}" timeframe="{c["params"]["timeframe"]}"' in x and "<same_srcip />" in x, f"{pid}: XML sai tham số")
    grp = x.split("<group>")[1].split("</group>")[0].split(",")
    check("web_scan" not in grp and "siemlab_observed" not in grp, f"{pid}: nhóm luật con trùng nhóm dùng làm điều kiện cha: {grp}")

    jr = c["regression"]["joint_select"]
    check(jr["union"]["false_alarm"] <= allowed and jr["rule"]["unique_detected"] >= 1 and c["regression"]["time_model"] == "wazuh_sec_worst_case",
          f"{pid}: hồi quy phải gồm kiểm mô phỏng chung + giờ Wazuh: {jr}")

# 8. v3: giờ Wazuh (giây nguyên) và mô phỏng chung
def mini(rows_):
    return pd.DataFrame([{"session_key": k, "scenario": "x", "label": l, "split": "val", "event_epoch": t, "status": st,
                          "srcip": "10.1.1.1", "method": "GET", "url": "/"} for k, l, t, st in rows_])
B = [(t, 404) for t in (0.0, 5.0, 10.5)]                        # 3 sự kiện trải 10,5 s; T = 10
d8 = mini([("ben", 0, 1e9 + t, st) for t, st in B] + [("att", 1, 2e9 + t, st) for t, st in B])
S8 = RP.Sessions(d8, "m"); S8x = RP.Sessions(d8, "m", exact_time=True)
nf8 = dict(zip(S8.keys, S8.simulate("web_scan", 3, 10)[0])); nf8x = dict(zip(S8x.keys, S8x.simulate("web_scan", 3, 10)[0]))
check(nf8["ben"] == 1 and nf8["att"] == 0, f"v3: benign tính cửa sổ T+1 (khớp), tấn công tính T (không khớp): {nf8}")
check(nf8x["ben"] == 0 and nf8x["att"] == 0, f"--exact-time (v2): không khớp cả hai: {nf8x}")
# mô phỏng chung: có r401 (if_matched_sid 100011) thì 401 KHÔNG còn được luật any đếm
d9 = mini([("only401", 1, 3e9 + i * .1, 401) for i in range(6)] + [("only200", 1, 4e9 + i * .1, 200) for i in range(6)])
S9 = RP.Sessions(d9, "j")
u9, per9 = RP.joint_check(S9, {"r401": {"N": 3, "T": 10}, "any": {"N": 3, "T": 10}})
k401, k200 = S9.keys.index("only401"), S9.keys.index("only200")
check(per9["r401"][k401] and not per9["any"][k401] and per9["any"][k200] and u9.all(), f"joint_check: {per9}")
check(S9.simulate("any", 3, 10)[0][k401] > 0, "đối chứng: mô phỏng độc lập thì any có đếm 401")
u9b, per9b = RP.joint_check(S9, {"any": {"N": 3, "T": 10}})
check(per9b["any"][k401], "không có r401 thì any đếm 401 cả trong mô phỏng chung")

# 9. 2c: --purpose demo -> pid DEMO-..., hồ sơ purpose=demo, report có dòng MINH HỌA (thư mục đề xuất riêng để không bị chống trùng)
import io
from contextlib import redirect_stdout
PRD = os.path.join(T, "proposals_demo"); OUTD = os.path.join(T, "out_demo")
with redirect_stdout(io.StringIO()):
    MD = RP.main(["--data", D, "--proposals", PRD, "--out", OUTD, "--purpose", "demo"])
dp = MD["proposals_written"]
check(dp and all(p.startswith("DEMO-R") for p in dp), f"đề xuất minh họa phải có tiền tố DEMO-: {dp}")
check(all(json.load(open(os.path.join(PRD, p + ".json")))["purpose"] == "demo" for p in dp), "hồ sơ phải ghi purpose=demo")
check("MINH HỌA" in open(os.path.join(OUTD, "report.md"), encoding="utf-8").read(), "report minh họa phải ghi rõ")
check(all(json.load(open(os.path.join(PR, p + ".json"))).get("purpose") == "official" for p in pids), "đề xuất thường phải là official")

# 7. chạy lại: không tạo trùng
M3 = run()
check(M3["proposals_written"] == [] and len([f for f in os.listdir(PR) if f.endswith(".json")]) == len(pids), "chạy lại không được tạo đề xuất trùng")

print("OK" if not fails else f"THẤT BẠI {len(fails)}"); shutil.rmtree(T); sys.exit(1 if fails else 0)
