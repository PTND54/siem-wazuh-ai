#!/usr/bin/env python3
"""rule_proposer.py — bước 2a: đề xuất luật tần suất Wazuh (frequency + timeframe + same_srcip) từ dữ liệu có nhãn.

  python3 scripts/rule_proposer.py --data data/dataset_full1.csv \
      --eval data/dataset_shift1.csv data/dataset_tools2.csv --metrics models/full1/metrics.json
  -> proposals/<pid>.{json,xml} (status 'proposed', cho apply_rule.py) + output/rules_full1/{report.md, rules.json}

Thiết kế đã chốt TRƯỚC khi chạy (22/10/2026):
  * 6 họ luật, chỉ dùng điều kiện Wazuh làm được (ngữ nghĩa đã đo — wazuh_sim.py; different_url bị loại vì đo được
    là không chặn được người dùng lặp lại vài link chết):
        r401 (if_matched_sid 100011) | web_scan 403+404 (if_matched_group web_scan) | r3xx (100014) | r5xx (100015)
        | other 4xx khác (100016) | any = mọi mã (if_matched_group siemlab_observed).
  * Lưới: T ∈ {10, 30, 60, 120, 240} s (IP chỉ được dùng lại sau 300 s nên T < 300 không vắt sang phiên trước),
    N ∈ lưới của trainer (2 … 1000).
  * Tập CHỌN = train + val (v2, 22/10 23:20). Test/shift/stress/tools chỉ GHI vào hồ sơ, không dùng để quyết.
  * DÒ CHUNG cả bộ: mỗi họ hoặc tắt, hoặc một (N, T); chọn tổ hợp bắt NHIỀU phiên tấn công nhất (tập chọn) với tổng số
    phiên benign bị CẢ BỘ báo nhầm <= floor(5% x số phiên benign của tập chọn); hòa -> ít báo nhầm hơn -> ít luật hơn
    -> trung vị thời gian đến lần bắt đầu sớm hơn -> thứ tự liệt kê. Điểm (N, T) bị trội (bắt tập con, báo nhầm tập cha
    của điểm khác cùng họ) được bỏ trước để dò nhanh; kết quả vẫn là tối ưu (test so với vét cạn).
  * Tiêu chí hồi quy (để apply_rule cho áp): trên tập chọn, cả bộ <= ngưỡng báo nhầm và MỖI luật đóng góp >= 1 phiên
    tấn công mà các luật khác trong bộ không bắt.
  * LỊCH SỬ — v1 (22/10 22:59, đã bỏ): chọn CHỈ trên val (48 phiên benign, cho phép 2) + chọn từng họ rồi ghép tham
    lam -> bộ web_scan N=10 T=10 + r401 N=12 T=60 + r3xx N=2 T=10: val 34/42 bắt, 2/48 báo nhầm, nhưng test 10/80
    (12,5%) báo nhầm (broken_links 7/10) và train 16/144 (11,1%); flood không luật nào bắt vì web_scan dùng hết hạn
    mức. Lý do sửa: val quá ít phiên benign (6 phiên broken_links) và ghép tham lam để một họ chiếm hết hạn mức. Vì
    đã nhìn kết quả test trước khi sửa, số trên test của v2 là "đã nhìn"; số cuối cùng lấy từ lockbox.
  * v3 (26/10, sau bước 2b trên Wazuh thật):
      - GIỜ: Wazuh so timeframe bằng giây nguyên (giờ Manager) nên cửa sổ thật dài từ T đến gần T+1 giây. v2 dùng giờ
        Apache chính xác tới micro giây và chọn đúng sát biên: bộ v2 (any N=500 T=10) có 9/192 báo nhầm theo giờ chính
        xác nhưng 11/192 (> ngưỡng 9) khi làm tròn giây như Wazuh (thêm 2 phiên heavy_burst). v3 tính theo trường hợp
        XẤU NHẤT: phiên benign dùng cửa sổ T+1 s (báo nhầm nhiều nhất), phiên tấn công dùng cửa sổ T (bắt ít nhất).
        `--exact-time` tái lập v2.
      - TƯƠNG TÁC: bộ đã chọn được kiểm lại bằng mô phỏng CHUNG (wazuh_sim.joint_fires, theo mã nguồn Wazuh: luật sid
        lấy sự kiện khỏi danh sách nhóm, dấu khớp chặn luật khác), thứ tự nạp = thứ tự id luật. Hồi quy chỉ đạt khi cả
        bộ mô phỏng chung vẫn <= ngưỡng báo nhầm và mỗi luật vẫn có >= 1 phiên tấn công riêng.
  * v4-AI (28/10, trước lockbox): `--label-source ai` — nhãn của phiên dùng để CHỌN là KẾT LUẬN CỦA AI, không phải ý
    định kịch bản: phiên "nghi ngờ" nếu RF (model.joblib, điểm vận hành fp5) gắn cờ >= 1 alert của phiên (k = 1, cùng
    định nghĩa với trainer/lockbox_eval). Chỉ dùng phiên RF CHƯA HỌC: mặc định split val của dataset huấn luyện + các
    dataset `--select-extra` (bỏ split stress — stress chỉ để đánh giá); từ chối nếu tập chọn chứa split train của chính
    dataset đã huấn luyện model. Mọi thứ khác giữ như v3 (họ, lưới, dò chung, hạn mức 5% — tính trên số phiên AI cho là
    sạch, cửa sổ xấu nhất theo nhãn AI). Nhãn THẬT chỉ để báo cáo/đánh giá (các tập khác, và dòng "tập chọn — nhãn thật").
    Thiết kế chốt trước khi chạy; đề xuất mang tiền tố 'AI-', hồ sơ ghi label_source, sha model, ngưỡng, mức đồng thuận
    AI/nhãn thật trên tập chọn.
"""
import argparse, hashlib, json, math, os, sys, time
from collections import OrderedDict
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import numpy as np
import pandas as pd
import wazuh_sim as W

FP_TARGET = 0.05
SEC_SLACK = 1 - 1e-6        # Wazuh: (giờ hiện tại - giờ sự kiện, cả hai là giây nguyên) > T mới hết hạn -> cửa sổ thật < T+1 s
T_GRID = (10, 30, 60, 120, 240)
N_GRID = (2, 3, 4, 5, 6, 8, 10, 12, 15, 20, 30, 50, 75, 100, 150, 200, 300, 400, 500, 600, 800, 1000)
TEMPLATE = {"name": "freq_same_srcip", "version": 1}
LEVEL = 10


def _3xx(s): return (s >= 300) & (s < 400)
def _5xx(s): return s >= 500
def _other(s): return ~(np.isin(s, (200, 401, 403, 404)) | _3xx(s) | _5xx(s))


FAMILIES = OrderedDict([
    ("r401", dict(rule_id=110011, member=lambda s: s == 401, cond="<if_matched_sid>100011</if_matched_sid>",
                  desc="HTTP 401 (dang nhap sai)")),
    ("web_scan", dict(rule_id=110020, member=lambda s: np.isin(s, (403, 404)), cond="<if_matched_group>web_scan</if_matched_group>",
                      desc="HTTP 403/404 (do quet)")),
    ("r3xx", dict(rule_id=110014, member=_3xx, cond="<if_matched_sid>100014</if_matched_sid>", desc="HTTP 3xx")),
    ("r5xx", dict(rule_id=110015, member=_5xx, cond="<if_matched_sid>100015</if_matched_sid>", desc="HTTP 5xx")),
    ("other", dict(rule_id=110016, member=_other, cond="<if_matched_sid>100016</if_matched_sid>",
                   desc="HTTP ma khac (400/405/...)")),
    ("any", dict(rule_id=110030, member=lambda s: np.ones(len(s), bool), cond="<if_matched_group>siemlab_observed</if_matched_group>",
                 desc="moi ma HTTP (tan suat cao)")),
])


# ============================================================ nhãn từ AI (v4-AI)
def ai_session_verdicts(paths_rows, model_path, op="fp5"):
    """Kết luận của RF theo phiên. paths_rows: [(csv, tập session_key cần)]. Đọc CSV như trainer.load_dataset
    (pd.read_csv mặc định) để điểm trùng tuyệt đối với trainer/lockbox_eval. Trả ({session_key: 0/1}, thông tin)."""
    import joblib
    B = joblib.load(model_path)
    cols, tau, dec = list(B["features"]), float(B["thresholds"][op]), int(B["score_decimals"])
    out, n_alerts, n_flag = {}, 0, 0
    for path, keys in paths_rows:
        d = pd.read_csv(path, low_memory=False, usecols=["session_key"] + cols)
        d = d[d.session_key.isin(keys)]
        if d[cols].isna().any().any():
            raise SystemExit(f"{path}: giá trị rỗng trong cột đặc trưng — không chấm được")
        sc = np.round(B["model"].predict_proba(d[cols].to_numpy(float))[:, 1], dec)
        fl = pd.Series(sc >= tau, index=d.index)
        g = fl.groupby(d.session_key).any()
        for k, v in g.items():
            out[k] = int(v)
        n_alerts += len(d); n_flag += int(fl.sum())
        miss = set(keys) - set(g.index)
        if miss:
            raise SystemExit(f"{path}: {len(miss)} phiên không có dòng để chấm (vd. {sorted(miss)[:3]})")
    info = {"model": model_path, "model_sha256": sha256_file(model_path), "op": op, "threshold": tau, "score_decimals": dec,
            "k": 1, "rule": f"phiên nghi ngờ nếu >= 1 alert có round(predict_proba, {dec}) >= {tau} ({op})",
            "alerts_scored": n_alerts, "alerts_flagged": n_flag, "model_train_data": B.get("dataset", {})}
    return out, info


# ============================================================ dữ liệu: các phiên của một tập
class Sessions:
    def __init__(self, df, name, exact_time=False):
        df = df.sort_values(["session_key", "event_epoch"], kind="mergesort").reset_index(drop=True)
        self.name, self.df = name, df
        self.keys = list(dict.fromkeys(df.session_key))
        g = df.groupby("session_key", sort=False)
        first = g.head(1).set_index("session_key")
        self.label = first.label.astype(int).reindex(self.keys).to_numpy()
        self.scenario = first.scenario.reindex(self.keys).to_numpy()
        self.idx = [np.asarray(g.indices[k]) for k in self.keys]
        self.t = df.event_epoch.to_numpy(float); self.status = df.status.to_numpy(int)
        self.n_ben, self.n_att = int((self.label == 0).sum()), int((self.label == 1).sum())
        self.exact_time = exact_time
        self._memo = {}

    def window(self, k, T):
        """Cửa sổ dùng cho phiên k: xấu nhất theo nhãn (benign T+1 s, tấn công T) trừ khi --exact-time."""
        return T if (self.exact_time or self.label[k] == 1) else T + SEC_SLACK

    def simulate(self, fam, N, T):
        """Mỗi phiên: (số lần luật khớp, vị trí alert khớp đầu trong phiên (1-based), giây từ request đầu đến khớp đầu)."""
        key = (fam, N, T)
        if key in self._memo:
            return self._memo[key]
        mem_all = FAMILIES[fam]["member"](self.status)
        nf = np.zeros(len(self.keys), int); pos = np.full(len(self.keys), np.nan); ttd = np.full(len(self.keys), np.nan)
        for k, ix in enumerate(self.idx):
            m = ix[mem_all[ix]]
            if len(m) < N:
                continue
            f = W.freq_fires(self.t[m].tolist(), N, self.window(k, T))
            hits = [j for j, x in enumerate(f) if x]
            if hits:
                nf[k] = len(hits)
                first_ev = m[hits[0]]
                pos[k] = int(np.searchsorted(ix, first_ev)) + 1
                ttd[k] = self.t[first_ev] - self.t[ix[0]]
        self._memo[key] = (nf, pos, ttd)
        return self._memo[key]


def summarize(S, fired, nf=None, ttd=None, pos=None):
    att, ben = S.label == 1, S.label == 0
    out = {"attack_sessions": S.n_att, "benign_sessions": S.n_ben,
           "detected": int(fired[att].sum()), "false_alarm": int(fired[ben].sum()),
           "detect_rate": float(fired[att].mean()) if S.n_att else None, "fp_rate": float(fired[ben].mean()) if S.n_ben else None}
    if ttd is not None:
        d = att & fired
        out["ttd_median_s"] = float(np.nanmedian(ttd[d])) if d.any() else None
        out["alerts_to_first_median"] = float(np.nanmedian(pos[d])) if d.any() else None
        out["fires_per_detected_session_median"] = float(np.median(nf[d])) if d.any() else None
    return out


def by_scenario(S, fired):
    rows = []
    for sc in sorted(set(S.scenario), key=lambda x: (str(x))):
        k = S.scenario == sc
        rows.append({"scenario": sc, "label": int(S.label[k][0]), "sessions": int(k.sum()), "fired": int(fired[k].sum())})
    return sorted(rows, key=lambda r: (r["label"], r["scenario"]))


# ============================================================ chọn trên val
def choose_family(V, fam, allowed):
    best, n_feasible, best_any = None, 0, None
    for T in T_GRID:
        for N in N_GRID:
            nf, pos, ttd = V.simulate(fam, N, T)
            fired = nf > 0
            det, fa = int(fired[V.label == 1].sum()), int(fired[V.label == 0].sum())
            if best_any is None or (det, -fa) > best_any[0]:
                best_any = ((det, -fa), N, T, fa)
            if fa > allowed:
                continue
            n_feasible += 1
            d = (V.label == 1) & fired
            med = float(np.nanmedian(ttd[d])) if d.any() else math.inf
            key = (det, -med, N, -T)
            if best is None or key > best[0]:
                best = (key, N, T, det, fa, med)
    if best is None or best[3] == 0:
        why = ("không có (N, T) nào giữ được báo nhầm <= ngưỡng" if best is None else "không (N, T) nào vừa đạt ngưỡng báo nhầm vừa bắt được phiên tấn công")
        n_member = int(sum(FAMILIES[fam]["member"](V.status)))
        return None, {"reason": why, "val_member_alerts": n_member, "feasible_points": n_feasible,
                      "best_unconstrained": {"N": best_any[1], "T": best_any[2], "detected": best_any[0][0], "false_alarm": best_any[3]} if best_any else None}
    _, N, T, det, fa, med = best
    return {"N": N, "T": T}, {"detected": det, "false_alarm": fa, "ttd_median_s": med, "feasible_points": n_feasible}


def candidates(S, fam, allowed):
    """Các điểm (N, T) của họ trên tập chọn: bắt >= 1 phiên tấn công, báo nhầm <= allowed; bỏ điểm bị trội."""
    att_i, ben_i = np.flatnonzero(S.label == 1), np.flatnonzero(S.label == 0)
    pts = []
    for T in T_GRID:
        for N in N_GRID:
            nf, pos, ttd = S.simulate(fam, N, T)
            f = nf > 0
            a = sum(1 << int(i) for i in np.flatnonzero(f[att_i])); b = sum(1 << int(i) for i in np.flatnonzero(f[ben_i]))
            if a == 0 or bin(b).count("1") > allowed:
                continue
            med = float(np.nanmedian(ttd[(S.label == 1) & f]))
            pts.append({"N": N, "T": T, "att": a, "ben": b, "ttd_med": med, "fired": f, "ttd": ttd})
    pts.sort(key=lambda p: (p["ttd_med"], -p["N"], p["T"]))          # cùng mặt nạ: giữ điểm ưu tiên hơn
    keep = []
    for p in pts:
        if any((q["att"] | p["att"]) == q["att"] and (q["ben"] | p["ben"]) == p["ben"] for q in keep):
            continue                                                  # q bắt >= p và báo nhầm <= p
        keep = [q for q in keep if not ((p["att"] | q["att"]) == p["att"] and (p["ben"] | q["ben"]) == q["ben"])]
        keep.append(p)
    return keep


def joint_search(S, cands, allowed):
    """Tổ hợp tối ưu (mỗi họ: tắt hoặc một điểm). cands: {họ: [điểm]}. Trả (chọn {họ: điểm}, thống kê)."""
    fams = [f for f in cands if cands[f]]
    best, n_eval, ties = None, 0, []
    pc = lambda x: bin(x).count("1")

    def rec(i, a, b, chosen):
        nonlocal best, n_eval, ties
        if i == len(fams):
            n_eval += 1
            key = (pc(a), -pc(b), -len(chosen))
            if best is None or key > best:
                best, ties = key, [dict(chosen)]
            elif key == best:
                ties.append(dict(chosen))
            return
        rec(i + 1, a, b, chosen)                                       # họ i tắt
        for p in cands[fams[i]]:
            nb = b | p["ben"]
            if pc(nb) > allowed:
                continue
            chosen[fams[i]] = p
            rec(i + 1, a | p["att"], nb, chosen)
            del chosen[fams[i]]

    rec(0, 0, 0, {})

    def tiekey(ch):
        if not ch:
            return (math.inf,)
        t = np.fmin.reduce([np.where(p["fired"], p["ttd"], np.nan) for p in ch.values()]) if len(ch) > 1 else \
            np.where(next(iter(ch.values()))["fired"], next(iter(ch.values()))["ttd"], np.nan)
        m = t[S.label == 1]
        return (float(np.nanmedian(m)) if np.isfinite(m).any() else math.inf, [list(FAMILIES).index(f) for f in ch])
    pick = min(ties, key=tiekey) if ties else {}
    return pick, {"combinations_evaluated": n_eval, "ties_at_best": len(ties), "best_key": best,
                  "candidate_points": {f: len(c) for f, c in cands.items()}}


def joint_check(S, chosen):
    """Mô phỏng CHUNG bộ đã chọn (thứ tự nạp = id luật tăng dần). Trả (fired_union, {họ: fired}) theo phiên."""
    order = sorted(chosen, key=lambda f: FAMILIES[f]["rule_id"])
    u = np.zeros(len(S.keys), bool); per = {f: np.zeros(len(S.keys), bool) for f in order}
    if not order:
        return u, per
    for k, ix in enumerate(S.idx):
        specs = []
        for f in order:
            cond = FAMILIES[f]["cond"]; val = cond.split(">")[1].split("<")[0]
            d = {"id": FAMILIES[f]["rule_id"], "level": LEVEL, "N": chosen[f]["N"], "T": S.window(k, chosen[f]["T"]),
                 "groups": f"ai_generated,siem10_{f},attack,ai_generated,"}
            d["sid" if "if_matched_sid" in cond else "group"] = int(val) if "if_matched_sid" in cond else val
            specs.append(d)
        fin = W.joint_fires(S.t[ix].tolist(), S.status[ix], specs)
        hit = set(fin)
        for f in order:
            per[f][k] = FAMILIES[f]["rule_id"] in hit
        u[k] = any(per[f][k] for f in order)
    return u, per


# ============================================================ đầu ra
def rule_xml(fam, N, T, label_source="truth"):
    """Nhóm của luật đề xuất KHÔNG được trùng nhóm dùng làm điều kiện cha (web_scan, siemlab_observed): nếu trùng, alert
    của luật con (vd. 110014 khớp một sự kiện 3xx) sẽ bị luật đếm theo nhóm (110020) đếm vào, lệch khỏi mô phỏng.
    label_source chỉ đổi mô tả (không đổi điều kiện khớp)."""
    F = FAMILIES[fam]
    src = " tu ket luan AI" if label_source == "ai" else ""
    return (f'<group name="ai_generated,">\n'
            f'  <rule id="{F["rule_id"]}" level="{LEVEL}" frequency="{N}" timeframe="{T}">\n'
            f'    {F["cond"]}\n'
            f'    <same_srcip />\n'
            f'    <description>siem10 de xuat{src} [{fam}]: {F["desc"]} &gt;= {N} lan trong {T}s tu cung nguon</description>\n'
            f'    <group>siem10_{fam},attack,ai_generated,</group>\n'
            f'  </rule>\n</group>\n')


def verify_lines(V, fam, N, T):
    """N dòng SIEMLAB của rule cha lấy từ một phiên tấn công val mà luật bắt được (+1 dòng sau) — logtest đọc liền
    một mạch (giờ = lúc đọc, đều trong T), nên kỳ vọng luật khớp đúng ở dòng thứ N."""
    nf, _, _ = V.simulate(fam, N, T)
    mem = FAMILIES[fam]["member"](V.status)
    for k in np.flatnonzero((V.label == 1) & (nf > 0)):
        m = V.idx[k][mem[V.idx[k]]]
        if len(m) >= N + 1:
            d = V.df.iloc[m[:N + 1]]
            lines = [f'SIEMLAB {int(round(r.event_epoch * 1e6))} {r.srcip} "{r.method} {r.url} HTTP/1.1" {int(r.status)} 0'
                     for r in d.itertuples()]
            exp = [j + 1 for j, x in enumerate(W.freq_fires([0.0] * len(lines), N, T)) if x]
            return {"lines": lines, "expect_fire_at": exp, "source_session": V.keys[k],
                    "note": "logtest đọc liền một mạch nên mọi dòng nằm trong T; kỳ vọng tính bằng wazuh_sim"}
    return None


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()


def fmt_rate(s):
    a = f"{s['detected']}/{s['attack_sessions']}" if s["attack_sessions"] else "—"
    b = f"{s['false_alarm']}/{s['benign_sessions']}" if s["benign_sessions"] else "—"
    pa = f" ({100 * s['detect_rate']:.1f}%)" if s["attack_sessions"] else ""
    pb = f" ({100 * s['fp_rate']:.1f}%)" if s["benign_sessions"] else ""
    return a + pa, b + pb


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", required=True, help="dataset có split train/val/test/stress (vd. dataset_full1.csv)")
    ap.add_argument("--eval", nargs="*", default=[], help="tập chỉ-đánh-giá (shift, tools)")
    ap.add_argument("--metrics", default=None, help="metrics.json của trainer để đặt RF cạnh luật")
    ap.add_argument("--out", default=None); ap.add_argument("--proposals", default=os.path.join(ROOT, "proposals"))
    ap.add_argument("--fp-target", type=float, default=FP_TARGET)
    ap.add_argument("--select-splits", default=None, help="các split dùng để CHỌN (mặc định train,val; với --label-source ai: val)")
    ap.add_argument("--dry-run", action="store_true", help="không ghi proposals/")
    ap.add_argument("--purpose", choices=("official", "demo"), default="official",
                    help="demo = bước 2c: đề xuất từ dữ liệu mới CHỈ minh họa quy trình (pid 'DEMO-...', apply_rule không áp)")
    ap.add_argument("--exact-time", action="store_true", help="tái lập v2: giờ Apache chính xác, không tính làm tròn giây của Wazuh")
    ap.add_argument("--label-source", choices=("truth", "ai"), default="truth",
                    help="nhãn phiên dùng để CHỌN: truth = ý định kịch bản (v1-v3); ai = kết luận RF fp5 theo phiên (v4-AI)")
    ap.add_argument("--model", default=os.path.join(ROOT, "models", "full1", "model.joblib"), help="model cho --label-source ai")
    ap.add_argument("--op", default="fp5", help="điểm vận hành của model cho --label-source ai")
    ap.add_argument("--select-extra", nargs="*", default=[],
                    help="dataset bổ sung vào tập CHỌN (mọi split trừ stress), vd. data/dataset_dev1.csv")
    a = ap.parse_args(argv)
    t0 = time.time()
    AI = a.label_source == "ai"
    if a.select_splits is None:
        a.select_splits = "val" if AI else "train,val"                 # ai: train của dataset huấn luyện -> RF đã học, không dùng
    stem = os.path.splitext(os.path.basename(a.data))[0].replace("dataset_", "")
    out = a.out or os.path.join(ROOT, "output", f"rules_{stem}" + ("_ai" if AI else ""))
    os.makedirs(out, exist_ok=True)
    cols = ["session_key", "scenario", "label", "split", "event_epoch", "status", "srcip", "method", "url"]
    df = pd.read_csv(a.data, usecols=cols, low_memory=False, float_precision="round_trip")
    XT = a.exact_time
    parts = OrderedDict((sp, Sessions(df[df.split == sp], sp, XT)) for sp in ("val", "train", "test", "stress") if (df.split == sp).any())
    for p in a.eval:
        e = pd.read_csv(p, usecols=cols, low_memory=False, float_precision="round_trip")
        nm = os.path.splitext(os.path.basename(p))[0].replace("dataset_", "")
        for sp in e.split.unique():
            parts[f"{nm}:{sp}"] = Sessions(e[e.split == sp], f"{nm}:{sp}", XT)
    sel_splits = [sp for sp in a.select_splits.split(",") if sp in parts]
    sel_df = df[df.split.isin(sel_splits)]
    sel_src = [(a.data, sel_df)]
    for p in a.select_extra:
        e = pd.read_csv(p, usecols=cols, low_memory=False, float_precision="round_trip")
        e = e[e.split != "stress"]
        if set(e.session_key) & set(sel_df.session_key):
            raise SystemExit(f"{p}: trùng session_key với tập chọn")
        sel_src.append((p, e)); sel_df = pd.concat([sel_df, e], ignore_index=True)
    sel_name = "+".join(sel_splits) + "".join(f"+{os.path.splitext(os.path.basename(p))[0].replace('dataset_', '')}" for p in a.select_extra)
    ai_info = None
    if AI:
        import joblib
        mtrain = (joblib.load(a.model).get("dataset") or {}).get("sha256")
        if "train" in sel_splits and mtrain == sha256_file(a.data):
            raise SystemExit("--label-source ai: tập chọn chứa split train của chính dataset đã huấn luyện model (RF đã học) — không hợp lệ")
        verdict, ai_info = ai_session_verdicts([(p, set(d.session_key)) for p, d in sel_src], a.model, a.op)
        truth_df = sel_df
        sel_df = sel_df.assign(label=sel_df.session_key.map(verdict).astype(int))
        T_ = Sessions(truth_df, sel_name + " (nhãn thật)", XT)
        A_ = np.array([verdict[k] for k in T_.keys])
        ai_info["agreement"] = {"sessions": len(T_.keys),
                                "ai_attack_truth_attack": int(((A_ == 1) & (T_.label == 1)).sum()),
                                "ai_attack_truth_benign": int(((A_ == 1) & (T_.label == 0)).sum()),
                                "ai_benign_truth_attack": int(((A_ == 0) & (T_.label == 1)).sum()),
                                "ai_benign_truth_benign": int(((A_ == 0) & (T_.label == 0)).sum())}
        ai_info["disagree_sessions"] = [{"session": k, "scenario": s, "truth": int(t), "ai": int(x)}
                                        for k, s, t, x in zip(T_.keys, T_.scenario, T_.label, A_) if t != x]
        print(f"nhãn AI ({a.op}, ngưỡng {ai_info['threshold']}) trên tập chọn {sel_name}: {ai_info['agreement']}")
    V = parts["SELECT"] = Sessions(sel_df, sel_name + (" (nhãn AI)" if AI else ""), XT)
    parts.move_to_end("SELECT", last=False)
    if AI:
        parts["SELECT_TRUTH"] = T_
        parts.move_to_end("SELECT_TRUTH", last=False); parts.move_to_end("SELECT", last=False)
    allowed = int(math.floor(a.fp_target * V.n_ben + 1e-9))
    what = ("phiên AI cho là nghi ngờ", "phiên AI cho là sạch") if AI else ("phiên tấn công", "phiên benign")
    print(f"tập chọn {V.name}: {V.n_att} {what[0]}, {V.n_ben} {what[1]} -> cho phép tối đa {allowed} phiên báo nhầm "
          f"({100 * allowed / V.n_ben:.2f}%; {allowed + 1} phiên = {100 * (allowed + 1) / V.n_ben:.2f}%)")

    info, cands = OrderedDict(), OrderedDict()
    for fam in FAMILIES:
        prm, inf = choose_family(V, fam, allowed)                     # một mình họ này: để báo cáo / lý do loại
        info[fam] = {"alone": prm, **inf}
        cands[fam] = candidates(V, fam, allowed)
        info[fam]["candidate_points"] = len(cands[fam])
        print(f"  {fam:9s}: " + (f"một mình tốt nhất N={prm['N']} T={prm['T']}s bắt {inf['detected']}/{V.n_att}, báo nhầm "
                                  f"{inf['false_alarm']}/{V.n_ben}; {len(cands[fam])} điểm không bị trội"
                                  if prm else f"KHÔNG có điểm khả thi — {inf['reason']} (alert rule cha: {inf['val_member_alerts']})"))
    pick, stats = joint_search(V, cands, allowed)
    chosen = OrderedDict((f, {"N": pick[f]["N"], "T": pick[f]["T"]}) for f in FAMILIES if f in pick)
    sel = list(chosen)
    steps = stats
    for f in FAMILIES:
        if f not in chosen:
            info[f]["not_in_set"] = ("không có điểm khả thi" if not cands[f] else
                                     "tổ hợp tối ưu không dùng họ này (thêm vào không tăng số phiên bắt được trong hạn mức báo nhầm)")
    print(f"bộ luật (dò chung, {stats['combinations_evaluated']} tổ hợp): " +
          ", ".join(f"{f} N={p['N']} T={p['T']}s" for f, p in chosen.items()) + f"  {stats['best_key']}")

    # đánh giá mọi tập: từng luật + cả bộ
    res = OrderedDict()
    for pn, S in parts.items():
        r = {"rules": {}, "union": None, "by_scenario": {}}
        u = np.zeros(len(S.keys), bool)
        for f in chosen:
            nf, pos, ttd = S.simulate(f, chosen[f]["N"], chosen[f]["T"])
            r["rules"][f] = summarize(S, nf > 0, nf, ttd, pos)
            r["by_scenario"][f] = by_scenario(S, nf > 0)
            u |= nf > 0
        if chosen:                                                    # đóng góp riêng của từng luật trong bộ
            for f in chosen:
                rest = np.zeros(len(S.keys), bool)
                for g in chosen:
                    if g != f: rest |= S.simulate(g, chosen[g]["N"], chosen[g]["T"])[0] > 0
                own = (S.simulate(f, chosen[f]["N"], chosen[f]["T"])[0] > 0) & ~rest
                r["rules"][f]["unique_detected"] = int(own[S.label == 1].sum())
        r["union"] = summarize(S, u); r["by_scenario"]["union"] = by_scenario(S, u)
        ju, jper = joint_check(S, chosen)                             # mô phỏng chung (tương tác giữa các luật)
        r["joint"] = {"union": summarize(S, ju), "differs_from_independent": int((ju != u).sum()), "rules": {}}
        for f in chosen:
            rest = np.zeros(len(S.keys), bool)
            for g in chosen:
                if g != f: rest |= jper[g]
            r["joint"]["rules"][f] = {"detected": int(jper[f][S.label == 1].sum()), "false_alarm": int(jper[f][S.label == 0].sum()),
                                      "unique_detected": int((jper[f] & ~rest)[S.label == 1].sum())}
        res[pn] = r

    rf = {}
    if a.metrics and os.path.exists(a.metrics):
        M = json.load(open(a.metrics, encoding="utf-8"))
        for pn, key in (("test", "test"), ("val", "val"), ("stress", "stress")):
            if key in M.get("eval", {}) and "rf" in M["eval"][key]:
                rf[pn] = M["eval"][key]["rf"]["fp5"]
        for k, v in M.get("eval", {}).items():
            if ":" in k and "rf" in v:
                rf[k] = v["rf"]["fp5"]

    created = datetime.now(timezone.utc).isoformat(timespec="seconds")
    dsha = sha256_file(a.data)
    meta = {"created": created, "data": a.data, "data_sha256": dsha, "eval": a.eval, "fp_target": a.fp_target,
            "select_splits": sel_splits, "val_benign_sessions": V.n_ben, "allowed_false_alarm_sessions": allowed, "t_grid": T_GRID, "n_grid": N_GRID,
            "template": TEMPLATE, "time_model": "exact" if XT else "wazuh_sec_worst_case", "purpose": a.purpose, "wazuh_sim_sha256": sha256_file(os.path.join(HERE, "wazuh_sim.py"))[:16],
            "families": {f: {"rule_id": FAMILIES[f]["rule_id"], "cond": FAMILIES[f]["cond"]} for f in FAMILIES},
            "chosen": chosen, "selection_info": info, "set": sel, "greedy_steps": steps, "search": stats, "results": res, "rf_fp5": rf,
            "label_source": a.label_source, "ai_labels": ai_info, "select_name": V.name,
            "select_extra": [{"path": p, "sha256": sha256_file(p)} for p in a.select_extra]}

    # hồ sơ đề xuất
    written = []
    if not a.dry_run:
        os.makedirs(a.proposals, exist_ok=True)
        existing = {}
        for fn in os.listdir(a.proposals):
            if fn.endswith(".json"):
                try:
                    c = json.load(open(os.path.join(a.proposals, fn), encoding="utf-8"))
                    existing[c.get("fingerprint")] = (fn[:-5], c.get("status"))
                except Exception:
                    pass
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        for f in sel:
            N, T = chosen[f]["N"], chosen[f]["T"]
            xml = rule_xml(f, N, T, a.label_source)
            fpkey = [TEMPLATE, f, FAMILIES[f]["cond"], N, T] + (["label_source=ai", ai_info["model_sha256"], a.op] if AI else [])
            fp = hashlib.sha256(json.dumps(fpkey).encode()).hexdigest()[:16]
            if fp in existing:
                print(f"  {f}: đã có đề xuất cùng fingerprint ({existing[fp][0]}, {existing[fp][1]}) — không tạo trùng")
                continue
            pid = ("DEMO-" if a.purpose == "demo" else "") + ("AI-" if AI else "") + f"R{FAMILIES[f]['rule_id']}-{f}-N{N}-T{T}-{stamp}"
            vrow, urow = res["SELECT"]["rules"][f], res["SELECT"]["union"]
            jrow = res["SELECT"]["joint"]
            passed = (urow["false_alarm"] <= allowed and vrow["detected"] >= 1 and vrow.get("unique_detected", 0) >= 1
                      and jrow["union"]["false_alarm"] <= allowed and jrow["rules"][f]["unique_detected"] >= 1)
            case = {"format": "siem10-proposal-v1", "proposal_id": pid, "status": "proposed", "created_at": created,
                    "generated_by": "rule_proposer.py", "kind": "frequency_rule", "family": f, "template": TEMPLATE,
                    "purpose": a.purpose,
                    **({"purpose_note": "bước 2c: chỉ minh họa quy trình đề xuất từ dữ liệu mới; bộ luật CHÍNH THỨC là bộ đang áp "
                                        "(xem apply_rule.py list). Không áp (apply_rule chặn purpose=demo)."} if a.purpose == "demo" else {}),
                    "label_source": a.label_source,
                    **({"ai_labels": {k: v for k, v in ai_info.items() if k != "disagree_sessions"}} if AI else {}),
                    "params": {"frequency": N, "timeframe": T, "parent": FAMILIES[f]["cond"], "same_srcip": True},
                    "fingerprint": fp, "xml_sha256": hashlib.sha256(xml.encode()).hexdigest(),
                    "data": {"path": a.data, "sha256": dsha, "eval": a.eval, "select_extra": meta["select_extra"]},
                    "selection": {"split": V.name, "label_source": a.label_source,
                                  "criterion": (f"dò chung: tối đa số phiên AI cho là nghi ngờ bị luật bắt, cả bộ chạm <= {allowed}/{V.n_ben} phiên AI cho là sạch ({V.name}); nhãn thật KHÔNG dùng để chọn"
                                                if AI else f"dò chung: tối đa số phiên tấn công bắt được, cả bộ báo nhầm <= {allowed}/{V.n_ben} phiên benign ({V.name})"),
                                  "search": stats, "set": sel, "info": {k: v for k, v in info[f].items()}},
                    "regression": {"passed": bool(passed),
                                   "summary": (f"{V.name}: bắt {vrow['detected']}/{vrow['attack_sessions']} (riêng {vrow.get('unique_detected')}), "
                                               f"báo nhầm {vrow['false_alarm']}/{vrow['benign_sessions']} (cả bộ {urow['false_alarm']}/{urow['benign_sessions']}; ngưỡng {allowed})"),
                                   "criteria": f"{V.name}: cả bộ <= ngưỡng báo nhầm, luật bắt >= 1 phiên mà các luật khác không bắt — cả khi mô phỏng độc lập lẫn mô phỏng chung; báo nhầm tính với cửa sổ T+1 s (làm tròn giây xấu nhất); các tập khác chỉ tham khảo"
                                               + ("; nhãn = kết luận AI theo phiên (nhãn thật chỉ báo cáo ở SELECT_TRUTH)" if AI else ""),
                                   "joint_select": {"union": jrow["union"], "rule": jrow["rules"][f]},
                                   "time_model": "exact" if XT else "wazuh_sec_worst_case",
                                   "decision_split": V.name,
                                   "splits": {pn: {"rule": r["rules"][f], "union": r["union"]} for pn, r in res.items()},
                                   "by_scenario_select": res["SELECT"]["by_scenario"][f]},
                    "evidence": [{"session": V.keys[k], "scenario": V.scenario[k], "fires": int(n)}
                                 for k, n in enumerate(V.simulate(f, N, T)[0]) if n > 0][:10],
                    "verify": verify_lines(V, f, N, T),
                    "limitations": ["giờ Apache thay giờ Manager (trễ trung vị 0,48 s đo ở 2b); làm tròn giây tính theo trường hợp xấu nhất",
                                    "nhiều luồng so luật song song của Wazuh có thể làm lần khớp lệch ±1-2 sự kiện (2b: khớp mức phiên 100%)"],
                    "history": []}
            open(os.path.join(a.proposals, pid + ".xml"), "w", encoding="utf-8").write(xml)
            json.dump(case, open(os.path.join(a.proposals, pid + ".json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
            written.append(pid)
    meta["proposals_written"] = written
    json.dump(meta, open(os.path.join(out, "rules.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1, default=str)
    write_report(os.path.join(out, "report.md"), meta, parts)
    print(f"xong ({time.time() - t0:.0f}s) -> {out}/report.md; đề xuất: {written or '(không ghi)'}")
    return meta


def write_report(path, M, parts):
    L = [f"# Đề xuất luật tần suất — {os.path.basename(M['data'])}", ""]
    if M.get("purpose") == "demo":
        L += ["> **MINH HỌA (bước 2c).** Đề xuất từ dữ liệu mới chỉ để minh họa quy trình đề xuất -> người duyệt. Bộ luật "
              "CHÍNH THỨC là v3 (chọn trên train+val của full1, xem output/rules_full1/report.md). Các đề xuất này mang tiền tố "
              "DEMO- và apply_rule.py không áp chúng.", ""]
    if M.get("label_source") == "ai":
        A = M["ai_labels"]; g = A["agreement"]
        L += [f"> **NHÃN TỪ AI (v4-AI).** Nhãn phiên dùng để CHỌN là kết luận của RF: phiên nghi ngờ nếu ≥ 1 alert có điểm ≥ "
              f"{A['threshold']} ({A['op']}, model sha256 `{A['model_sha256'][:16]}…`). Nhãn thật KHÔNG dùng để chọn; chỉ để báo cáo "
              f"(dòng *tập chọn — nhãn thật*) và đánh giá các tập khác. Tập chọn: {M['select_name']} (chỉ phiên RF chưa học).", "",
              f"Đồng thuận AI / nhãn thật trên tập chọn ({g['sessions']} phiên): AI nghi ngờ & tấn công {g['ai_attack_truth_attack']}, "
              f"AI nghi ngờ & benign {g['ai_attack_truth_benign']}, AI sạch & tấn công {g['ai_benign_truth_attack']}, "
              f"AI sạch & benign {g['ai_benign_truth_benign']}. Phiên bất đồng: "
              + (", ".join(f"{d['scenario']} (thật {d['truth']}, AI {d['ai']})" for d in A.get("disagree_sessions", [])[:30]) or "không có"), ""]
    L += [
         f"Sinh lúc {M['created']}. Chọn CHỈ trên {M.get('select_name') or '+'.join(M['select_splits'])} (dò chung cả bộ): tối đa số phiên "
         f"{'AI cho là nghi ngờ' if M.get('label_source') == 'ai' else 'tấn công'} bắt được với cả bộ báo nhầm ≤ "
         f"{M['allowed_false_alarm_sessions']}/{M['val_benign_sessions']} phiên benign "
         f"(= floor({M['fp_target']:.0%} × {M['val_benign_sessions']}); thêm 1 phiên nữa đã là "
         f"{100 * (M['allowed_false_alarm_sessions'] + 1) / M['val_benign_sessions']:.2f}%). "
         "Các tập khác chỉ để tham khảo, không dùng để quyết. Mô phỏng: wazuh_sim.py (ngữ nghĩa đo trên Wazuh 4.14.7).", "",
         "## Theo họ (tập chọn)", "", "| họ | rule | điều kiện cha | N | T (s) | bắt | báo nhầm | ghi chú |", "|---|---|---|---|---|---|---|---|"]
    for f, inf in M["selection_info"].items():
        F = M["families"][f]; p = M["chosen"].get(f)
        if p:
            s0 = M["results"]["SELECT"]["rules"][f]
            L.append(f"| {f} | {F['rule_id']} | `{F['cond']}` | {p['N']} | {p['T']} | {s0['detected']} (riêng {s0.get('unique_detected')}) | {s0['false_alarm']} | TRONG BỘ |")
        elif inf.get("alone"):
            al = inf["alone"]
            L.append(f"| {f} | {F['rule_id']} | `{F['cond']}` | ({al['N']}) | ({al['T']}) | ({inf['detected']}) | ({inf['false_alarm']}) | "
                     f"không vào bộ: {inf.get('not_in_set')} — số trong ngoặc: tốt nhất nếu đứng một mình |")
        else:
            b = inf.get("best_unconstrained") or {}
            L.append(f"| {f} | {F['rule_id']} | `{F['cond']}` | — | — | — | — | KHÔNG đề xuất: {inf['reason']}; số alert rule cha trên tập chọn: "
                     f"{inf['val_member_alerts']}; nếu bỏ ràng buộc báo nhầm, điểm bắt nhiều nhất: N={b.get('N')}, T={b.get('T')} -> bắt "
                     f"{b.get('detected')} phiên tấn công, báo nhầm {b.get('false_alarm')} phiên benign |")
    L += ["", f"Dò chung: {M['search']}", "", "## Kết quả theo tập (phiên: bắt / báo nhầm, k = 1)", "",
          "Test đã được NHÌN trước khi đổi sang thiết kế v2 (xem mục Lịch sử) — số trên test là tham khảo, số cuối lấy từ lockbox.", "",
          "| tập | luật | bắt (tấn công) | báo nhầm (benign) | khớp đầu: trung vị giây | trung vị số alert đến khớp đầu | số lần khớp / phiên bắt được |",
          "|---|---|---|---|---|---|---|"]
    lab = lambda pn: ((M.get("select_name") or "+".join(M["select_splits"])) + " (CHỌN)" if pn == "SELECT" else
                      "tập chọn — nhãn thật (chỉ báo cáo)" if pn == "SELECT_TRUTH" else pn)
    for pn, r in M["results"].items():
        for f, s in list(r["rules"].items()) + [("CẢ BỘ " + "+".join(M["set"]), r["union"])]:
            if not f.startswith("CẢ BỘ") and f not in M["set"]:
                continue
            a_, b_ = fmt_rate(s)
            g = lambda k: ("—" if s.get(k) is None else f"{s[k]:.1f}")
            L.append(f"| {lab(pn)} | {f} | {a_} | {b_} | {g('ttd_median_s')} | {g('alerts_to_first_median')} | {g('fires_per_detected_session_median')} |")
        rf = M["rf_fp5"].get(pn)
        if rf:
            pc = lambda v: "—" if v is None else f"{100 * v:.1f}%"
            L.append(f"| {pn} | *RF fp5 (trainer)* | {pc(rf.get('det_k1'))} | {pc(rf.get('fp_k1'))} | | | |")
    L += ["", "## Theo kịch bản — cả bộ (số phiên bị luật bắt / số phiên)", ""]
    pns = list(M["results"])
    scen = {}
    for pn in pns:
        for row in M["results"][pn]["by_scenario"]["union"]:
            scen.setdefault((row["label"], row["scenario"]), {})[pn] = f"{row['fired']}/{row['sessions']}"
    L += ["| nhãn | kịch bản | " + " | ".join(lab(pn) for pn in pns) + " |", "|---|---|" + "---|" * len(pns)]
    for (lab, sc), v in sorted(scen.items(), key=lambda x: (x[0][0], str(x[0][1]))):
        L.append(f"| {lab} | {sc} | " + " | ".join(v.get(pn, "") for pn in pns) + " |")
    L += ["", "## Lịch sử", "",
          "- v1 (22/10 22:59, đã bỏ): chọn CHỈ trên val (48 phiên benign, cho phép 2) + chọn từng họ rồi ghép tham lam -> "
          "web_scan N=10 T=10 + r401 N=12 T=60 + r3xx N=2 T=10; val 34/42 bắt, 2/48 báo nhầm; test 56/70 bắt, 10/80 (12,5%) "
          "báo nhầm (broken_links 7/10); train 16/144 (11,1%); flood không bị bắt. Sửa vì val quá ít phiên benign và ghép tham "
          "lam để một họ chiếm hết hạn mức. Test đã được nhìn trước khi sửa.", "",
          "## Giới hạn", "",
          "- Mỗi luật được mô phỏng độc lập; Wazuh chỉ sinh một alert cho mỗi sự kiện và có thể có tương tác giữa các luật cùng "
          "rule cha — kiểm ở bước 2b bằng phát lại trên Manager thật.",
          "- Thời gian dùng giờ Apache (Wazuh dùng giờ Manager, độ phân giải giây; trễ thường < 1 s).",
          "- `if_matched_group` (web_scan, siemlab_observed) chưa được đo bằng probe như `if_matched_sid` — kiểm ở 2b "
          "(apply_rule chạy logtest với verify.lines của hồ sơ).",
          "- Mã 4xx khác (400/405/…) không có trong train/val; chỉ xuất hiện ở công cụ thật (nikto, nmap).",
          "- Ngưỡng 5% tính bằng số phiên tuyệt đối trên tập chọn; kết quả trên tập khác có thể vượt 5%.", ""]
    open(path, "w", encoding="utf-8").write("\n".join(L))


if __name__ == "__main__":
    main()
