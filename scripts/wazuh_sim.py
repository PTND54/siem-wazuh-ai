"""wazuh_sim.py — mô phỏng offline luật tần suất của Wazuh (frequency + timeframe + if_matched_sid/group + same_srcip
[+ different_url]) THEO NGỮ NGHĨA ĐÃ ĐO trên Manager 4.14.7 bằng scripts/wazuh_probe.py (22/10/2026, N=3, T=8 s):

  * Luật khớp ở sự kiện cha thứ N trong cửa sổ T giây (cùng srcip) — tính cả sự kiện hiện tại.
  * Khi khớp, N sự kiện đã được đếm (gồm sự kiện hiện tại) bị "tiêu thụ": không được đếm cho lần khớp sau. Vì vậy luật
    khớp ở sự kiện N, 2N, 3N, ... của một chuỗi liên tục — KHÔNG khớp ở mọi sự kiện sau sự kiện thứ N.
    (probe fire_index: khớp ở 3, 6; v9: scan ~160 sự kiện, N=5 -> 30 lần khớp.)
  * same_srcip: đếm riêng từng IP (probe same_srcip). Sự kiện quá T giây không còn được đếm (probe timeframe).
  * different_url: chỉ bỏ các sự kiện trước có URL TRÙNG URL sự kiện hiện tại; KHÔNG đòi các URL khác nhau đôi một
    (probe different_url_cycle: 2 URL xoay vòng, N=3 vẫn khớp ở 4, 7, 10; cùng 1 URL thì không bao giờ khớp).
  * Sự kiện đã thành alert luật con vẫn là sự kiện của luật cha (đã bị tiêu thụ) — xem trên.

Mô hình này giải thích ĐÚNG cả 5 ca thăm dò (tests/test_wazuh_sim.py). Xấp xỉ còn lại so với Wazuh thật:
  * Thời gian: Wazuh dùng giờ Manager nhận sự kiện (độ phân giải giây); offline dùng giờ Apache (trễ thường < 1 s).
  * Nhiều luật cùng nạp: freq_fires mô phỏng từng luật ĐỘC LẬP (đúng khi chỉ có một luật trên các sự kiện đó). Khi
    nhiều luật cùng nạp, dùng joint_fires (cuối file) — đọc từ mã nguồn Wazuh 4.14, kiểm trên probe 26/10 và dev_rules1.
  * N=2 là ngoại lệ: khớp ở MỌI sự kiện cha từ thứ 2 (không sự kiện trước nào bị đánh dấu) — theo mã nguồn, đã đo
    thật 26/10 (probe --n 2: 2, 3, 4, 5, 6). freq_fires và joint_fires đều theo đúng điều này (trước 26/10 freq_fires
    sai: 2, 4, 6).
"""
from collections import deque


def freq_fires(t, N, T, member=None, urls=None, different_url=False):
    """t: thời điểm (đã sắp tăng dần) của MỘT chuỗi cùng srcip (hoặc nhiều chuỗi cách nhau > T, vd. phiên nối tiếp
    với khoảng đệm lớn); member[i]: sự kiện i có khớp rule cha không (None = tất cả). Trả list bool: luật khớp tại i."""
    n = len(t)
    out = [False] * n
    if N is None or N == float("inf") or N < 1:
        return out
    if not different_url and N == 2:
        # mã nguồn (eventinfo.c): frequency nội bộ 0 -> khớp ngay ở sự kiện trước đầu tiên còn trong T, KHÔNG đánh dấu
        # sự kiện trước nào; sự kiện đã khớp thành alert luật con nên không vào danh sách cha. => khớp ở MỌI sự kiện cha
        # mà sự kiện cha "chưa khớp" gần nhất còn trong T. Đo thật 26/10 (probe --n 2): 404 x6 -> khớp ở 2, 3, 4, 5, 6.
        last = None
        for i in range(n):
            if member is not None and not member[i]:
                continue
            if last is not None and t[i] - last <= T:
                out[i] = True
            else:
                last = t[i]
        return out
    if not different_url:
        d = deque()                                   # thời điểm các sự kiện cha chưa bị tiêu thụ
        for i in range(n):
            if member is not None and not member[i]:
                continue
            ti = t[i]
            while d and d[0] < ti - T:
                d.popleft()
            if len(d) >= N - 1:
                out[i] = True
                d.clear()                             # N sự kiện đã đếm bị tiêu thụ (len(d) luôn <= N-1)
            else:
                d.append(ti)
        return out
    pend = []                                         # [t, url] chưa bị tiêu thụ, theo thời gian
    for i in range(n):
        if member is not None and not member[i]:
            continue
        ti, ui = t[i], urls[i]
        pend = [p for p in pend if p[0] >= ti - T]
        cand = [k for k in range(len(pend) - 1, -1, -1) if pend[k][1] != ui][:N - 1]   # mới nhất trước
        if len(cand) >= N - 1:
            out[i] = True
            drop = set(cand)
            pend = [p for k, p in enumerate(pend) if k not in drop]
        else:
            pend.append([ti, ui])
    return out


# ============================================================ mô phỏng CHUNG nhiều luật (theo mã nguồn Wazuh 4.14)
"""Bổ sung 26/10/2026 sau bước 2b (run2b: luật 'any' thật khớp 6 lần, mô phỏng độc lập 12; probe tương tác: luật nhóm
không khớp gì trên chuỗi 404). Đọc mã nguồn wazuh/wazuh v4.14.0 (src/analysisd/analysisd.c, eventinfo.c, rules.c,
rules_list.c) cho ra 4 cơ chế mà mô phỏng từng luật độc lập bỏ sót:

  (1) Danh sách đếm gắn với rule CUỐI CÙNG của sự kiện (rule sinh alert). Sự kiện được thêm vào danh sách
      if_matched_sid của rule đó; NẾU rule đó không có danh sách sid ("else if") mới được thêm vào các danh sách
      if_matched_group. => khi đã có luật if_matched_sid 100011 (r401), sự kiện 401 KHÔNG còn được luật nhóm
      siemlab_observed (any) đếm. Sự kiện đã thành alert luật con (110xxx) không vào danh sách của rule cha.
  (2) Rule có danh sách nhóm X nếu chuỗi group của nó CHỨA X (OSMatch, so khớp chuỗi con) — cả rule 110xxx.
  (3) Đếm: duyệt ngược từ sự kiện mới nhất, dừng khi gặp sự kiện quá T giây (giờ Manager, giây) HOẶC sự kiện đã có
      matched >= level của luật. Khớp khi đếm được N-1 sự kiện trước (frequency nội bộ = N-2). Khi khớp: đánh dấu
      matched = level cho sự kiện hiện tại và sự kiện trước GẦN NHẤT -> các lần đếm sau dừng ở đó (= "tiêu thụ").
      Dấu này nằm trên SỰ KIỆN nên chặn cả luật khác dùng chung sự kiện (web_scan khớp -> chặn luật any).
      N=2: không có "sự kiện trước gần nhất" nào được đánh dấu -> khớp lại ở mỗi sự kiện cha sau đó (đo thật 26/10).
  (4) Luật con được thử theo thứ tự nạp; luật đầu tiên khớp thắng, các luật sau không được thử cho sự kiện đó.
Không mô phỏng: nhiều luồng so luật song song (analysisd.rule_matching_threads = số CPU) — nguồn lệch ±1-2 sự kiện ở
tốc độ cao; bộ nhớ sự kiện chung (memory_size, mặc định 8192) — chỉ ảnh hưởng khi tổng tốc độ rất cao.
"""

# rule nền SIEMLAB (wazuh/local_rules.xml): (sid, level, chuỗi group như Wazuh ghép, điều kiện mã)
BASE_RULES = (
    (100010, 3, "siemlab,siemlab_observed,", lambda s: s == 200),
    (100011, 5, "siemlab,siemlab_observed,authentication_failed,", lambda s: s == 401),
    (100012, 4, "siemlab,siemlab_observed,web_scan,", lambda s: s == 404),
    (100013, 4, "siemlab,siemlab_observed,web_scan,", lambda s: s == 403),
    (100014, 3, "siemlab,siemlab_observed,", lambda s: 300 <= s < 400),
    (100015, 5, "siemlab,siemlab_observed,", lambda s: s >= 500),
)
BASE_OTHER = (100016, 4, "siemlab,siemlab_observed,")


def base_rule(s):
    for sid, lv, grp, f in BASE_RULES:
        if f(s):
            return sid
    return BASE_OTHER[0]


def _base_groups():
    g = {sid: grp for sid, lv, grp, f in BASE_RULES}
    g[BASE_OTHER[0]] = BASE_OTHER[2]
    return g


def joint_fires(t, status, rules, ips=None):
    """Mô phỏng CHUNG các luật tần suất đang nạp, theo đúng thứ tự xử lý sự kiện.
    t: giờ Manager (giây, nên làm tròn xuống) tăng dần; status: mã HTTP; ips: srcip từng sự kiện (None = một IP).
    rules: list (THỨ TỰ NẠP) dict: id, level, N, T, và sid (if_matched_sid) HOẶC group (if_matched_group);
           tùy chọn groups (chuỗi group của chính luật, mặc định ''), src (hàm ip -> bool, như <srcip>).
    Trả list: rule id cuối cùng (alert) của từng sự kiện — rule nền 1000xx hoặc id luật đã khớp."""
    n = len(t)
    bgroups = _base_groups()
    rgroups = {r["id"]: r.get("groups", "") for r in rules}
    sid_targets = {r["sid"] for r in rules if r.get("sid") is not None}
    grp_rules = [r for r in rules if r.get("group") is not None]

    def lists_of(rid):
        """Danh sách mà sự kiện có rule cuối cùng = rid được thêm vào (cơ chế 1, 2)."""
        if rid in sid_targets:
            return [("sid", rid)]
        g = bgroups.get(rid, rgroups.get(rid, ""))
        return [("grp", r["id"]) for r in grp_rules if r["group"] in g]

    children = {}
    for sid in bgroups:
        words = set(bgroups[sid].split(","))
        children[sid] = [r for r in rules if (r.get("sid") == sid) or (r.get("group") is not None and r["group"] in words)]
    L = {}
    matched = [0] * n
    final = [0] * n
    for k in range(n):
        b = base_rule(int(status[k]))
        win = None
        for r in children[b]:
            if ips is not None and r.get("src") is not None and not r["src"](ips[k]):
                continue
            lst = L.get(("sid", r["sid"]) if r.get("sid") is not None else ("grp", r["id"]), [])
            cnt, first, fire = 0, None, False
            for j in reversed(lst):
                if t[k] - t[j] > r["T"]:
                    break
                if ips is not None and ips[j] != ips[k]:
                    continue
                if matched[j] >= r["level"]:
                    break
                if cnt < r["N"] - 2:
                    cnt += 1
                    if first is None:
                        first = j
                    continue
                fire = True
                break
            if fire:
                matched[k] = r["level"]
                if first is not None:
                    matched[first] = r["level"]
                win = r
                break
        final[k] = win["id"] if win else b
        for key in lists_of(final[k]):
            L.setdefault(key, []).append(k)
    return final
