#!/usr/bin/env python3
"""features.py — đặc trưng cửa sổ 60 s theo srcip, MỘT code path cho offline (train) và online (ai-service).

Khác v9:
  * Không còn rule_level (Gini cao nhưng permutation importance ~0: nó chỉ lặp lại mã trạng thái).
  * Thêm mã trạng thái theo lớp, mức tập trung URL, độ đều của nhịp, chuỗi 401, thành công sau thất bại.
  * WindowState duy trì O(1) mỗi sự kiện (v9 tính lại cả cửa sổ + json.loads mỗi alert).
  * enrich() offline = đẩy tuần tự từng sự kiện vào đúng WindowState mà online dùng.

Quy ước: cửa sổ = các sự kiện cùng srcip có t_j >= t_i - 60 (gồm cả i). Sự kiện phải đến theo thứ tự
thời gian không giảm (nơi gọi chịu trách nhiệm sắp xếp / reorder buffer).
Ngoài đặc trưng: srcip và thời gian tuyệt đối KHÔNG được dùng làm đặc trưng.
"""
import math
from collections import Counter, deque

WINDOW = 60.0
SHORT = 10.0

FEATURE_GROUPS = {
    "volume":  ["count_60s", "count_10s"],
    "variety": ["distinct_urls", "distinct_status", "max_url_share"],
    "timing":  ["mean_interval", "interval_cv"],
    "status":  ["r2xx", "r3xx", "r401", "r403", "r404", "r5xx"],
    "auth":    ["fail_streak", "succ_after_fail"],
    "url":     ["url_length", "url_entropy", "path_depth"],
}
FEATURE_COLUMNS = [c for g in FEATURE_GROUPS.values() for c in g]
NO_URL_COLUMNS = [c for c in FEATURE_COLUMNS if c not in FEATURE_GROUPS["url"]]


def _entropy(s):
    n = len(s)
    if n == 0:
        return 0.0
    return -sum(v / n * math.log2(v / n) for v in Counter(s).values())


class WindowState:
    """Trạng thái cửa sổ của MỘT srcip."""
    __slots__ = ("ev", "ev10", "url_cnt", "hist", "maxc", "st_cnt", "cls", "run", "trans_sum", "sum_d", "sum_d2", "last")

    def __init__(self):
        self.ev = deque()          # (t, url, status, trans_flag)
        self.ev10 = deque()        # t của các sự kiện trong 10 s gần nhất
        self.url_cnt, self.hist, self.maxc = {}, Counter(), 0
        self.st_cnt = Counter()
        self.cls = Counter()
        self.run = 0               # chuỗi 401 liên tiếp tính đến sự kiện hiện tại (toàn cục; đặc trưng cắt theo w)
        self.trans_sum = 0         # tổng cờ (401 -> 200) của mọi sự kiện trong cửa sổ
        self.sum_d = self.sum_d2 = 0.0   # tổng khoảng cách / bình phương giữa các sự kiện liền kề TRONG cửa sổ
        self.last = None

    @staticmethod
    def _cls(s):
        if 200 <= s < 300: return "r2xx"
        if 300 <= s < 400: return "r3xx"
        if s == 401: return "r401"
        if s == 403: return "r403"
        if s == 404: return "r404"
        if s >= 500: return "r5xx"
        return "other"

    def _evict(self, t):
        ev = self.ev
        while ev and ev[0][0] < t - WINDOW:
            t0, u, s, tr = ev.popleft()
            c = self.url_cnt[u]; self.hist[c] -= 1
            if c == self.maxc and self.hist[c] == 0: self.maxc = c - 1
            if c == 1: del self.url_cnt[u]
            else: self.url_cnt[u] = c - 1; self.hist[c - 1] += 1
            self.st_cnt[s] -= 1
            if self.st_cnt[s] == 0: del self.st_cnt[s]
            self.cls[self._cls(s)] -= 1
            self.trans_sum -= tr
            if ev:                                  # khoảng (t0 -> sự kiện kế) rời cửa sổ
                d = ev[0][0] - t0; self.sum_d -= d; self.sum_d2 -= d * d
        while self.ev10 and self.ev10[0] < t - SHORT:
            self.ev10.popleft()

    def push(self, t, url, status):
        """Thêm sự kiện (t không giảm) và trả dict đặc trưng cho sự kiện này."""
        if self.last is not None and t < self.last:
            raise ValueError(f"sự kiện đến ngược thời gian: {t} < {self.last}")
        prev_status = self.ev[-1][2] if self.ev else None
        self._evict(t)
        tr = 1 if (prev_status == 401 and status == 200 and self.ev) else 0
        # chuỗi 401 toàn cục (không phụ thuộc cửa sổ), sau đó cắt theo kích thước cửa sổ khi tính đặc trưng
        self.run = self.run + 1 if status == 401 else 0
        if self.ev:
            d = t - self.ev[-1][0]; self.sum_d += d; self.sum_d2 += d * d
        self.ev.append((t, url, status, tr)); self.ev10.append(t); self.last = t
        c = self.url_cnt.get(url, 0); self.url_cnt[url] = c + 1
        if c: self.hist[c] -= 1
        self.hist[c + 1] += 1
        if c + 1 > self.maxc: self.maxc = c + 1
        self.st_cnt[status] += 1; self.cls[self._cls(status)] += 1; self.trans_sum += tr
        return self._features(url)

    def _features(self, url):
        w = len(self.ev)
        if w <= 64:        # cửa sổ nhỏ: tính lại chính xác, tránh trôi số học của tổng chạy khi trừ dần
            ts = [e[0] for e in self.ev]
            ds = [b - a for a, b in zip(ts, ts[1:])]
            self.sum_d = sum(ds); self.sum_d2 = sum(x * x for x in ds)
        f = {"count_60s": w, "count_10s": len(self.ev10), "distinct_urls": len(self.url_cnt),
             "distinct_status": len(self.st_cnt), "max_url_share": self.maxc / w}
        if w >= 2:
            m = w - 1; mean = self.sum_d / m
            f["mean_interval"] = mean
            if w >= 3 and mean > 0:
                var = max(self.sum_d2 / m - mean * mean, 0.0)
                f["interval_cv"] = math.sqrt(var) / mean if var > 1e-12 else 0.0
            else:
                f["interval_cv"] = 0.0
        else:
            f["mean_interval"] = WINDOW; f["interval_cv"] = 0.0
        for k in ("r2xx", "r3xx", "r401", "r403", "r404", "r5xx"):
            f[k] = self.cls[k] / w
        f["fail_streak"] = min(self.run, w)
        f["succ_after_fail"] = self.trans_sum - self.ev[0][3]       # bỏ cờ của sự kiện đầu cửa sổ (cặp đứt)
        f["url_length"] = len(url); f["url_entropy"] = _entropy(url); f["path_depth"] = url.count("/")
        return f

    # ---- (de)serialize để lưu Redis: chỉ cần danh sách sự kiện trong cửa sổ ----
    def dump(self):
        return [(t, u, s) for t, u, s, _ in self.ev]

    @classmethod
    def load(cls, events):
        """Dựng lại trạng thái từ dump(). Đặc trưng của sự kiện kế tiếp giống hệt khi không mất trạng thái:
        fail_streak = min(chuỗi 401, w) tính lại được từ cửa sổ; cờ 401->200 của sự kiện đầu cửa sổ vốn bị loại."""
        st = cls()
        for t, u, s in events:
            st.push(t, u, s)
        return st


def enrich(events):
    """Offline: events = list dict có khóa srcip, event_epoch, url, status. Trả list dict (cùng thứ tự đầu vào)
    thêm các cột FEATURE_COLUMNS. Mỗi srcip được xử lý theo thứ tự thời gian (ổn định khi trùng thời điểm)."""
    out = [None] * len(events)
    order = sorted(range(len(events)), key=lambda i: (events[i]["srcip"], events[i]["event_epoch"], i))
    states = {}
    for i in order:
        e = events[i]
        st = states.get(e["srcip"])
        if st is None: st = states[e["srcip"]] = WindowState()
        f = st.push(float(e["event_epoch"]), e["url"], int(e["status"]))
        r = dict(e); r.update(f); out[i] = r
    return out
