#!/usr/bin/env python3
"""scenarios.py — CHƯƠNG TRÌNH hành vi (không gửi gói tin). Mỗi kịch bản nhận ctx và trả
danh sách Req(t, method, url, cred) + nhãn. traffic.py mới là nơi gửi thật.

Nguyên tắc thiết kế (khác v9):
  * Tham số (tốc độ, độ dài, kiểu wordlist, tỉ lệ lỗi...) được RÚT NGẪU NHIÊN THEO PHIÊN từ
    dải rộng, và dải của benign CHỒNG LẤN dải của malicious (một crawler/heavy_burst nhanh
    như một scan chậm). Nhãn là Ý ĐỊNH của kịch bản, không phải thứ suy ra từ tốc độ.
  * Mỗi phiên dùng một IP riêng (run_batch cấp), nên "theo srcip" = "theo phiên".
  * Mã trạng thái KHÔNG được ghi sẵn ở đây — lấy từ Apache thật khi gửi. status_of() ở
    site_model chỉ dùng cho dry-run và cho kiểm tra.
"""
import hashlib, math, random, string
from collections import namedtuple

import site_model as S

Req = namedtuple("Req", "t method url cred")          # cred: None | "good" | "bad"
Scenario = namedtuple("Scenario", "name fn label family")

TOK_A = ("admin backup config db login test dev old new tmp upload uploads files data api wp user users panel manager "
         "console shell cmd phpinfo info status server git svn env aws key id_rsa dump sql bak zip tar index default "
         "setup install cache logs log private secret").split()
TOK_B = ("portal intranet staging stage preprod sandbox legacy archive release deploy build jenkins grafana kibana "
         "prometheus actuator swagger graphql debug trace metrics health monitoring phpmyadmin adminer pma webmail owa "
         "remote vpn citrix").split()

UA_BROWSER = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
              "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
              "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"]
UA_SCRIPT = ["python-requests/2.31.0", "curl/8.5.0", "Go-http-client/1.1", "okhttp/4.12.0"]
UA_BOT = ["Mozilla/5.0 (compatible; Googlebot/2.1)", "Mozilla/5.0 (compatible; bingbot/2.0)", "Wget/1.21.4"]
UA_MON = ["UptimeRobot/2.0", "Pingdom.com_bot", "kube-probe/1.29"]


def lu(r, a, b):                       # log-uniform
    return math.exp(r.uniform(math.log(a), math.log(b)))


def wordlist_path(r, style):
    """Đường dẫn kiểu wordlist. Kiểu A ~ danh sách ngắn kinh điển; kiểu B ~ danh sách khác (thư mục lồng, ngẫu nhiên)."""
    if style == "A":
        return "/" + r.choice(TOK_A) + r.choice(["", ".php", ".bak", ".sql", "/", ".txt", ".zip"])
    if r.random() < .6:
        return f"/{r.choice(TOK_B + TOK_A)}/{r.choice(TOK_B + TOK_A)}{r.choice(['', '.json', '.yml', '.php', '.old', '/index.php'])}"
    return "/" + "".join(r.choice(string.ascii_lowercase) for _ in range(r.randint(5, 14))) + f"-{r.randint(10, 99999)}"


class Ctx:
    def __init__(self, r, shift=False):
        self.r, self.shift = r, shift
        self.mult, self.wl = 1.0, "A"
        self.params = {}
        self.phase = ""                 # tiền tố tên tham số khi một kịch bản gồm nhiều pha (recon_then_brute)
        self.ua, self.keepalive = r.choice(UA_SCRIPT), r.random() < .6
        if shift:                       # phân phối lệch: tốc độ nhân 0.3-0.55 hoặc 1.8-3.0, wordlist khác
            self.mult = r.uniform(.3, .55) if r.random() < .5 else r.uniform(1.8, 3.0)
            self.wl = "B"
        self.params["shift_mult"] = round(self.mult, 3)

    def rate(self, a, b, cap=None):
        x = lu(self.r, a, b) * self.mult
        x = min(x, cap) if cap else x
        k = self.phase + "rate"
        if k in self.params:            # gọi nhiều lần (mỗi đợt một tốc độ) -> giữ cả danh sách, không ghi đè
            old = self.params[k]
            self.params[k] = (old if isinstance(old, list) else [old]) + [round(x, 3)]
        else:
            self.params[k] = round(x, 3)
        return x

    def log(self, **kw):
        self.params.update({self.phase + k: (round(v, 4) if isinstance(v, float) else v) for k, v in kw.items()})


def times(r, rate, dur, reg, cap=1800):
    """Thời điểm đến: reg=1 đều tăm tắp, reg=0 Poisson, giữa là trộn."""
    t, out = 0.0, []
    while len(out) < cap:
        t += (1.0 / rate) * (reg + (1 - reg) * r.expovariate(1))
        if t > dur: break
        out.append(t)
    return out


_SPECIAL = S.REDIR + S.FORB + ["/robots.txt", "/sitemap.xml"]
_KNOWN = S.OK_SET | S.REDIR_SET | S.FORB_SET


def probe(r, ctx, ph):
    """URL dò: xác suất ph là đường 'đặc biệt' (robots/redirect/forbidden), còn lại từ wordlist (loại URL hợp lệ).
    Wordlist vẫn có thể trúng thư mục thật (/api/ -> 403, /api -> 301) hay vùng /private/* (401): đó là hành vi thật
    của công cụ dò, status_of() mô hình hóa đúng các ca này (đã đối chiếu Apache)."""
    if r.random() < ph:
        return r.choice(_SPECIAL)
    while True:
        u = wordlist_path(r, ctx.wl)
        if u not in _KNOWN:
            return u


def G(t, u, cred=None, m="GET"):
    return Req(round(t, 4), m, u, cred)


# ================================================================= BENIGN
def browse_human(c):
    r, ev, t = c.r, [], 0.0
    c.ua = r.choice(UA_BROWSER); c.keepalive = True
    dur = r.uniform(60, 180); fav = r.sample(S.VALID, r.randint(5, 60)); think = 6 / c.mult
    c.log(dur=dur, think=think)
    if r.random() < .5: ev.append(G(0.0, "/favicon.ico"))
    while t < dur and len(ev) < 1500:
        ev.append(G(t, r.choice(fav)))
        for _ in range(r.randint(2, 8)): ev.append(G(t + r.uniform(.03, .4), r.choice(S.ASSETS)))
        t += math.exp(r.gauss(math.log(think), .6))
    return ev


def heavy_burst(c):
    """Người dùng/ứng dụng hợp lệ tải dồn dập (tải trang nặng, prefetch, script nội bộ)."""
    r = c.r; rate = c.rate(5, 60); dur = r.uniform(15, 60); reg = r.uniform(0, 1)
    pool = r.sample(S.VALID + S.ASSETS, r.randint(3, 60)); c.log(dur=dur, reg=reg, pool=len(pool))
    return [G(t, r.choice(pool)) for t in times(r, rate, dur, reg)]


def broken_links(c):
    """Đi theo link hỏng/đã dời -> nhiều 404 nhưng chỉ vài URL lặp lại."""
    r = c.r; rate = c.rate(.3, 4); dur = r.uniform(40, 150); pb = r.uniform(.3, .8)
    br = [f"/old/page-{i}.html" for i in range(r.randint(2, 8))]; pool = r.sample(S.VALID, r.randint(5, 40))
    c.log(dur=dur, p_broken=pb)
    return [G(t, r.choice(br) if r.random() < pb else r.choice(pool)) for t in times(r, rate, dur, r.uniform(0, 1))]


def _login(c, n_wrong, pace, tail, first_blank=True):
    r = c.r; ev, t = [], 0.0
    c.ua = r.choice(UA_BROWSER); c.keepalive = True
    if first_blank:                     # trình duyệt gửi lần đầu chưa có thông tin -> 401
        ev.append(G(t, S.PRIV)); t += r.uniform(.5, 3)
    for _ in range(n_wrong):
        ev.append(G(t, S.PRIV, "bad")); t += r.uniform(*pace) / c.mult
    ev.append(G(t, S.PRIV, "good"))
    for _ in range(tail):               # trình duyệt chỉ gửi lại Authorization trong vùng /private/
        t += r.uniform(1, 8) / c.mult
        u = r.choice([S.PRIV] + S.VALID[:20])
        ev.append(G(t, u, "good" if u == S.PRIV else None))
    c.log(n_wrong=n_wrong, tail=tail)
    return ev


def typo_login(c):
    return _login(c, c.r.randint(1, 4), (1.5, 6), c.r.randint(5, 30))


def forgot_pw(c):
    return _login(c, c.r.randint(4, 10), (.8, 4), c.r.randint(3, 20))


def crawler(c):
    """Bot hợp lệ: đọc robots.txt rồi duyệt nhiều trang, ít 404/redirect."""
    r = c.r; c.ua = r.choice(UA_BOT); c.keepalive = r.random() < .5
    ev = [G(0.0, "/robots.txt")]; t = 0.0
    pages = r.sample(S.VALID, r.randint(50, 300)); ps, pr = r.uniform(.03, .12), .02
    d_med = r.uniform(.3, 3) / c.mult; c.log(d_med=d_med, p_404=ps)
    for p in pages:
        t += math.exp(r.gauss(math.log(d_med), .4)); x = r.random()
        if x < ps: ev.append(G(t, f"/old/gone-{r.randint(1, 999)}.html"))
        elif x < ps + pr: ev.append(G(t, r.choice(S.REDIR)))
        else: ev.append(G(t, p))
        if len(ev) > 1500 or t > 240: break
    return ev


def monitor(c):
    """Health-check định kỳ rất đều (HEAD/GET)."""
    r = c.r; c.ua = r.choice(UA_MON); I = r.uniform(1, 10) / c.mult; dur = r.uniform(60, 180)
    pool = r.sample(["/index.html", "/api/v1/item0.json", "/about.html"], r.randint(1, 2)); m = r.choice(["GET", "HEAD"])
    c.log(interval=I, dur=dur)
    return [G(i * I * (1 + r.uniform(-.05, .05)), r.choice(pool), m=m) for i in range(int(min(dur / I, 1500)))]


def api_client(c):
    r = c.r; rate = c.rate(2, 10); dur = r.uniform(30, 100); p5 = r.uniform(0, .08)
    pool = r.sample(S.API, r.randint(3, 6)); c.log(dur=dur, p_5xx=p5)
    return [G(t, r.choice(pool) if r.random() > p5 else r.choice(S.FLAKY)) for t in times(r, rate, dur, r.uniform(.2, 1))]


# ================================================================= MALICIOUS
def scan_fast(c):
    r = c.r; rate = c.rate(4, 60); dur = r.uniform(15, 60); ph = r.uniform(.01, .08); c.log(dur=dur, ph=ph)
    return [G(t, probe(r, c, ph)) for t in times(r, rate, dur, r.uniform(0, 1))]


def scan_stealth(c):
    """Dò chậm, xen URL hợp lệ để trông giống người dùng."""
    r = c.r; rate = c.rate(.3, 4); dur = r.uniform(60, 180); q = r.uniform(.2, .7); ph = r.uniform(.01, .08)
    c.log(dur=dur, mix_valid=q)
    return [G(t, r.choice(S.VALID) if r.random() < q else probe(r, c, ph)) for t in times(r, rate, dur, r.uniform(0, 1))]


def scan_pulsed(c):
    """Dò theo đợt: vài chục request rồi nghỉ, né ngưỡng theo cửa sổ."""
    r = c.r; ev, t = [], 0.0; ph = r.uniform(.01, .08); nb = r.randint(3, 6)
    for _ in range(nb):
        g = 1 / c.rate(5, 20)
        for _ in range(r.randint(5, 20)):
            t += g * r.uniform(.5, 1.5); ev.append(G(t, probe(r, c, ph)))
        t += r.uniform(20, 90) / c.mult
    c.log(bursts=nb)
    return ev


def auth_fast(c):
    r = c.r; rate = c.rate(3, 40); dur = r.uniform(10, 50)
    ev = [G(t, S.PRIV, "bad") for t in times(r, rate, dur, r.uniform(0, 1))]
    hit = bool(ev) and r.random() < .2
    if hit: ev.append(G(ev[-1].t + 1 / rate, S.PRIV, "good"))      # đoán trúng ở cuối
    c.log(dur=dur, hit=hit)
    return ev


def auth_slow(c):
    """Brute-force chậm, xen request vô hại."""
    r = c.r; rate = c.rate(.1, 1.2); dur = r.uniform(80, 200); q = r.uniform(0, .5); c.log(dur=dur, mix_valid=q)
    return [G(t, r.choice(S.VALID)) if r.random() < q else G(t, S.PRIV, "bad") for t in times(r, rate, dur, r.uniform(0, 1))]


def flood(c):
    r = c.r; rate = c.rate(40, 100, cap=110); dur = r.uniform(8, 20); pool = r.sample(S.VALID, r.randint(1, 3))
    c.log(dur=dur, pool=len(pool))
    return [G(t, r.choice(pool)) for t in times(r, rate, dur, r.uniform(0, 1), cap=1800)]


def recon_then_brute(c):
    c.phase = "scan_"; a = scan_fast(c); t0 = a[-1].t + 1 if a else 0
    c.phase = "brute_"; b = auth_fast(c); c.phase = ""
    return a + [G(t0 + x.t, x.url, x.cred) for x in b]


# ================================================================= STRESS (chỉ đánh giá, không train)
def misconfig_monitor(c):
    """Monitor hợp lệ nhưng cấu hình sai: poll /private/ không có thông tin -> toàn 401 (giống brute-force)."""
    r = c.r; c.ua = r.choice(UA_MON); I = r.uniform(3, 15) / c.mult; dur = r.uniform(80, 200)
    c.log(interval=I, dur=dur)
    return [G(i * I * (1 + r.uniform(-.05, .05)), S.PRIV) for i in range(int(min(dur / I, 800)))]


def sso_retry_storm(c):
    """Ứng dụng nội bộ retry đăng nhập sai mật khẩu đã hết hạn theo backoff -> nhiều 401 giống brute-force chậm."""
    r = c.r; c.keepalive = True; ev, t = [], 0.0; gap = r.uniform(1, 4) / c.mult
    for _ in range(r.randint(15, 60)):
        if t > 300: break
        ev.append(G(t, S.PRIV, "bad")); t += gap; gap = min(gap * r.uniform(1.0, 1.15), 20)
    return ev


BENIGN = ["browse_human", "heavy_burst", "broken_links", "typo_login", "forgot_pw", "crawler", "monitor", "api_client"]
MALICIOUS = ["scan_fast", "scan_stealth", "scan_pulsed", "auth_fast", "auth_slow", "flood", "recon_then_brute"]
STRESS = ["misconfig_monitor", "sso_retry_storm"]
FAMILY = {**{n: "benign" for n in BENIGN}, "scan_fast": "recon", "scan_stealth": "recon", "scan_pulsed": "recon",
          "recon_then_brute": "recon", "auth_fast": "cred", "auth_slow": "cred", "flood": "flood",
          **{n: "benign" for n in STRESS}}
SCEN = {n: Scenario(n, globals()[n], 0 if FAMILY[n] == "benign" else 1, FAMILY[n]) for n in BENIGN + MALICIOUS + STRESS}


def build_session(name, seed, split, k, shift=False):
    """Sinh một phiên xác định theo (seed, name, split, k): cùng tham số -> cùng chuỗi request."""
    sc = SCEN[name]
    r = random.Random(f"{seed}|{name}|{split}|{k}")
    c = Ctx(r, shift)
    reqs = sorted(sc.fn(c), key=lambda q: q.t)
    base = reqs[0].t if reqs else 0.0
    reqs = [q._replace(t=round(q.t - base, 4)) for q in reqs]
    return {"run_id": f"{split}_{name}_{k:03d}", "scenario": name, "family": sc.family, "label": sc.label,
            "split": split, "shift": shift, "seed": str(seed), "params": c.params, "ua": c.ua, "keepalive": c.keepalive,
            "reqs": reqs, "duration": reqs[-1].t if reqs else 0.0, "peak_rps": peak_rps(reqs)}


def peak_rps(reqs):
    ts = [q.t for q in reqs]; best, j = 0, 0
    for i, t in enumerate(ts):
        while ts[j] <= t - 1.0: j += 1
        best = max(best, i - j + 1)
    return best


def session_digest(s):
    return hashlib.sha1(repr([(q.t, q.method, q.url, q.cred) for q in s["reqs"]]).encode()).hexdigest()[:12]
