#!/usr/bin/env python3
"""ai_service.py — mục 15 hướng dẫn v2 (HANDOFF_v10 mục 6.4): chấm điểm alert SIEMLAB theo thời gian gần thực.

  python3 scripts/ai_service.py --model models/full1/model.joblib --alerts /wazuh-logs/alerts/alerts.json \
          --redis redis://redis:6379/0 --sink opensearch [--op fp5] [--from-start | --from-end]
  python3 scripts/ai_service.py ... --sink file --out output/ai_enriched.jsonl --store memory --once --from-start   # chạy lại offline

Luồng:  alerts.json (tail, theo dõi xoay vòng) -> lọc SIEMLAB -> bỏ trùng (id; dòng log) -> REORDER BUFFER theo thời gian
Apache (usec trong full_log, không phải giờ Wazuh) -> đặc trưng bằng features.WindowState (ĐÚNG code path của
build_dataset/trainer) -> chấm điểm THEO LÔ (một lần predict_proba cho cả lô) -> tài liệu "enriched" -> OUTBOX (Redis)
-> bulk vào index ai-enriched-alerts-YYYY.MM.DD (_id = id alert, ghi lại không tạo bản trùng).

Nguyên tắc (lập trường đề tài): AI chỉ ENRICHMENT/chấm điểm. Không chặn IP, không sửa alert gốc, không học online.
  * Một dòng log SIEMLAB = MỘT sự kiện vào cửa sổ đặc trưng, bất kể rule nào sinh alert. Wazuh chỉ sinh một alert cho
    mỗi sự kiện (rule khớp sâu nhất): khi luật tương quan đã duyệt (110xxx) khớp, alert 110xxx THAY CHO alert gốc
    10001x và không mang nhóm siemlab_observed -> nhận theo decoder siemlab (audit_coverage.siemlab_match), đưa vào
    cửa sổ như alert gốc (ai.kind = "correlated" chỉ ghi loại rule). Nếu bỏ đi như v9 thì mất ~18% sự kiện sau khi
    luật có hiệu lực. Alert thứ hai cho CÙNG dòng log: alert gốc -> agent đọc lại, bỏ; alert rule khác -> vẫn index
    (ai.duplicate = true, mang điểm của sự kiện) nhưng KHÔNG vào cửa sổ (một request không được đếm hai lần).
  * Ngưỡng, danh sách đặc trưng, số chữ số làm tròn điểm lấy từ model.joblib do trainer.py sinh; từ chối model nếu
    danh sách đặc trưng khác features.NO_URL_COLUMNS hoặc features.py đã đổi so với lúc dựng dataset huấn luyện.

Bền vững qua khởi động lại (Redis, một transaction mỗi lô): trạng thái cửa sổ của các srcip vừa chạm (WindowState.dump),
checkpoint (inode + offset của dòng sớm nhất còn nằm trong buffer + id các alert đã xử lý nằm sau offset đó) và tài liệu
outbox được ghi CÙNG LÚC. Khởi động lại = đọc lại từ checkpoint, bỏ qua id đã xử lý -> không mất, không trùng.

Sự kiện đến trễ (thời gian Apache < sự kiện cuối đã xử lý của cùng srcip, vượt quá --reorder giây): không thể chèn vào
quá khứ của cửa sổ; được đẩy với thời gian = sự kiện cuối (giữ cửa sổ hợp lệ) và đánh dấu ai.late = true. Số đếm có ở log.
Giới hạn: khi khởi động lại mà alerts.json đã xoay vòng (inode khác checkpoint), phần cuối file cũ chưa đọc sẽ bị bỏ qua
(có cảnh báo); bỏ trùng theo dòng log chỉ nhớ trong RAM (agent đọc lại file ngay sau khởi động lại có thể lọt qua).
"""
import argparse, hashlib, json, math, os, signal, sys, time
from collections import OrderedDict, defaultdict
import heapq

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import numpy as np

import features as F
from audit_coverage import BASE_RULES, siemlab_match

VERSION = "ai-service-v10.1"
INDEX_PREFIX = "ai-enriched-alerts-"


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# ============================================================ model
def sha16(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()[:16]


def load_model(path, allow_feature_mismatch=False):
    import joblib
    B = joblib.load(path)
    if not isinstance(B, dict) or B.get("format") != "siem10-trainer-v1":
        raise SystemExit(f"{path}: không phải model của trainer.py (format={getattr(B, 'get', lambda k: None)('format')})")
    feats = list(B["features"])
    if feats != list(F.NO_URL_COLUMNS):
        raise SystemExit(f"{path}: danh sách đặc trưng {feats} khác features.NO_URL_COLUMNS")
    n_in = getattr(B["model"], "n_features_in_", None)
    if n_in != len(feats):
        raise SystemExit(f"{path}: mô hình nhận {n_in} cột, danh sách đặc trưng có {len(feats)}")
    code_sha = sha16(os.path.join(HERE, "features.py"))
    ds_sha = (B.get("dataset") or {}).get("features_sha_dataset")
    if ds_sha and ds_sha != code_sha:
        msg = f"features.py hiện tại ({code_sha}) khác bản dùng dựng dataset huấn luyện ({ds_sha})"
        if not allow_feature_mismatch:
            raise SystemExit(msg + " -> đặc trưng online sẽ khác lúc huấn luyện. Dùng --allow-feature-mismatch nếu chắc chắn.")
        log("CẢNH BÁO:", msg)
    B.setdefault("score_decimals", 9)
    B["model_sha"] = sha16(path)
    return B


# ============================================================ lưu trạng thái
class MemoryStore:
    """Giống RedisStore nhưng trong RAM (chạy offline/kiểm thử). Một commit = một thay đổi nguyên tử."""

    def __init__(self):
        self.ckpt, self.states, self.outbox = None, {}, []

    def get_ckpt(self):
        return self.ckpt

    def load_states(self):
        return dict(self.states)

    def commit(self, states, ckpt, docs):
        for ip, ev in states.items():
            if ev:
                self.states[ip] = ev
            else:
                self.states.pop(ip, None)
        self.ckpt = ckpt
        self.outbox.extend(docs)

    def outbox_peek(self, n):
        return self.outbox[:n]

    def outbox_trim(self, n):
        del self.outbox[:n]

    def outbox_len(self):
        return len(self.outbox)


class RedisStore:
    def __init__(self, url, prefix="ai:"):
        import redis
        self.r = redis.Redis.from_url(url, decode_responses=True)
        self.r.ping()
        self.p = prefix

    def get_ckpt(self):
        v = self.r.get(self.p + "ckpt")
        return json.loads(v) if v else None

    def load_states(self):
        out = {}
        for k in self.r.scan_iter(self.p + "state:*", count=1000):
            v = self.r.get(k)
            if v:
                out[k[len(self.p) + 6:]] = [tuple(x) for x in json.loads(v)]
        return out

    def commit(self, states, ckpt, docs):
        pipe = self.r.pipeline(transaction=True)
        for ip, ev in states.items():
            if ev:
                pipe.set(self.p + "state:" + ip, json.dumps(ev))
            else:
                pipe.delete(self.p + "state:" + ip)
        pipe.set(self.p + "ckpt", json.dumps(ckpt))
        if docs:
            pipe.rpush(self.p + "outbox", *[json.dumps(d, ensure_ascii=False) for d in docs])
        pipe.execute()

    def outbox_peek(self, n):
        return [json.loads(x) for x in self.r.lrange(self.p + "outbox", 0, n - 1)]

    def outbox_trim(self, n):
        self.r.ltrim(self.p + "outbox", n, -1)

    def outbox_len(self):
        return self.r.llen(self.p + "outbox")


# ============================================================ đích ghi
class FileSink:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)

    def send(self, docs):
        with open(self.path, "a", encoding="utf-8") as f:
            for d in docs:
                f.write(json.dumps(d, ensure_ascii=False) + "\n")


class OpenSearchSink:
    TEMPLATE = {"index_patterns": [INDEX_PREFIX + "*"], "priority": 200,
                "template": {"settings": {"number_of_shards": 1, "number_of_replicas": 0},
                             "mappings": {"dynamic": True, "properties": {
                                 "timestamp": {"type": "date"}, "event_time": {"type": "date"},
                                 "srcip": {"type": "ip"}, "url": {"type": "keyword"}, "method": {"type": "keyword"},
                                 "status": {"type": "integer"}, "full_log": {"type": "text"},
                                 "rule": {"properties": {"id": {"type": "keyword"}, "level": {"type": "integer"},
                                                         "description": {"type": "keyword"}, "groups": {"type": "keyword"}}},
                                 "ai": {"properties": {"score": {"type": "float"}, "flag": {"type": "boolean"},
                                                       "op": {"type": "keyword"}, "kind": {"type": "keyword"},
                                                       "late": {"type": "boolean"}, "duplicate": {"type": "boolean"}}}}}}}

    def __init__(self, url, user, password, ca, verify=True, client=None):
        if client is None:
            from opensearchpy import OpenSearch
            kw = dict(hosts=[url], http_auth=(user, password), timeout=30)
            if url.startswith("https"):
                kw.update(use_ssl=True, verify_certs=verify, ca_certs=ca if verify else None, ssl_show_warn=False)
            client = OpenSearch(**kw)
        self.c = client

    def init_index(self):
        self.c.indices.put_index_template(name="ai-enriched-alerts", body=self.TEMPLATE)

    def send(self, docs):
        body = []
        for d in docs:
            body.append({"index": {"_index": INDEX_PREFIX + d["event_time"][:10].replace("-", "."), "_id": d["_id"]}})
            body.append({k: v for k, v in d.items() if k != "_id"})
        r = self.c.bulk(body=body)
        if r.get("errors"):
            bad = [it for it in r["items"] if it.get("index", {}).get("status", 200) >= 300]
            raise RuntimeError(f"bulk lỗi {len(bad)}/{len(docs)}: {bad[:1]}")


# ============================================================ đọc alerts.json
class Tail:
    """Đọc alerts.json theo dòng, nhớ (inode, offset) đầu mỗi dòng; theo dõi xoay vòng (file mới, inode khác)."""

    def __init__(self, path, inode=None, offset=0, from_end=False):
        self.path, self.f, self.ino, self.pos, self.partial = path, None, None, 0, b""
        self._open(inode, offset, from_end)

    def _open(self, inode=None, offset=0, from_end=False):
        if not os.path.exists(self.path):
            return
        st = os.stat(self.path)
        self.f = open(self.path, "rb")                    # nhị phân: offset = byte thật, không lệch vì giải mã
        self.ino = st.st_ino
        if inode is not None and inode != st.st_ino:
            log(f"CẢNH BÁO: {self.path} đã xoay vòng từ lần chạy trước (inode {inode} -> {st.st_ino}); "
                "phần chưa đọc của file cũ bị bỏ qua — chạy lại build/ai_service với --from-start trên file xoay vòng nếu cần")
            offset = 0
        elif inode is None and from_end:
            offset = st.st_size
        if offset > st.st_size:
            offset = 0
        self.f.seek(offset); self.pos = offset; self.partial = b""

    def line_start(self):
        """Offset đầu dòng chưa hoàn chỉnh (hoặc vị trí đọc hiện tại)."""
        return self.pos - len(self.partial)

    def lines(self, max_lines=5000):
        """Trả list (offset_đầu_dòng, inode, text) các dòng hoàn chỉnh mới."""
        if self.f is None:
            self._open()
            if self.f is None:
                return []
        out = []
        while len(out) < max_lines:
            start = self.line_start()
            chunk = self.f.readline()
            if not chunk:
                break
            self.pos += len(chunk)
            if not chunk.endswith(b"\n"):
                self.partial += chunk                     # dòng đang ghi dở: chờ phần còn lại
                continue
            text = (self.partial + chunk).decode("utf-8", errors="replace"); self.partial = b""
            out.append((start, self.ino, text))
        if not out and self.f is not None:               # hết file: kiểm tra xoay vòng
            try:
                st = os.stat(self.path)
            except FileNotFoundError:
                return out
            if st.st_ino != self.ino or st.st_size < self.pos:
                log(f"alerts.json xoay vòng/cắt ngắn (inode {self.ino} -> {st.st_ino}); mở file mới")
                self.f.close(); self._open(None, 0)
        return out


# ============================================================ dịch vụ
class Service:
    def __init__(self, model, store, sink, alerts_path, op="fp5", reorder=2.0, idle_flush=5.0,
                 from_start=False, from_end=False, batch_max=2000, dedup_lines=500_000):
        self.M, self.store, self.sink = model, store, sink
        self.op = op
        self.reorder, self.idle_flush = reorder, idle_flush
        self.cols, self.tau, self.dec = model["features"], model["thresholds"], int(model["score_decimals"])
        if op not in self.tau:
            raise SystemExit(f"điểm vận hành '{op}' không có trong model ({list(self.tau)})")
        self.batch_max = batch_max
        ck = None if from_start else store.get_ckpt()
        self.states = {}
        if ck:
            for ip, ev in store.load_states().items():
                self.states[ip] = F.WindowState.load([tuple(e) for e in ev])
            self.done_after = set(ck.get("emitted_after", []))
            self.tail = Tail(alerts_path, ck["inode"], ck["offset"])
            log(f"tiếp tục từ checkpoint inode={ck['inode']} offset={ck['offset']}, {len(self.states)} srcip có trạng thái")
        else:
            self.done_after = set()
            self.tail = Tail(alerts_path, None, 0, from_end=from_end and not from_start)
            log(f"bắt đầu mới ({'đầu file' if not from_end or from_start else 'cuối file'})")
        self.buf = []                     # heap (t, kind_order, arrival, item)
        self.arrival = 0
        self.max_t = -math.inf
        self.last_line_wall = time.time()
        self.seen_ids, self.seen_lines = OrderedDict(), OrderedDict()
        self.dedup_lines = dedup_lines
        self.recent_score = OrderedDict() # dòng log -> điểm của sự kiện, cho alert thứ hai cùng dòng (ai.duplicate)
        self.emitted_after = []           # (offset, id) đã xử lý — để dựng checkpoint
        self.c = defaultdict(int)

    # ---- phân loại một dòng alerts.json
    def ingest(self, off, ino, text):
        self.c["lines"] += 1
        if "SIEMLAB" not in text:
            self.c["ignored_non_siemlab"] += 1; return
        try:
            a = json.loads(text)
        except Exception:
            self.c["bad_json"] += 1; return
        rule = a.get("rule", {})
        if (a.get("decoder") or {}).get("name") != "siemlab" and "siemlab_observed" not in rule.get("groups", []):
            self.c["ignored_other_group"] += 1; return
        m = siemlab_match(a)
        if not m:
            self.c["ignored_no_match"] += 1; return
        aid = str(a.get("id") or a["full_log"])
        base = str(rule.get("id")) in BASE_RULES
        line = m[0]
        if aid in self.done_after:                        # đã xử lý trước khi khởi động lại
            self.c["skip_already_done"] += 1
            self._remember(self.seen_ids, aid)
            self._remember(self.seen_lines, line)
            return
        if aid in self.seen_ids:
            self.c["dup_id"] += 1; return
        self._remember(self.seen_ids, aid)
        event = line not in self.seen_lines
        if not event and base:                            # agent đọc lại file: id mới, cùng dòng log
            self.c["dup_line"] += 1; return
        if event:
            self._remember(self.seen_lines, line)
        ev = {"id": aid, "off": off, "t": int(m[1]) / 1e6, "srcip": m[2], "method": m[3], "url": m[4],
              "status": int(m[5]), "line": line, "base": base, "event": event, "alert": a}
        self.max_t = max(self.max_t, ev["t"])
        heapq.heappush(self.buf, (ev["t"], 0 if event else 1, self.arrival, ev))
        self.arrival += 1
        self.c[("base" if base else "correlated") if event else "duplicate"] += 1

    def _remember(self, od, k):
        od[k] = None
        if len(od) > self.dedup_lines:
            od.popitem(last=False)

    # ---- lấy các sự kiện đã "chín" khỏi buffer, tính đặc trưng tuần tự, chấm điểm theo lô
    def drain(self, force=False):
        wm = math.inf if force else self.max_t - self.reorder
        ready = []
        while self.buf and self.buf[0][0] <= wm and len(ready) < self.batch_max:
            ready.append(heapq.heappop(self.buf)[3])
        if not ready:
            return []
        rows, idx, touched = [], [], set()
        for i, ev in enumerate(ready):
            if not ev["event"]:
                continue
            st = self.states.get(ev["srcip"])
            if st is None:
                st = self.states[ev["srcip"]] = F.WindowState()
            t = ev["t"]
            if st.last is not None and t < st.last:
                ev["late"] = True; self.c["late"] += 1; t = st.last
            f = st.push(t, ev["url"], ev["status"])
            ev["features"] = {k: f[k] for k in self.cols}
            ev["window_n"] = f["count_60s"]
            rows.append([f[k] for k in self.cols]); idx.append(i); touched.add(ev["srcip"])
        if rows:
            p = self.M["model"].predict_proba(np.asarray(rows, float))[:, 1]
            p = np.round(p, self.dec)
            for j, i in enumerate(idx):
                ready[i]["score"] = float(p[j])
        docs = []
        for ev in ready:
            if ev["event"]:
                sc = ev["score"]
                self.recent_score[ev["line"]] = sc
                if len(self.recent_score) > 200_000:
                    self.recent_score.popitem(last=False)
            else:
                sc = self.recent_score.get(ev["line"])
                if sc is None:
                    self.c["duplicate_without_event"] += 1
            docs.append(self.doc(ev, sc))
            self.c["flagged"] += bool(docs[-1]["ai"]["flag"])
            self.emitted_after.append((ev["off"], ev["id"]))
        self._gc(touched)
        self._commit(touched, docs)
        return docs

    def doc(self, ev, sc):
        a, rule = ev["alert"], ev["alert"].get("rule", {})
        flags = {op: (sc is not None and sc >= tau) for op, tau in self.tau.items()}
        ai = {"score": sc, "op": self.op, "threshold": self.tau[self.op], "flag": flags[self.op],
              "flags": flags, "kind": "base" if ev["base"] else "correlated", "late": bool(ev.get("late")),
              "duplicate": not ev["event"],
              "model_sha": self.M["model_sha"], "dataset_sha": (self.M.get("dataset") or {}).get("sha256", "")[:16],
              "service": VERSION, "scored_at": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
        if ev["event"]:
            ai["features"] = ev["features"]; ai["window_n"] = ev["window_n"]
        return {"_id": ev["id"], "timestamp": a.get("timestamp"),
                "event_time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ev["t"])) + f".{int(ev['t'] * 1e6) % 1_000_000:06d}Z",
                "srcip": ev["srcip"], "method": ev["method"], "url": ev["url"], "status": ev["status"],
                "rule": {"id": str(rule.get("id")), "level": rule.get("level"), "description": rule.get("description"),
                         "groups": rule.get("groups", [])},
                "agent": (a.get("agent") or {}).get("name"), "full_log": a.get("full_log"), "ai": ai}

    def _gc(self, touched):
        """Bỏ trạng thái srcip đã im lặng lâu hơn cửa sổ (không ảnh hưởng đặc trưng: cửa sổ đã rỗng)."""
        if len(self.states) < 512:
            return
        lim = self.max_t - 2 * F.WINDOW
        for ip in [ip for ip, st in self.states.items() if st.last is not None and st.last < lim]:
            del self.states[ip]; touched.add(ip)

    def _commit(self, touched, docs):
        buf_offs = [x[3]["off"] for x in self.buf]
        off = min(buf_offs) if buf_offs else self.tail.line_start()
        self._ck_off = (self.tail.ino, off)
        self.emitted_after = [(o, i) for o, i in self.emitted_after if o >= off]
        ck = {"inode": self.tail.ino, "offset": off, "path": self.tail.path,
              "emitted_after": [i for _, i in self.emitted_after], "max_t": self.max_t, "service": VERSION}
        states = {ip: (self.states[ip].dump() if ip in self.states else None) for ip in touched}
        self.store.commit(states, ck, docs)

    def flush_outbox(self, n=500):
        sent = 0
        while True:
            docs = self.store.outbox_peek(n)
            if not docs:
                return sent
            self.sink.send(docs)                          # lỗi -> ném ra, outbox giữ nguyên, thử lại vòng sau
            self.store.outbox_trim(len(docs)); sent += len(docs)

    # ---- vòng chính
    def step(self, force=False):
        got = self.tail.lines()
        now = time.time()
        for off, ino, text in got:
            self.ingest(off, ino, text)
        if got:
            self.last_line_wall = now
        idle = (now - self.last_line_wall) >= self.idle_flush
        n = 0
        while True:
            d = self.drain(force=force or idle)
            n += len(d)
            if not d:
                break
        if not n and not self.buf and getattr(self, "_ck_off", None) != (self.tail.ino, self.tail.line_start()):
            # không có gì để chấm nhưng offset đã chạy (dòng bị lọc / trùng): commit checkpoint cho theo kịp
            self._commit(set(), [])
        return len(got), n

    def run(self, once=False, poll=0.5, stats_every=30.0):
        stop = {"v": False}
        for s in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(s, lambda *_: stop.__setitem__("v", True))
            except ValueError:
                pass
        t_stats = time.time()
        while not stop["v"]:
            nl, nd = self.step(force=False)
            if once and nl == 0:
                self.step(force=True)
                self._flush_safe()
                break
            self._flush_safe()
            if time.time() - t_stats >= stats_every:
                self.stats(); t_stats = time.time()
            if nl == 0:
                time.sleep(poll)
        self.stats()

    def _flush_safe(self):
        try:
            self.flush_outbox()
        except Exception as e:                            # indexer chưa sẵn sàng: giữ outbox, thử lại
            self.c["sink_errors"] += 1
            if self.c["sink_errors"] % 20 == 1:
                log(f"CẢNH BÁO: ghi indexer lỗi ({e}); outbox={self.store.outbox_len()} — sẽ thử lại")

    def stats(self):
        log("thống kê:", json.dumps(dict(self.c), ensure_ascii=False), f"buffer={len(self.buf)} srcip={len(self.states)} "
            f"outbox={self.store.outbox_len()}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--model", default="models/full1/model.joblib")
    ap.add_argument("--alerts", default="/wazuh-logs/alerts/alerts.json")
    ap.add_argument("--op", default="fp5", help="điểm vận hành dùng cho ai.flag (f1 | fp5); cả hai đều được ghi trong ai.flags")
    ap.add_argument("--store", choices=["redis", "memory"], default="redis")
    ap.add_argument("--redis", default=os.environ.get("REDIS_URL", "redis://redis:6379/0"))
    ap.add_argument("--prefix", default="ai:", help="tiền tố khóa Redis")
    ap.add_argument("--sink", choices=["opensearch", "file"], default="opensearch")
    ap.add_argument("--out", default="output/ai_enriched.jsonl", help="với --sink file")
    ap.add_argument("--indexer", default=os.environ.get("INDEXER_URL", "https://wazuh.indexer:9200"))
    ap.add_argument("--indexer-user", default=os.environ.get("INDEXER_USERNAME", "admin"))
    ap.add_argument("--indexer-password", default=os.environ.get("INDEXER_PASSWORD", "SecretPassword"))
    ap.add_argument("--ca", default=os.environ.get("INDEXER_CA", "/certs/root-ca.pem"))
    ap.add_argument("--insecure", action="store_true", help="không kiểm chứng chỉ indexer (chỉ để chẩn đoán)")
    ap.add_argument("--init-index", action="store_true", help="tạo/cập nhật index template rồi chạy")
    ap.add_argument("--reorder", type=float, default=2.0, help="giây giữ trong reorder buffer (theo thời gian Apache)")
    ap.add_argument("--idle-flush", type=float, default=5.0, help="không có dòng mới sau N giây -> xả buffer")
    ap.add_argument("--from-start", action="store_true", help="bỏ checkpoint, đọc từ đầu file")
    ap.add_argument("--from-end", action="store_true", help="khi CHƯA có checkpoint: bắt đầu từ cuối file (mặc định: đầu file)")
    ap.add_argument("--once", action="store_true", help="đọc tới cuối file, xả hết, rồi thoát")
    ap.add_argument("--allow-feature-mismatch", action="store_true")
    a = ap.parse_args(argv)
    M = load_model(a.model, a.allow_feature_mismatch)
    log(f"{VERSION}: model {a.model} (sha {M['model_sha']}, dataset {M['dataset']['sha256'][:16]}, sklearn lúc train "
        f"{M['versions']['sklearn']}), {len(M['features'])} đặc trưng, op={a.op} ngưỡng={M['thresholds'][a.op]}")
    store = MemoryStore() if a.store == "memory" else RedisStore(a.redis, a.prefix)
    if a.sink == "file":
        sink = FileSink(a.out)
    else:
        sink = OpenSearchSink(a.indexer, a.indexer_user, a.indexer_password, a.ca, verify=not a.insecure)
        if a.init_index:
            sink.init_index(); log("đã tạo index template ai-enriched-alerts")
    svc = Service(M, store, sink, a.alerts, a.op, a.reorder, a.idle_flush, a.from_start, a.from_end)
    svc.run(once=a.once)
    return svc


if __name__ == "__main__":
    main()
