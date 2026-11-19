#!/usr/bin/env python3
"""apply_rule.py — cổng NGƯỜI DUYỆT cho luật Wazuh do hệ thống đề xuất (hướng dẫn v2 mục 17; v10).

Đề xuất = proposals/<pid>.json (hồ sơ) + proposals/<pid>.xml (luật). Không có gì tự sửa ruleset: mọi thay đổi đi qua đây.
Chạy trên HOST (cần docker), từ thư mục project:

  python3 scripts/apply_rule.py list
  python3 scripts/apply_rule.py show    <pid>
  python3 scripts/apply_rule.py check   <pid>                       # chỉ kiểm cú pháp (ghi tạm, analysisd -t, khôi phục)
  python3 scripts/apply_rule.py apply   <pid> [--by TÊN] [--yes] [--allow-no-regression]
  python3 scripts/apply_rule.py verify  <pid>                       # wazuh-logtest: luật khớp ở dòng nào
  python3 scripts/apply_rule.py remove  <pid> [--by TÊN] [--yes]
  python3 scripts/apply_rule.py reject  <pid> --reason "..." [--by TÊN]
  python3 scripts/apply_rule.py health                              # chỉ kiểm sức khỏe (không đổi gì)
  python3 scripts/apply_rule.py sync [--restore]                    # so file luật AI trên host với file đang chạy;
                                                                    # --restore: chép bản host vào manager (sau down -v)
  python3 scripts/apply_rule.py make-canary [--broken]              # tạo đề xuất THỬ chỉ khớp 192.0.2.0/24 (TEST-NET);
                                                                    # --broken: rule cha không tồn tại, để thử khôi phục

apply (mỗi bước được bấm giờ, ghi vào history của hồ sơ):
  0. tiền kiểm: hồ sơ đúng định dạng, trạng thái 'proposed' (luật đã 'rejected' KHÔNG bao giờ được áp), có kết quả kiểm
     thử hồi quy đạt (hoặc --allow-no-regression, được ghi lại), id luật trong 110000-119899 và chưa có trong ruleset,
     ruleset hiện tại qua analysisd -t, sức khỏe hiện tại đạt;
  1. sao lưu file luật AI (bản host + bản đang chạy -> wazuh/backups/ và /var/ossec/etc/siem10_backups/);
  2. ghi luật thành một khối BEGIN/END vào FILE LUẬT AI RIÊNG /var/ossec/etc/rules/zz_siem10_ai_rules.xml trong manager
     + bản sao trên host wazuh/ai_rules/zz_siem10_ai_rules.xml (không nằm trong zip). Vì sao file riêng:
       - /var/ossec/etc là volume wazuh_etc -> file tồn tại qua restart / tạo lại container;
       - script khởi động của image chỉ chép đè 3 file được gắn (ossec.conf, local_rules.xml, local_decoder.xml), nên
         file AI không bị chép đè; unzip bản mới cũng không xóa được nó (khác v1 ghi vào local_rules.xml);
       - tên "zz_" để Wazuh nạp SAU local_rules.xml (rule cha 100011/100012 phải có trước, nếu không luật bị bỏ qua);
       - `docker compose down -v` xóa volume -> dùng `sync --restore` để nạp lại từ bản host.
     Không còn khối nào thì xóa hẳn file (không để file rỗng).
  3. wazuh-analysisd -t — rc != 0 HOẶC có WARNING/ERROR mới so với trước khi đổi (Wazuh trả rc=0 khi bỏ qua luật hỏng,
     vd. "Rule '119801' will be ignored"): khôi phục cả hai, KHÔNG restart;
  4. wazuh-control restart;
  5. kiểm sức khỏe: tiến trình cần thiết chạy, agent Active, một request canary thật (host -> Apache :8080 -> siem.log
     -> agent -> manager) xuất hiện trong alerts.json, và (nếu ai-service chạy) trong ai-enriched-alerts-*;
  6. kiểm CHỨC NĂNG: nếu hồ sơ có verify.lines + expect_fire_at, wazuh-logtest phải cho luật khớp đúng các dòng đó
     (remove: luật không còn khớp ở dòng nào);
  7. sức khỏe hoặc chức năng KHÔNG đạt: khôi phục cả hai file, restart lại, kiểm sức khỏe lại; ghi 'rolled_back'.
remove: gỡ đúng khối BEGIN/END của đề xuất, cùng quy trình 1-7. Request canary sinh 1 alert SIEMLAB ngoài mọi batch
(build_dataset tự loại) — đừng apply/remove trong lúc đang sinh dữ liệu.
"""
import argparse, copy, hashlib, json, os, re, ssl, subprocess, sys, time, urllib.request, uuid
import xml.dom.minidom
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST_AI = os.path.join(ROOT, "wazuh", "ai_rules", "zz_siem10_ai_rules.xml")
BACKUP_DIR = os.path.join(ROOT, "wazuh", "backups")
PROPOSALS = os.path.join(ROOT, "proposals")
ACTIVE = "/var/ossec/etc/rules/zz_siem10_ai_rules.xml"     # file luật AI riêng (volume wazuh_etc)
BASE_ACTIVE = "/var/ossec/etc/rules/local_rules.xml"         # rule SIEMLAB gốc: chỉ ĐỌC (kiểm trùng id / khối cũ)
MGR_BACKUP = "/var/ossec/etc/siem10_backups"
ALERTS = "/var/ossec/logs/alerts/alerts.json"
BIN = "/var/ossec/bin"
FORMAT = "siem10-proposal-v1"
STATUSES = ("proposed", "applied", "removed", "rejected", "superseded")
ID_MIN, ID_MAX = 110000, 119899               # 1199xx dành cho wazuh_probe.py
REQUIRED_DAEMONS = ("wazuh-analysisd", "wazuh-remoted", "wazuh-db", "wazuh-modulesd", "wazuh-execd")
AGENT_NAME = os.environ.get("AGENT_NAME", "apache-lab-agent")
BEGIN = "<!-- siem10-ai BEGIN {pid} fp={fp} -->"
END = "<!-- siem10-ai END {pid} -->"


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Fail(Exception):
    pass


# ============================================================ môi trường thật (Docker); test thay bằng bản giả
class Env:
    def __init__(self, project=None, manager=None, apache_url=None, indexer=None, user=None, password=None, ca=None):
        self.compose = ["docker", "compose", "-p", project or os.environ.get("SIEM_PROJECT", "siem10")]
        self.svc = manager or os.environ.get("MANAGER_SVC", "wazuh.manager")
        self.apache_url = apache_url or os.environ.get("APACHE_URL", "http://127.0.0.1:8080")
        self.indexer = indexer or os.environ.get("INDEXER_HOST_URL", "https://127.0.0.1:9200")
        self.auth = (user or os.environ.get("INDEXER_USERNAME", "admin"), password or os.environ.get("INDEXER_PASSWORD", "SecretPassword"))
        self.ca = ca or os.path.join(ROOT, "vendor/wazuh-docker/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem")

    def mgr(self, args, inp=None, timeout=300):
        p = subprocess.run(self.compose + ["exec", "-T", self.svc] + args, input=inp, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout + p.stderr

    def http_get(self, path):
        try:
            with urllib.request.urlopen(self.apache_url + path, timeout=10) as r:
                return r.status
        except urllib.error.HTTPError as e:
            return e.code

    def es_count(self, field, value):
        """Số tài liệu ai-enriched-alerts-* có field == value; None nếu không hỏi được (indexer tắt, chưa có index)."""
        if os.access(self.ca, os.R_OK):
            ctx = ssl.create_default_context(cafile=self.ca); ctx.check_hostname = False
        else:                                         # thư mục chứng chỉ thuộc root: chỉ đọc, chỉ localhost
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        body = json.dumps({"query": {"term": {field: value}}}).encode()
        req = urllib.request.Request(self.indexer + "/ai-enriched-alerts-*/_count", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        import base64
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{self.auth[0]}:{self.auth[1]}".encode()).decode())
        try:
            with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
                return json.loads(r.read()).get("count")
        except Exception:
            return None

    def sleep(self, s):
        time.sleep(s)

    def clock(self):
        return time.time()


# ============================================================ hồ sơ đề xuất
def paths(pid):
    return os.path.join(PROPOSALS, f"{pid}.json"), os.path.join(PROPOSALS, f"{pid}.xml")


def load(pid):
    jp, xp = paths(pid)
    if not os.path.exists(jp) or not os.path.exists(xp):
        raise Fail(f"không có {os.path.relpath(jp, ROOT)} / {os.path.relpath(xp, ROOT)}")
    case = json.load(open(jp, encoding="utf-8"))
    xml_text = open(xp, encoding="utf-8").read()
    if case.get("format") != FORMAT:
        raise Fail(f"hồ sơ {pid}: format {case.get('format')!r} != {FORMAT}")
    if case.get("status") not in STATUSES:
        raise Fail(f"hồ sơ {pid}: trạng thái lạ {case.get('status')!r}")
    sha = hashlib.sha256(xml_text.encode()).hexdigest()
    if case.get("xml_sha256") and case["xml_sha256"] != sha:
        raise Fail(f"{pid}.xml đã bị sửa sau khi đề xuất (sha256 khác hồ sơ) — tạo đề xuất mới thay vì sửa tay")
    return case, xml_text


def save(pid, case):
    jp, _ = paths(pid)
    tmp = jp + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(case, f, ensure_ascii=False, indent=1)
    os.replace(tmp, jp)


def history(case, action, by, ok, **details):
    case.setdefault("history", []).append({"at": now_iso(), "action": action, "by": by, "ok": ok, **details})


def rule_ids(xml_text):
    try:
        doc = xml.dom.minidom.parseString("<root>" + xml_text + "</root>")
    except Exception as e:
        raise Fail(f"XML luật không hợp lệ: {e}")
    ids = [r.getAttribute("id") for r in doc.getElementsByTagName("rule")]
    if not ids:
        raise Fail("XML không có <rule>")
    for i in ids:
        if not i.isdigit() or not (ID_MIN <= int(i) <= ID_MAX):
            raise Fail(f"id luật {i} ngoài khoảng {ID_MIN}-{ID_MAX}")
    return ids


def block(pid, case, xml_text):
    return "\n" + BEGIN.format(pid=pid, fp=case.get("fingerprint", "-")) + "\n" + xml_text.strip() + "\n" + END.format(pid=pid) + "\n"


def strip_block(text, pid):
    pat = re.compile(r"\n?<!-- siem10-ai BEGIN " + re.escape(pid) + r" fp=[^>]*-->.*?<!-- siem10-ai END " + re.escape(pid) + r" -->\n?", re.S)
    out, n = pat.subn("\n", text)
    return out, n


def read_host():
    return open(HOST_AI, encoding="utf-8").read() if os.path.exists(HOST_AI) else ""


def write_host(text):
    """Bản sao trên host (KHÔNG gắn vào container — chỉ để lưu/khôi phục). Rỗng -> xóa file."""
    if not text.strip():
        if os.path.exists(HOST_AI):
            os.remove(HOST_AI)
        return
    os.makedirs(os.path.dirname(HOST_AI), exist_ok=True)
    tmp = HOST_AI + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, HOST_AI)


# ============================================================ thao tác trên manager
class Ops:
    def __init__(self, env, log=print, canary_timeout=120, ready_timeout=240):
        self.env, self.log = env, log
        self.canary_timeout, self.ready_timeout = canary_timeout, ready_timeout

    def read_active(self):
        """Nội dung file luật AI đang chạy; '' nếu chưa có file."""
        rc, out = self.env.mgr(["sh", "-c", f"if [ -e {ACTIVE} ]; then cat {ACTIVE}; fi"])
        if rc != 0:
            raise Fail(f"không đọc được {ACTIVE}: {out[-300:]}")
        return out

    def read_base(self):
        rc, out = self.env.mgr(["cat", BASE_ACTIVE])
        if rc != 0:
            raise Fail(f"không đọc được {BASE_ACTIVE}: {out[-300:]}")
        return out

    def write_active(self, text):
        if not text.strip():
            rc, out = self.env.mgr(["rm", "-f", ACTIVE])
        else:
            rc, out = self.env.mgr(["sh", "-c", f"cat > {ACTIVE} && (chown wazuh:wazuh {ACTIVE} 2>/dev/null; chmod 660 {ACTIVE})"], inp=text)
        if rc != 0:
            raise Fail(f"không ghi được {ACTIVE}: {out[-300:]}")

    def validate(self, baseline=None):
        """(ok, output, thông báo MỚI). analysisd -t trả rc=0 cả khi bỏ qua luật hỏng (đo 22/10: rule cha không tồn tại
        -> "WARNING: (7620): Signature ID '999999' was not found. Invalid 'if_matched_sid'.Rule '119801' will be
        ignored.", rc=0). Vì vậy: mọi WARNING/ERROR/CRITICAL MỚI so với lần kiểm ruleset trước khi đổi = KHÔNG đạt."""
        rc, out = self.env.mgr([f"{BIN}/wazuh-analysisd", "-t"])
        msgs = set(re.findall(r"((?:WARNING|ERROR|CRITICAL): .*)", out))
        new = sorted(msgs - set(baseline or ())) if baseline is not None else []
        return rc == 0 and not new, out.strip()[-1500:], new

    def messages(self):
        return set(re.findall(r"((?:WARNING|ERROR|CRITICAL): .*)", self.env.mgr([f"{BIN}/wazuh-analysisd", "-t"])[1]))

    def logtest_fires(self, lines, ids):
        rc, out = self.env.mgr([f"{BIN}/wazuh-logtest"], inp="\n".join(lines) + "\n")
        got = []
        for b in out.split("**Phase 1: Completed pre-decoding.")[1:]:
            m = re.search(r"\*\*Phase 3: Completed filtering \(rules\)\.\s*\n\s*id: '(\d+)'", b)
            got.append(m.group(1) if m else None)
        return [k + 1 for k, r in enumerate(got) if r in ids], got

    def restart(self):
        rc, out = self.env.mgr([f"{BIN}/wazuh-control", "restart"], timeout=600)
        return rc == 0, out.strip()[-800:]

    def daemons(self):
        rc, out = self.env.mgr([f"{BIN}/wazuh-control", "status"])
        running = set(re.findall(r"(wazuh-[a-z]+) is running", out))
        return [d for d in REQUIRED_DAEMONS if d not in running]

    def agent_active(self):
        rc, out = self.env.mgr([f"{BIN}/agent_control", "-l"])
        return any(AGENT_NAME in l and "Active" in l and "Disconnected" not in l for l in out.splitlines())

    def health(self, tag):
        """Trả (ok, chi tiết). Chờ tối đa ready_timeout cho tiến trình + agent, canary_timeout cho canary."""
        env, t0 = self.env, self.env.clock()
        det = {}
        while True:
            missing = self.daemons(); agent = self.agent_active()
            if not missing and agent:
                break
            if env.clock() - t0 > self.ready_timeout:
                return False, {"missing_daemons": missing, "agent_active": agent, "waited_s": round(env.clock() - t0, 1)}
            env.sleep(3)
        det["ready_s"] = round(env.clock() - t0, 1)
        token = f"{tag}-{uuid.uuid4().hex[:8]}"
        url = f"/__siem10_canary/{token}"
        t1 = env.clock()
        det["canary_http"] = env.http_get(url)
        found = False
        while env.clock() - t1 <= self.canary_timeout:
            rc, out = env.mgr(["sh", "-c", f"grep -c -F '{url}' {ALERTS} || true"])
            if out.strip().splitlines() and out.strip().splitlines()[-1].strip().isdigit() and int(out.strip().splitlines()[-1]) > 0:
                found = True; break
            env.sleep(2)
        det["canary_alert"] = found
        det["canary_alert_s"] = round(env.clock() - t1, 1) if found else None
        if not found:
            return False, det
        enr = None
        while env.clock() - t1 <= self.canary_timeout:
            enr = env.es_count("url", url)
            if enr is None or enr > 0:
                break
            env.sleep(2)
        det["canary_enriched"] = enr               # None = không hỏi được indexer / ai-service chưa có index
        det["canary_enriched_s"] = round(env.clock() - t1, 1) if enr else None
        if enr == 0:
            return False, det                      # indexer trả lời nhưng tài liệu không đến: ai-service không theo kịp
        try:                                       # chỉ báo, không làm hỏng sức khỏe
            det["ai_rules_host_eq_active"] = read_host().strip() == self.read_active().strip()
        except Exception:
            det["ai_rules_host_eq_active"] = None
        return True, det

    # --- thay ruleset có bảo vệ: trả (ok, timings, details)
    def change(self, new_text, tag, current=None, functional=None):
        """functional(): (ok, chi tiết) — kiểm CHỨC NĂNG sau khi khỏe (vd. logtest: luật mới khớp đúng chỗ kỳ vọng);
        không đạt -> khôi phục như khi sức khỏe không đạt."""
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        tm, det = {}, {}
        t = self.env.clock()
        active = current if current is not None else self.read_active()
        host = read_host()
        os.makedirs(BACKUP_DIR, exist_ok=True)
        bak_host = os.path.join(BACKUP_DIR, f"ai_rules.{ts}.host.xml"); bak_act = os.path.join(BACKUP_DIR, f"ai_rules.{ts}.active.xml")
        open(bak_host, "w", encoding="utf-8").write(host); open(bak_act, "w", encoding="utf-8").write(active)
        self.env.mgr(["sh", "-c", f"mkdir -p {MGR_BACKUP} && if [ -e {ACTIVE} ]; then cp {ACTIVE} {MGR_BACKUP}/ai_rules.{ts}.xml; fi"])
        det["backup"] = [os.path.relpath(bak_host, ROOT), os.path.relpath(bak_act, ROOT), f"{MGR_BACKUP}/ai_rules.{ts}.xml"]
        if host.strip() != active.strip():
            det["warning"] = "bản host khác bản đang chạy trước khi đổi — ghi cả hai theo bản đang chạy"
        base_msgs = self.messages()
        tm["backup_s"] = round(self.env.clock() - t, 2)

        def write_both(text):
            write_host(text)
            self.write_active(text)

        def restore(reason):
            self.log(f"  ! khôi phục ruleset cũ ({reason})")
            write_both(active)
            ok_v, _, new_v = self.validate(base_msgs)
            det["restored"] = {"reason": reason, "validate_ok": ok_v, "new_messages": new_v}

        t = self.env.clock(); write_both(new_text); tm["write_s"] = round(self.env.clock() - t, 2)
        t = self.env.clock(); ok, out, new_msgs = self.validate(base_msgs); tm["validate_s"] = round(self.env.clock() - t, 2)
        det["validate"] = {"ok": ok, "out": out[-600:], "new_messages": new_msgs}
        self.log(f"  • wazuh-analysisd -t: {'OK' if ok else 'KHÔNG ĐẠT'}" + (f" — thông báo mới: {new_msgs}" if new_msgs else ""))
        if not ok:
            restore("analysisd -t lỗi hoặc có cảnh báo mới"); return False, tm, det
        t = self.env.clock(); ok, out = self.restart(); tm["restart_s"] = round(self.env.clock() - t, 1)
        det["restart"] = {"ok": ok, "out": out[-400:]}
        self.log(f"  • wazuh-control restart: {'OK' if ok else 'LỖI'} ({tm['restart_s']} s)")
        hok, hdet = (False, {"skipped": "restart lỗi"}) if not ok else self.health(tag)
        det["health"] = hdet; tm["health_s"] = hdet.get("ready_s")
        self.log(f"  • sức khỏe: {'ĐẠT' if hok else 'KHÔNG ĐẠT'} {hdet}")
        if hok and functional is not None:
            t = self.env.clock(); fok, fdet = functional(); tm["functional_s"] = round(self.env.clock() - t, 2)
            det["functional"] = fdet
            self.log(f"  • kiểm chức năng (logtest): {'ĐẠT' if fok else 'KHÔNG ĐẠT'} {fdet}")
            if not fok:
                hok = False; why = "luật không hoạt động như kỳ vọng (logtest)"
        else:
            why = "sức khỏe không đạt sau restart"
        if hok:
            return True, tm, det
        restore(why)
        t = self.env.clock(); ok2, _ = self.restart(); tm["rollback_restart_s"] = round(self.env.clock() - t, 1)
        h2, h2det = self.health(tag + "-rb") if ok2 else (False, {"skipped": "restart lỗi"})
        det["health_after_rollback"] = h2det
        self.log(f"  • sau rollback: sức khỏe {'ĐẠT' if h2 else 'VẪN KHÔNG ĐẠT — cần xử lý tay'}")
        det["rolled_back"] = True
        return False, tm, det


# ============================================================ lệnh
def confirm(msg, yes):
    if yes:
        return True
    return input(f"  {msg} [y/N] ").strip().lower() in ("y", "yes")


def cmd_list(a, ops):
    os.makedirs(PROPOSALS, exist_ok=True)
    rows = []
    for fn in sorted(os.listdir(PROPOSALS)):
        if fn.endswith(".json"):
            pid = fn[:-5]
            try:
                c, x = load(pid)
                reg = c.get("regression") or {}
                rows.append((pid, c["status"] + (" (demo)" if c.get("purpose") == "demo" else ""), ",".join(rule_ids(x)), "đạt" if reg.get("passed") else ("chưa" if not reg else "KHÔNG đạt"),
                             c.get("created_at", "")[:19]))
            except Exception as e:
                rows.append((pid, f"<lỗi: {e}>", "", "", ""))
    if not rows:
        print("(chưa có đề xuất)"); return 0
    w = max(34, max(len(r[0]) for r in rows) + 2)
    print(f"{'ĐỀ XUẤT':<{w}}{'TRẠNG THÁI':<19}{'RULE':<10}{'HỒI QUY':<10}TẠO LÚC")
    for r in rows:
        print(f"{r[0]:<{w}}{r[1]:<19}{r[2]:<10}{r[3]:<10}{r[4]}")
    return 0


def cmd_show(a, ops):
    c, x = load(a.pid)
    print(json.dumps(c, ensure_ascii=False, indent=1)); print("\n--- XML ---\n" + x)
    return 0


def preflight(pid, case, xml_text, active, a, base=""):
    ids = rule_ids(xml_text)
    if case["status"] == "rejected":
        raise Fail(f"{pid} đã bị TỪ CHỐI — không bao giờ áp lại; tạo đề xuất mới (phiên bản mới) nếu cần")
    if case["status"] != "proposed":
        raise Fail(f"{pid} đang ở trạng thái '{case['status']}', chỉ áp được đề xuất 'proposed'")
    if case.get("purpose") == "demo" and not getattr(a, "allow_demo", False):
        raise Fail(f"{pid} là đề xuất MINH HỌA (purpose=demo, bước 2c) — không áp lên hệ thống; bộ luật chính thức là bộ "
                   f"đang áp (apply_rule.py list). Chỉ dùng --allow-demo khi cố ý thử, có ghi vào hồ sơ")
    reg = case.get("regression")
    if not (reg and reg.get("passed")) and not a.allow_no_regression:
        raise Fail(f"{pid} chưa có kết quả kiểm thử hồi quy ĐẠT (regression.passed) — không áp. "
                   f"Chỉ dùng --allow-no-regression cho luật thử nghiệm, có ghi vào hồ sơ")
    if "siem10-ai BEGIN" in base:
        raise Fail("local_rules.xml đang chạy còn khối luật AI kiểu cũ (bản apply_rule trước 26/10) — gỡ bằng bản cũ "
                   "hoặc sửa tay trước, rồi mới dùng file luật AI riêng")
    others = strip_block(active, pid)[0] + "\n" + base
    dup = [i for i in ids if re.search(rf'<rule\s+id="{i}"', others)]
    if dup:
        raise Fail(f"id luật đã có trong ruleset đang chạy: {dup}")
    if strip_block(active, pid)[1]:
        raise Fail(f"ruleset đang chạy đã có khối của {pid} nhưng hồ sơ ghi '{case['status']}' — kiểm tra tay")
    return ids


def cmd_check(a, ops):
    case, xml_text = load(a.pid)
    active = ops.read_active()
    ids = rule_ids(xml_text)
    base = ops.messages()
    ops.write_active(active.rstrip() + "\n" + block(a.pid, case, xml_text))
    try:
        ok, out, new = ops.validate(base)
    finally:
        ops.write_active(active)
    print(f"{a.pid}: rule {ids}; analysisd -t với luật này: {'OK' if ok else 'KHÔNG ĐẠT'} (đã khôi phục, không restart)")
    if not ok: print(out); print("thông báo mới:", new)
    return 0 if ok else 1


def cmd_apply(a, ops):
    case, xml_text = load(a.pid)
    active = ops.read_active()
    ids = preflight(a.pid, case, xml_text, active, a, base=ops.read_base())
    ok, out, _ = ops.validate()
    if not ok:
        raise Fail(f"ruleset HIỆN TẠI đã lỗi analysisd -t — không đụng vào:\n{out}")
    print(f"→ tiền kiểm sức khỏe trước khi đổi ruleset")
    h0, h0det = ops.health("pre-" + a.pid)
    if not h0:
        raise Fail(f"hệ thống đang KHÔNG khỏe trước khi áp ({h0det}) — xử lý trước, không áp lên hệ thống hỏng")
    reg = case.get("regression") or {}
    print(f"→ áp {a.pid}: rule {ids}; hồi quy: {reg.get('summary', 'KHÔNG CÓ (--allow-no-regression)')}")
    if not confirm("Xác nhận ghi ruleset + restart manager?", a.yes):
        print("Hủy."); return 1
    v = case.get("verify") or {}
    func = None
    if v.get("lines") and v.get("expect_fire_at") is not None:
        def func():
            fired, _ = ops.logtest_fires(v["lines"], ids)
            return fired == v["expect_fire_at"], {"fired_at": fired, "expected": v["expect_fire_at"]}
    ok, tm, det = ops.change(active.rstrip() + "\n" + block(a.pid, case, xml_text), "apply-" + a.pid, current=active, functional=func)
    det["pre_health"] = h0det
    if ok:
        case["status"] = "applied"
        history(case, "apply", a.by, True, rule_ids=ids, timings=tm, details=det,
                no_regression_override=bool(a.allow_no_regression and not reg.get("passed")),
                demo_override=bool(case.get("purpose") == "demo"))
        save(a.pid, case)
        print(f"✓ đã áp {a.pid} ({tm}).  Tiếp: python3 scripts/apply_rule.py verify {a.pid}")
        return 0
    history(case, "apply", a.by, False, rule_ids=ids, timings=tm, details=det)
    save(a.pid, case)
    print(f"✗ áp {a.pid} THẤT BẠI — đã khôi phục ruleset cũ. Chi tiết trong history của hồ sơ.")
    return 2


def cmd_remove(a, ops):
    case, xml_text = load(a.pid)
    active = ops.read_active()
    new, n = strip_block(active, a.pid)
    if case["status"] != "applied" or n == 0:
        raise Fail(f"{a.pid}: trạng thái '{case['status']}', số khối trong ruleset đang chạy = {n} — không có gì để gỡ")
    if not confirm(f"Gỡ {a.pid} + restart manager?", a.yes):
        print("Hủy."); return 1
    ids = rule_ids(xml_text)
    lines = (case.get("verify") or {}).get("lines")
    func = None
    if lines:
        def func():
            fired, _ = ops.logtest_fires(lines, ids)
            return not fired, {"fired_at_after_remove": fired}
    ok, tm, det = ops.change(new.rstrip() + "\n" if new.strip() else "", "remove-" + a.pid, current=active, functional=func)
    if ok:
        case["status"] = "removed"
    history(case, "remove", a.by, ok, timings=tm, details=det, reason=a.reason)
    save(a.pid, case)
    print(("✓ đã gỡ " if ok else "✗ gỡ THẤT BẠI, đã khôi phục ") + f"{a.pid} ({tm})")
    return 0 if ok else 2


def cmd_reject(a, ops):
    case, _ = load(a.pid)
    if case["status"] != "proposed":
        raise Fail(f"chỉ từ chối được đề xuất 'proposed' (hiện: '{case['status']}'); luật đang áp thì dùng remove")
    if not a.reason:
        raise Fail("cần --reason")
    case["status"] = "rejected"
    history(case, "reject", a.by, True, reason=a.reason)
    save(a.pid, case)
    print(f"✓ {a.pid} = rejected (không bao giờ được áp lại)")
    return 0


def cmd_verify(a, ops):
    case, xml_text = load(a.pid)
    ids = rule_ids(xml_text)
    v = case.get("verify") or {}
    lines = v.get("lines") or []
    if not lines:
        raise Fail("hồ sơ không có verify.lines")
    fired, got = ops.logtest_fires(lines, ids)
    exp = v.get("expect_fire_at")
    res = {"fired_at": fired, "expected": exp, "match": (fired == exp) if exp is not None else None, "rule_ids": got}
    print(f"{a.pid}: luật {ids} khớp ở dòng {fired}" + (f" (kỳ vọng {exp}: {'KHỚP' if fired == exp else 'LỆCH'})" if exp is not None else ""))
    if not fired and case["status"] != "applied":
        print("  (luật chưa được áp nên logtest không biết nó — chạy verify sau apply)")
    history(case, "verify", a.by, bool(res["match"]) if exp is not None else bool(fired), result=res)
    save(a.pid, case)
    return 0 if (exp is None or fired == exp) else 3


def cmd_sync(a, ops):
    """So bản host với bản đang chạy. --restore: nạp bản host vào manager (sau `down -v` xóa volume wazuh_etc)."""
    host, active = read_host(), ops.read_active()
    blk = lambda t: re.findall(r"siem10-ai BEGIN (\S+)", t)
    print(f"bản host  ({os.path.relpath(HOST_AI, ROOT)}): {blk(host) or '(không có luật)'}")
    print(f"đang chạy ({ACTIVE}): {blk(active) or '(không có luật)'}")
    if host.strip() == active.strip():
        print("✓ trùng nhau"); return 0
    if not a.restore:
        print("✗ KHÁC NHAU — `sync --restore` để nạp bản host vào manager (có kiểm cú pháp, restart, sức khỏe, rollback)")
        return 2
    if not confirm("Nạp bản host vào manager + restart?", a.yes):
        print("Hủy."); return 1
    ok, tm, det = ops.change(host, "sync-restore", current=active)
    print(("✓ đã nạp bản host " if ok else "✗ nạp THẤT BẠI, đã khôi phục ") + f"({tm})")
    return 0 if ok else 2


def cmd_health(a, ops):
    ok, det = ops.health("health")
    print(("ĐẠT " if ok else "KHÔNG ĐẠT ") + json.dumps(det, ensure_ascii=False))
    return 0 if ok else 2


def cmd_make_canary(a, ops):
    """Đề xuất thử: chỉ khớp srcip 192.0.2.0/24 — không bao giờ có trong lab -> áp/gỡ không ảnh hưởng dữ liệu."""
    os.makedirs(PROPOSALS, exist_ok=True)
    rid = a.rule_id
    pid = f"CANARY{'-BROKEN' if a.broken else ''}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    parent = "999999" if a.broken else "100012"       # --broken: rule cha không tồn tại -> analysisd -t phải từ chối
    xml_text = (f'<group name="ai_generated,siem10_canary,">\n'
                f'  <rule id="{rid}" level="3" frequency="3" timeframe="60">\n'
                f'    <if_matched_sid>{parent}</if_matched_sid>\n    <same_srcip />\n    <srcip>192.0.2.0/24</srcip>\n'
                f'    <description>siem10 canary: 3 lan 404 / 60s cung nguon (chi TEST-NET 192.0.2.0/24)</description>\n'
                f'  </rule>\n</group>\n')
    rule_ids(xml_text)
    t = int(time.time() * 1e6)
    lines = [f'SIEMLAB {t + i} 192.0.2.77 "GET /canary{i} HTTP/1.1" 404 10' for i in range(7)]
    case = {"format": FORMAT, "proposal_id": pid, "status": "proposed", "created_at": now_iso(), "generated_by": "apply_rule.py make-canary",
            "kind": "canary", "template": {"name": "canary_frequency", "version": 1},
            "fingerprint": hashlib.sha256(xml_text.encode()).hexdigest()[:16], "xml_sha256": hashlib.sha256(xml_text.encode()).hexdigest(),
            "regression": {"passed": True, "summary": "không áp dụng — luật thử chỉ khớp 192.0.2.0/24 (TEST-NET)", "kind": "canary"},
            "verify": {"lines": lines, "expect_fire_at": [3, 6]}, "history": []}
    jp, xp = paths(pid)
    open(xp, "w", encoding="utf-8").write(xml_text)
    json.dump(case, open(jp, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"✓ tạo {pid} (rule {rid}). Thử: apply {pid} --yes -> verify {pid} -> remove {pid} --yes")
    return 0


def main(argv=None, env=None, log=print):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("list", "health", "make-canary", "sync"):
        sp = sub.add_parser(name)
        if name == "sync":
            sp.add_argument("--restore", action="store_true"); sp.add_argument("--yes", action="store_true")
        if name == "make-canary":
            sp.add_argument("--rule-id", type=int, default=119800)
            sp.add_argument("--broken", action="store_true", help="luật thử SAI (rule cha 999999) để kiểm khôi phục khi analysisd -t lỗi")
    for name in ("show", "check", "apply", "verify", "remove", "reject"):
        sp = sub.add_parser(name); sp.add_argument("pid")
        sp.add_argument("--by", default=os.environ.get("USER", "unknown"))
        sp.add_argument("--yes", action="store_true"); sp.add_argument("--reason", default=None)
        sp.add_argument("--allow-no-regression", action="store_true")
        sp.add_argument("--allow-demo", action="store_true", help="cho áp đề xuất minh họa (purpose=demo) — có ghi lại")
    ap.add_argument("--canary-timeout", type=float, default=120); ap.add_argument("--ready-timeout", type=float, default=240)
    a = ap.parse_args(argv)
    ops = Ops(env or Env(), log=log, canary_timeout=a.canary_timeout, ready_timeout=a.ready_timeout)
    fn = {"list": cmd_list, "show": cmd_show, "check": cmd_check, "apply": cmd_apply, "verify": cmd_verify, "remove": cmd_remove,
          "reject": cmd_reject, "health": cmd_health, "make-canary": cmd_make_canary, "sync": cmd_sync}[a.cmd]
    try:
        return fn(a, ops)
    except Fail as e:
        print(f"✗ {e}"); return 1
    except PermissionError as e:
        print(f"✗ {e}\n  (file do container tạo thuộc root: sudo chown -R $USER proposals wazuh)"); return 1


if __name__ == "__main__":
    sys.exit(main())
