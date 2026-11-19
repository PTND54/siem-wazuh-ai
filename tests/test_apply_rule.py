#!/usr/bin/env python3
"""Kiểm apply_rule.py với một manager GIẢ LẬP (không cần Docker): apply/verify/remove trọn vòng, sai cú pháp -> khôi phục,
KHÔNG restart; restart xong nhưng sức khỏe không đạt -> khôi phục + restart lại; luật bị từ chối không bao giờ áp được;
thiếu kiểm thử hồi quy -> từ chối (trừ --allow-no-regression, có ghi lại); XML bị sửa sau đề xuất; trùng id; hệ thống
không khỏe trước khi áp; luật AI ở FILE RIÊNG zz_siem10_ai_rules.xml (local_rules.xml không bị đụng), còn nguyên sau khi
tạo lại manager (volume), `sync --restore` nạp lại sau `down -v`; khối luật AI kiểu cũ trong local_rules.xml -> chặn.
  python3 tests/test_apply_rule.py"""
import io, json, os, re, shutil, sys, tempfile
from contextlib import redirect_stdout
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import apply_rule as AR
from wazuh_sim import freq_fires

fails = []
def check(c, m):
    if not c: fails.append(m); print("  LỖI:", m)

T = tempfile.mkdtemp()
os.makedirs(os.path.join(T, "wazuh")); os.makedirs(os.path.join(T, "proposals"))
BASE = open(os.path.join(ROOT, "wazuh", "local_rules.xml"), encoding="utf-8").read()
AR.ROOT = T; AR.HOST_AI = os.path.join(T, "wazuh", "ai_rules", "zz_siem10_ai_rules.xml")
AR.BACKUP_DIR = os.path.join(T, "wazuh", "backups"); AR.PROPOSALS = os.path.join(T, "proposals")
HOST_LOCAL = os.path.join(T, "wazuh", "local_rules.xml")
open(HOST_LOCAL, "w", encoding="utf-8").write(BASE)


class FakeEnv:
    """Manager giả: local_rules.xml (base, chép từ host mỗi lần tạo lại container) + file luật AI riêng trong volume."""
    def __init__(self):
        self.base = BASE; self.ai = None; self.loaded = ""; self.t = 0.0
        self.restarts = 0; self.canaries = []; self.down = False

    @property
    def active(self): return self.ai or ""

    def recreate(self):                    # up -d --force-recreate: volume giữ, file gắn được chép đè từ host
        self.base = open(HOST_LOCAL, encoding="utf-8").read(); self.restarts += 1; self.loaded = self.active

    def clock(self): return self.t
    def sleep(self, s): self.t += s

    def mgr(self, args, inp=None, timeout=300):
        self.t += 0.5
        a0 = args[0]
        if a0 == "sh" and args[2] == f"if [ -e {AR.ACTIVE} ]; then cat {AR.ACTIVE}; fi": return 0, self.active
        if args == ["cat", AR.BASE_ACTIVE]: return 0, self.base
        if args == ["rm", "-f", AR.ACTIVE]: self.ai = None; return 0, ""
        if a0 == "sh" and args[2].startswith(f"cat > {AR.ACTIVE} "): self.ai = inp; return 0, ""
        if a0 == "sh" and args[2].startswith(f"mkdir -p {AR.MGR_BACKUP}"): return 0, ""
        if a0.endswith("wazuh-analysisd"):
            allr = self.base + "\n" + self.active
            try:
                import xml.dom.minidom
                xml.dom.minidom.parseString("<r>" + self.base + "</r>"); xml.dom.minidom.parseString("<r>" + self.active + "</r>")
            except Exception as e:
                return 1, f"ERROR: {e}"
            ids = re.findall(r'<rule\s+id="(\d+)"', allr)
            if "BREAK_SYNTAX" in self.active or len(ids) != len(set(ids)):
                return 1, "ERROR: Invalid configuration"
            out = "2026/10/22 11:00:00 wazuh-analysisd: WARNING: (1234): cảnh báo có sẵn từ trước\n"   # đã có trước: bỏ qua
            for rid in re.findall(r'<rule id="(\d+)"[^>]*>\s*<if_matched_sid>999999<', self.active):  # như Wazuh 4.14.7 đo 22/10
                out += (f"2026/10/22 11:{self.t % 60:02.0f}:00 wazuh-analysisd: WARNING: (7620): Signature ID '999999' was not found. "
                        f"Invalid 'if_matched_sid'.Rule '{rid}' will be ignored.\n")
            return 0, out
        if a0.endswith("wazuh-control") and args[1] == "restart":
            self.restarts += 1; self.loaded = self.active; self.t += 20; return 0, "restarted"
        if a0.endswith("wazuh-control") and args[1] == "status":
            if self.down: return 0, "wazuh-analysisd not running..."
            return 0, "\n".join(f"{d} is running..." for d in AR.REQUIRED_DAEMONS) + "\nwazuh-clusterd not running..."
        if a0.endswith("agent_control"):
            return 0, f"ID: 000, Name: wazuh.manager (server), IP: 127.0.0.1, Active/Local\nID: 001, Name: {AR.AGENT_NAME}, IP: any, Active"
        if a0 == "sh" and "grep -c -F" in args[2]:
            url = re.search(r"grep -c -F '([^']+)'", args[2]).group(1)
            ok = url in self.canaries and "BREAK_HEALTH" not in self.loaded
            return 0, "1" if ok else "0"
        if a0.endswith("wazuh-logtest"):
            ids = re.findall(r'<rule id="(\d+)" level="\d+" frequency="(\d+)" timeframe="(\d+)">\s*<if_matched_sid>100012<', self.loaded)
            lines = inp.strip().split("\n"); out = ""
            per = [(rid, {k for k, x in enumerate(freq_fires([i * 0.1 for i in range(len(lines))], int(n), int(tf))) if x}) for rid, n, tf in ids]
            for k, l in enumerate(lines):
                rid = next((r for r, fs in per if k in fs), "100012")       # rule đầu tiên (theo thứ tự file) khớp dòng này
                out += f"**Phase 1: Completed pre-decoding.\n\tfull event: '{l}'\n\n**Phase 3: Completed filtering (rules).\n\tid: '{rid}'\n\n"
            return 0, out
        raise AssertionError(f"lệnh lạ: {args}")

    def http_get(self, path): self.canaries.append(path); return 404
    def es_count(self, field, value): return 1 if value in self.canaries and "BREAK_HEALTH" not in self.loaded else 0


def run(env, *argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = AR.main(list(argv) + ["--canary-timeout", "30", "--ready-timeout", "30"][:0], env=env, log=print)
    return rc, buf.getvalue()

def case(pid): return json.load(open(os.path.join(AR.PROPOSALS, pid + ".json")))
def host(): return open(AR.HOST_AI, encoding="utf-8").read() if os.path.exists(AR.HOST_AI) else ""
def local_untouched(): return open(HOST_LOCAL, encoding="utf-8").read() == BASE and E.base == BASE

E = FakeEnv()
rc, out = run(E, "make-canary"); pid = re.search(r"tạo (CANARY-\S+)", out).group(1)
check(rc == 0, "make-canary")

# 1. apply trọn vòng
rc, out = run(E, "apply", pid, "--yes", "--by", "tester")
c = case(pid)
check(rc == 0 and c["status"] == "applied", f"apply canary: rc={rc} {out[-300:]}")
check(f"siem10-ai BEGIN {pid}" in E.active and f"siem10-ai BEGIN {pid}" in host() and E.loaded == E.active, "khối luật phải ở file AI (host + manager) và đã nạp")
check(local_untouched(), "local_rules.xml (host và manager) KHÔNG được đụng tới")
h = c["history"][-1]
check(h["action"] == "apply" and h["ok"] and "restart_s" in h["timings"] and h["details"]["health"]["canary_alert"], f"history apply thiếu: {h}")
check(len(os.listdir(AR.BACKUP_DIR)) == 2 and E.restarts == 1, "phải có 2 file sao lưu và đúng 1 lần restart")
# tạo lại manager: luật AI còn nguyên (volume), local_rules chép lại từ host không ảnh hưởng
E.recreate()
rc, out = run(E, "verify", pid); check(rc == 0 and "KHỚP" in out and f"siem10-ai BEGIN {pid}" in E.loaded, f"sau tạo lại manager luật phải còn: {out}")
rc, out = run(E, "sync"); check(rc == 0 and "trùng" in out, f"sync sau tạo lại: {out}")
rc, out = run(E, "apply", pid, "--yes"); check(rc == 1 and "chỉ áp được" in out, "áp lại luật đang applied phải bị chặn")

# 2. verify
rc, out = run(E, "verify", pid); check(rc == 0 and "KHỚP" in out, f"verify canary: {out}")

# 3. remove
rc, out = run(E, "remove", pid, "--yes")
check(rc == 0 and case(pid)["status"] == "removed" and host() == "" and E.ai is None and not os.path.exists(AR.HOST_AI),
      f"remove khối cuối cùng phải xóa hẳn file AI (host + manager): {out[-200:]}")
check(local_untouched(), "local_rules.xml không đổi sau remove")

def clone(src, newpid, xml_mut=None, rid=None, **case_upd):
    c = case(src); x = open(os.path.join(AR.PROPOSALS, src + ".xml"), encoding="utf-8").read()
    if rid: x = x.replace('id="119800"', f'id="{rid}"')
    if xml_mut: x = xml_mut(x)
    import hashlib
    c.update({"proposal_id": newpid, "status": "proposed", "history": [], "xml_sha256": hashlib.sha256(x.encode()).hexdigest()}); c.update(case_upd)
    open(os.path.join(AR.PROPOSALS, newpid + ".xml"), "w").write(x); json.dump(c, open(os.path.join(AR.PROPOSALS, newpid + ".json"), "w"))
    return newpid

# 4. từ chối -> không bao giờ áp
p2 = clone(pid, "P-reject", rid=119801)
rc, out = run(E, "reject", p2, "--reason", "báo nhầm trên broken_links"); check(rc == 0 and case(p2)["status"] == "rejected", "reject")
rc, out = run(E, "apply", p2, "--yes"); check(rc == 1 and "TỪ CHỐI" in out, "luật bị từ chối không được áp")

# 5. sai cú pháp -> khôi phục, KHÔNG restart
r0 = E.restarts
p3 = clone(pid, "P-syntax", rid=119802, xml_mut=lambda x: x.replace("siem10 canary", "BREAK_SYNTAX"))
rc, out = run(E, "apply", p3, "--yes")
check(rc == 2 and case(p3)["status"] == "proposed" and E.restarts == r0, f"sai cú pháp: phải thất bại, không restart ({rc}, {E.restarts - r0})")
check(host() == "" and E.active == "", "sai cú pháp: phải khôi phục cả hai file")
check(case(p3)["history"][-1]["details"]["restored"]["validate_ok"], "sau khôi phục analysisd -t phải OK")

# 6. restart xong nhưng sức khỏe không đạt -> khôi phục + restart lại
r0 = E.restarts
p4 = clone(pid, "P-health", rid=119803, xml_mut=lambda x: x.replace("siem10 canary", "BREAK_HEALTH"))
rc, out = run(E, "apply", p4, "--yes")
d = case(p4)["history"][-1]["details"]
check(rc == 2 and case(p4)["status"] == "proposed" and E.restarts == r0 + 2, f"sức khỏe hỏng: phải rollback + restart lại ({rc}, {E.restarts - r0})")
check(host() == "" and E.loaded == "" and d.get("rolled_back") and d["health_after_rollback"]["canary_alert"],
      "sức khỏe hỏng: ruleset đang nạp phải là bản cũ và khỏe lại")

# 7. thiếu hồi quy
p5 = clone(pid, "P-noreg", rid=119804, regression=None)
rc, out = run(E, "apply", p5, "--yes"); check(rc == 1 and "hồi quy" in out, "thiếu hồi quy phải bị chặn")
rc, out = run(E, "apply", p5, "--yes", "--allow-no-regression")
check(rc == 0 and case(p5)["history"][-1]["no_regression_override"] is True, "--allow-no-regression phải được ghi lại")
run(E, "remove", p5, "--yes")

# 7b. đề xuất minh họa (2c, purpose=demo) không được áp, trừ --allow-demo (ghi lại); list đánh dấu (demo)
pd_ = clone(pid, "DEMO-P-demo", rid=119806, purpose="demo")
rc, out = run(E, "apply", pd_, "--yes"); check(rc == 1 and "MINH HỌA" in out and case(pd_)["status"] == "proposed", f"demo phải bị chặn: {out[-200:]}")
rc, out = run(E, "list"); check("proposed (demo)" in out, "list phải đánh dấu (demo)")
rc, out = run(E, "apply", pd_, "--yes", "--allow-demo")
check(rc == 0 and case(pd_)["history"][-1].get("demo_override") is True, "--allow-demo phải được ghi lại")
run(E, "remove", pd_, "--yes")

# 8. XML bị sửa sau đề xuất
p6 = clone(pid, "P-tamper", rid=119805)
open(os.path.join(AR.PROPOSALS, p6 + ".xml"), "a").write("<!-- sửa tay -->")
rc, out = run(E, "apply", p6, "--yes"); check(rc == 1 and "bị sửa" in out, "XML bị sửa phải bị chặn")

# 9. trùng id với ruleset
p7 = clone(pid, "P-dup", xml_mut=lambda x: x.replace('id="119800"', 'id="100012"'))
rc, out = run(E, "apply", p7, "--yes"); check(rc == 1 and "ngoài khoảng" in out, "id ngoài khoảng 110000-119899 phải bị chặn")
p8 = clone(pid, "P-a", rid=119806); run(E, "apply", p8, "--yes")
p9 = clone(pid, "P-b", rid=119806)
rc, out = run(E, "apply", p9, "--yes"); check(rc == 1 and "đã có trong ruleset" in out, "trùng id với luật đang chạy phải bị chặn")
run(E, "remove", p8, "--yes")

# 10. hệ thống không khỏe trước khi áp
E.down = True
p10 = clone(pid, "P-down", rid=119807)
rc, out = run(E, "apply", p10, "--yes"); check(rc == 1 and "KHÔNG khỏe" in out and host() == "", "không áp lên hệ thống đang hỏng")
E.down = False

# 11. luật hỏng mà analysisd -t vẫn rc=0 (Wazuh chỉ cảnh báo "will be ignored") -> phải coi là KHÔNG đạt, không restart
r0 = E.restarts
rc, out = run(E, "make-canary", "--broken", "--rule-id", "119808"); pb = re.search(r"tạo (CANARY-BROKEN-\S+)", out).group(1)
rc, out = run(E, "apply", pb, "--yes")
hb = case(pb)["history"][-1]["details"]["validate"]
check(rc == 2 and E.restarts == r0 and host() == "" and any("7620" in m for m in hb["new_messages"]),
      f"luật bị Wazuh bỏ qua phải bị chặn trước restart: rc={rc} restarts={E.restarts - r0} {hb}")
check(not any("1234" in m for m in hb["new_messages"]), "cảnh báo có sẵn từ trước không được tính là mới")
# 12. khỏe nhưng luật không khớp đúng chỗ kỳ vọng (logtest) -> khôi phục + restart lại
r0 = E.restarts
p11 = clone(pid, "P-func", rid=119809, verify={"lines": case(pid)["verify"]["lines"], "expect_fire_at": [2, 4]})
rc, out = run(E, "apply", p11, "--yes"); d = case(p11)["history"][-1]["details"]
check(rc == 2 and E.restarts == r0 + 2 and host() == "" and d["functional"]["fired_at"] == [3, 6] and d.get("rolled_back"),
      f"kiểm chức năng không đạt phải rollback: rc={rc} {d.get('functional')}")
# remove có kiểm chức năng: sau gỡ luật không còn khớp
h_rm = [h for h in case(pid)["history"] if h["action"] == "remove"][-1]
check(h_rm["details"]["functional"]["fired_at_after_remove"] == [], "remove: logtest sau gỡ phải không còn khớp")
check([h for h in case(pid)["history"] if h["action"] == "apply"][-1]["details"]["functional"]["fired_at"] == [3, 6], "apply: kiểm chức năng phải chạy")

# 13. down -v (mất volume) -> sync phát hiện khác, --restore nạp lại bản host
p12 = clone(pid, "P-sync", rid=119810); run(E, "apply", p12, "--yes")
E.ai = None; E.loaded = ""                                           # volume mất
rc, out = run(E, "sync"); check(rc == 2 and "KHÁC" in out, f"sync phải phát hiện khác: {out}")
rc, out = run(E, "sync", "--restore", "--yes")
check(rc == 0 and f"siem10-ai BEGIN {p12}" in E.loaded, f"sync --restore phải nạp lại: {out[-300:]}")
run(E, "remove", p12, "--yes")
# 14. hai luật cùng lúc: gỡ một thì luật kia còn
# (cùng rule cha, N khác nhau để logtest giả không phải quyết luật nào thắng ở cùng một dòng — chuyện đó đo ở 2b-2)
pa = clone(pid, "P-x", rid=119811)
pb2 = clone(pid, "P-y", rid=119812, xml_mut=lambda x: x.replace('frequency="3"', 'frequency="4"'),
            verify={"lines": case(pid)["verify"]["lines"], "expect_fire_at": [4]})
run(E, "apply", pa, "--yes"); run(E, "apply", pb2, "--yes")
run(E, "remove", pa, "--yes")
check(f"BEGIN {pb2}" in E.active and f"BEGIN {pa}" not in E.active and f"BEGIN {pb2}" in host(), "gỡ một luật phải giữ luật kia")
run(E, "remove", pb2, "--yes"); check(E.ai is None and host() == "", "gỡ hết thì không còn file AI")
# 15. local_rules.xml còn khối AI kiểu cũ -> chặn
E.base = BASE + "\n<!-- siem10-ai BEGIN OLD fp=x -->\n<!-- siem10-ai END OLD -->\n"
p13 = clone(pid, "P-legacy", rid=119813)
rc, out = run(E, "apply", p13, "--yes"); check(rc == 1 and "kiểu cũ" in out, f"phải chặn khi còn khối AI cũ trong local_rules: {out[-200:]}")
E.base = BASE
# id trùng với luật viết tay trong local_rules.xml -> chặn
E.base = BASE + '\n<group name="tay,"><rule id="119820" level="3"><if_sid>100012</if_sid><description>tay</description></rule></group>\n'
p14 = clone(pid, "P-dupbase", rid=119820)
rc, out = run(E, "apply", p14, "--yes"); check(rc == 1 and "đã có trong ruleset" in out, f"trùng id với local_rules phải bị chặn: {out[-200:]}")
E.base = BASE

rc, out = run(E, "list"); check(rc == 0 and pid in out and "rejected" in out, "list")
print("OK" if not fails else f"THẤT BẠI {len(fails)}"); shutil.rmtree(T); sys.exit(1 if fails else 0)
