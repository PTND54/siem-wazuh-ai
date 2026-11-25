#!/usr/bin/env python3
"""ar_manager.py — cài / gỡ / xem phần Active Response trên Wazuh Manager. Chạy trên HOST (WSL), trong ~/siem-wazuh-ai:
  python3 -B ar/tools/ar_manager.py status
  python3 -B ar/tools/ar_manager.py install [--yes]
  python3 -B ar/tools/ar_manager.py remove  [--yes]

Chỉ ghi bên trong container Manager (volume wazuh_etc), không sửa file nào của dự án:
  /var/ossec/etc/ossec.conf                         + white_list trong <global>, + các khối <active-response>
                                                    (đặt giữa hai cặp dấu SIEM10-AR, gỡ là cắt đúng hai đoạn đó)
  /var/ossec/etc/decoders/zx_siem10_ar_decoders.xml decoder dòng "SIEM10AI ..." của ar-watch
  /var/ossec/etc/rules/zx_siem10_ar_rules.xml       luật 100250
Trình tự an toàn dùng lại Ops của scripts/apply_rule.py (như sig/tools/sig_rules.py): sức khỏe trước -> ghi ->
wazuh-analysisd -t (không có cảnh báo MỚI) -> wazuh-control restart BÊN TRONG container -> sức khỏe -> logtest chức năng;
không đạt thì ghi lại bản cũ và khởi động lại. Nhật ký: ar/runs/ar_<lệnh>_<giờ>.json, bản sao ossec.conf cũ cùng chỗ.

LƯU Ý: tạo lại container Manager (docker compose up --force-recreate) sẽ chép lại ossec.conf gốc -> mất phần AR.
"""
import argparse, json, os, re, subprocess, sys, time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__)); ARD = os.path.dirname(HERE); ROOT = os.path.dirname(ARD)
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import apply_rule as AR  # noqa: E402  (chỉ import, không sửa)

CONF = "/var/ossec/etc/ossec.conf"
FILES = {"/var/ossec/etc/decoders/zx_siem10_ar_decoders.xml": os.path.join(ARD, "manager", "zx_siem10_ar_decoders.xml"),
         "/var/ossec/etc/rules/zx_siem10_ar_rules.xml": os.path.join(ARD, "manager", "zx_siem10_ar_rules.xml")}
B1, E1 = "<!-- SIEM10-AR:WHITELIST BEGIN -->", "<!-- SIEM10-AR:WHITELIST END -->"
B2, E2 = "<!-- SIEM10-AR:BLOCKS BEGIN -->", "<!-- SIEM10-AR:BLOCKS END -->"
TEST_LINE = "SIEM10AI srcip=192.0.2.77 flagged=12 window=60 maxscore=0.950"


def mread(ops, p):
    rc, out = ops.env.mgr(["sh", "-c", f"if [ -e {p} ]; then cat {p}; else printf __NOFILE__; fi"])
    if rc != 0:
        sys.exit(f"không đọc được {p}: {out[-300:]}")
    return None if out == "__NOFILE__" else out


def mwrite(ops, p, text):
    if text is None:
        rc, out = ops.env.mgr(["rm", "-f", p])
    else:   # file có sẵn (ossec.conf): `cat >` giữ nguyên chủ sở hữu và quyền; file mới: wazuh:wazuh 660
        rc, out = ops.env.mgr(["sh", "-c", f"if [ -e {p} ]; then cat > {p}; else cat > {p} && chown wazuh:wazuh {p} && chmod 660 {p}; fi"],
                              inp=text)
    if rc != 0:
        raise RuntimeError(f"không ghi được {p}: {out[-300:]}")


def whitelist():
    ips = [l.strip() for l in open(os.path.join(ARD, "manager", "whitelist.txt"), encoding="utf-8")
           if l.strip() and not l.lstrip().startswith("#")]
    return ips


def add(cur):
    i = cur.find("</global>")
    j = cur.rfind("</ossec_config>")
    if i < 0 or j < 0:
        sys.exit("ossec.conf không có </global> hoặc </ossec_config> — dừng, chưa ghi gì")
    wl = "\n    " + B1 + "".join(f"\n    <white_list>{ip}</white_list>" for ip in whitelist()) + "\n    " + E1
    blocks = open(os.path.join(ARD, "manager", "active_response.xml"), encoding="utf-8").read().rstrip("\n")
    bl = "\n  " + B2 + "\n" + blocks + "\n  " + E2
    li = cur.rfind("\n", 0, i); lj = cur.rfind("\n", 0, j)
    new = cur[:li] + wl + cur[li:lj] + bl + cur[lj:]
    if strip(new) != cur:
        sys.exit("dựng ossec.conf mới không trả lại đúng bản cũ khi cắt — dừng, chưa ghi gì")
    return new


def strip(conf):
    for b, e in ((B1, E1), (B2, E2)):
        conf = re.sub(r"\n[ \t]*" + re.escape(b) + r".*?" + re.escape(e), "", conf, flags=re.S)
    return conf


def wait_agent(since_utc, timeout=120):
    """Chờ agent kết nối LẠI sau khi Manager khởi động lại. Đo 24/11/2026: agent mất kết nối khi Manager restart và nối lại
    sau ~10 s; request kiểm tra gửi trong khoảng đó được Apache ghi nhưng KHÔNG bao giờ thành alert (mất hẳn, không phải
    tới muộn) -> kiểm sức khỏe phải đợi dòng "Connected to the server" có giờ >= lúc bắt đầu restart."""
    t0 = time.time(); lim = since_utc.strftime("%Y/%m/%d %H:%M:%S")
    while time.time() - t0 < timeout:
        p = subprocess.run(["docker", "exec", "wazuh-agent", "sh", "-c",
                            "grep 'Connected to the server' /var/ossec/logs/ossec.log | tail -1"],
                           capture_output=True, text=True, timeout=30)
        last = p.stdout.strip()[:19]
        if last and last >= lim:
            time.sleep(5)               # để analysisd / logcollector ổn định
            print(f"  • agent nối lại lúc {last} UTC (sau {round(time.time() - t0, 1)} s)")
            return True
        time.sleep(3)
    print(f"  • agent CHƯA nối lại sau {timeout} s")
    return False


def health_after(ops, tag, since_utc):
    wait_agent(since_utc)
    ok, det = ops.health(tag)
    if not ok and det.get("canary_alert") is False:      # thử lại một lần với request kiểm tra mới
        print("  • request kiểm tra không thành alert, thử lại một lần")
        ok, det = ops.health(tag + "-retry")
    return ok, det


def functional(ops):
    pos, got = ops.logtest_fires([TEST_LINE], {"100250"})
    return pos == [1], {"logtest": TEST_LINE, "rule": got}


def save(cmd, rec, old_conf=None):
    d = os.path.join(ARD, "runs"); os.makedirs(d, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    if old_conf is not None:
        open(os.path.join(d, f"ossec.conf.{ts}.bak"), "w", encoding="utf-8").write(old_conf)
    p = os.path.join(d, f"ar_{cmd}_{ts}.json")
    json.dump(rec, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("nhật ký ->", os.path.relpath(p, ROOT))


def status(ops):
    cur = mread(ops, CONF) or ""
    print(f"ossec.conf: whitelist AR {'CÓ' if B1 in cur else 'không'}, khối active-response AR {'CÓ' if B2 in cur else 'không'}")
    for p in FILES:
        print(f"{p}: {'có' if mread(ops, p) is not None else 'không'}")
    m = re.search(r"<command>\s*<name>firewall-drop</name>.*?</command>", cur, flags=re.S)
    print("lệnh firewall-drop:", re.sub(r"\s+", " ", m.group(0)) if m else "(KHÔNG có định nghĩa)")
    if B2 in cur:
        seg = cur[cur.find(B2):cur.find(E2)]
        for blk in re.findall(r"<active-response>.*?</active-response>", seg, flags=re.S):
            print("  ", re.sub(r"\s+", " ", blk))
    return 0


def change(ops, cmd, new_conf, new_files, yes):
    old_conf = mread(ops, CONF)
    old_files = {p: mread(ops, p) for p in new_files}
    if not yes and input(f"  {cmd} Active Response + khởi động lại tiến trình Wazuh trong container? [y/N] ").strip().lower() not in ("y", "yes"):
        print("Hủy."); return 1
    rec = {"cmd": cmd, "start_utc": datetime.now(timezone.utc).isoformat()}
    hok, hdet = ops.health("ar-pre"); rec["health_before"] = {"ok": hok, "det": hdet}
    print(f"  • sức khỏe trước: {'ĐẠT' if hok else 'KHÔNG ĐẠT'}")
    if not hok and cmd == "install":
        save(cmd, rec); sys.exit("hệ thống không khỏe trước khi đổi — dừng, chưa ghi gì")
    base = ops.messages()

    def write_all(conf, files):
        for p, t in files.items():
            mwrite(ops, p, t)
        mwrite(ops, CONF, conf)

    def back(why, restart=True):
        print(f"  ! khôi phục ({why})")
        write_all(old_conf, old_files)
        rec["rollback"] = {"why": why}
        if restart:
            ts0 = datetime.now(timezone.utc); rok, _ = ops.restart(); h2, _ = health_after(ops, "ar-rollback", ts0)
            rec["rollback"].update(restart_ok=rok, health_ok=h2)
            print(f"  • sau khôi phục: restart {'OK' if rok else 'LỖI'}, sức khỏe {'ĐẠT' if h2 else 'KHÔNG ĐẠT'}")

    write_all(new_conf, new_files)
    vok, vout, vnew = ops.validate(base)
    rc_x, out_x = ops.env.mgr([f"{AR.BIN}/wazuh-execd", "-t"])
    if rc_x != 0 and re.search(r"invalid option|unrecognized|usage", out_x, flags=re.I):
        rc_x, out_x = 0, "(bản này không có execd -t: bỏ qua, analysisd -t vẫn kiểm)"
    rec["validate"] = {"analysisd_ok": vok, "new": vnew, "execd_rc": rc_x, "execd_out": out_x.strip()[-500:]}
    print(f"  • analysisd -t: {'OK' if vok else 'KHÔNG ĐẠT'}" + (f" — thông báo mới: {vnew}" if vnew else ""))
    print(f"  • execd -t: {'OK' if rc_x == 0 else 'KHÔNG ĐẠT: ' + out_x.strip()[-300:]}")
    if not vok or rc_x != 0:
        back("kiểm cấu hình không đạt", restart=False); rec["result"] = "chặn trước khi khởi động lại"
        save(cmd, rec, old_conf); return 2
    ts0 = datetime.now(timezone.utc)
    t = time.time(); rok, _ = ops.restart(); rec["restart"] = {"ok": rok, "s": round(time.time() - t, 1)}
    print(f"  • wazuh-control restart (trong container): {'OK' if rok else 'LỖI'} ({rec['restart']['s']} s)")
    hok, hdet = (False, {"skip": "restart lỗi"}) if not rok else health_after(ops, "ar-" + cmd, ts0)
    rec["health_after"] = {"ok": hok, "det": hdet}; print(f"  • sức khỏe sau: {'ĐẠT' if hok else 'KHÔNG ĐẠT'} {hdet}")
    if cmd == "install":
        fok, fdet = (False, {}) if not hok else functional(ops)
        rec["functional"] = {"ok": fok, "det": fdet}
        print(f"  • chức năng (logtest dòng SIEM10AI -> 100250): {'ĐẠT' if fok else 'KHÔNG ĐẠT'} {fdet.get('rule')}")
    else:
        fok = True
    if not (hok and fok):
        back("sức khỏe/chức năng không đạt"); rec["result"] = "rolled_back"; save(cmd, rec, old_conf); return 2
    rec["result"] = "ok"; rec["end_utc"] = datetime.now(timezone.utc).isoformat(); save(cmd, rec, old_conf)
    print(f"✓ {'đã cài' if cmd == 'install' else 'đã gỡ'} Active Response trên Manager")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["status", "install", "remove"]); ap.add_argument("--yes", action="store_true")
    a = ap.parse_args()
    ops = AR.Ops(AR.Env())
    if a.cmd == "status":
        return status(ops)
    cur = mread(ops, CONF)
    if cur is None:
        sys.exit(f"không có {CONF} trong Manager")
    if a.cmd == "install":
        if B2 in cur or B1 in cur:
            print("Manager đã có phần AR — không làm gì (muốn cài lại thì remove trước)."); return 0
        files = {p: open(src, encoding="utf-8").read() for p, src in FILES.items()}
        return change(ops, "install", add(cur), files, a.yes)
    if B1 not in cur and B2 not in cur and all(mread(ops, p) is None for p in FILES):
        print("Manager không có phần AR — không có gì để gỡ."); return 0
    return change(ops, "remove", strip(cur), {p: None for p in FILES}, a.yes)


if __name__ == "__main__":
    sys.exit(main())
