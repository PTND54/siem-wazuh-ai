#!/usr/bin/env python3
"""sig_rules.py — cài / gỡ / kiểm bộ luật chữ ký trên Manager, theo đúng trình tự an toàn của scripts/apply_rule.py
(dùng lại chính Ops/Env của apply_rule.py: analysisd -t chặn cảnh báo MỚI, khởi động lại tiến trình Wazuh BÊN TRONG container
bằng wazuh-control, kiểm sức khỏe bằng request canary thật, kiểm chức năng bằng logtest, khôi phục khi không đạt).

Chạy trên HOST trong WSL, từ thư mục dự án (~/siem-wazuh-ai), khi KHÔNG có traffic:
  python3 -B sig/tools/sig_rules.py status
  python3 -B sig/tools/sig_rules.py check                  # chỉ logtest chức năng (không đổi gì)
  python3 -B sig/tools/sig_rules.py install [--yes]        # cài sig/rules/zy_siem10_sig_rules.xml
  python3 -B sig/tools/sig_rules.py remove  [--yes]        # gỡ, trở về ruleset đã chốt

File đích: /var/ossec/etc/rules/zy_siem10_sig_rules.xml (volume wazuh_etc; nạp sau local_rules.xml, trước zz_siem10_ai_rules.xml).
Không đụng file nào trong bản kê khóa. Nhật ký mỗi lần cài/gỡ: sig/runs/rules_<lệnh>_<giờ>.json
"""
import argparse, hashlib, json, os, sys, time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__)); SIG = os.path.dirname(HERE); ROOT = os.path.dirname(SIG)
sys.path.insert(0, os.path.join(ROOT, "scripts")); sys.path.insert(0, HERE)
import apply_rule as AR  # noqa: E402  (chỉ import, không sửa)
from replay_logtest import parse  # noqa: E402

DST = "/var/ossec/etc/rules/zy_siem10_sig_rules.xml"
SRC = os.path.join(SIG, "rules", "zy_siem10_sig_rules.xml")


def cl(ip, url, st):
    return f'{ip} - - [15/Nov/2026:09:00:00 +0000] "GET {url} HTTP/1.1" {st} 100 "-" "Mozilla/5.0 siem10-check"'


def sl(i, ip, url, st):
    return f'SIEMLAB {int(time.time() * 1e6) + i} {ip} "GET {url} HTTP/1.1" {st} 10'


def functional(ops):
    """(ok, chi tiết). Mỗi ca một phiên logtest riêng."""
    def run(lines):
        rc, out = ops.env.mgr([f"{AR.BIN}/wazuh-logtest"], inp="".join(l + "\n" for l in lines))
        return [(r.get("rule_id"), r.get("level"), r.get("alert")) for r in parse(out)]
    det, ok = {}, True
    single = [("sqli_200", cl("192.0.2.11", "/index.html?q=1%27%20union%20select%201,2--", 200), "sig"),
              ("xss_404", cl("192.0.2.12", "/nope?q=%3Cscript%3Ealert(1)%3C/script%3E", 404), "sig"),
              ("traversal_path_404", cl("192.0.2.13", "/static/..%2f..%2f..%2fetc%2fpasswd", 404), "sig"),
              ("cmdi_200", cl("192.0.2.14", "/index.html?q=x;cat%20/etc/passwd", 200), "sig"),
              ("plain_404_khong_alert", cl("192.0.2.15", "/khong_co_trang", 404), "noalert"),
              ("plain_200_khong_alert", cl("192.0.2.16", "/index.html", 200), "noalert")]
    got = run([l for _, l, _ in single])
    for (name, _, exp), g in zip(single, got + [None] * (len(single) - len(got))):
        rid, lv, al = g if g else (None, None, None)
        good = (rid is not None and rid.isdigit() and 100100 <= int(rid) <= 100199) if exp == "sig" else (not al)
        det[name] = {"rule": rid, "level": lv, "alert": al, "ok": good}; ok &= good
    g = run([cl("192.0.2.21", f"/index.html?q=1%27%20union%20select%20{i}--", 200) for i in range(6)])
    ids = [rid for rid, _, _ in g]          # không có luật tần suất: 6 dòng cùng IP đều phải là 100110
    det["cung_ip_6_dong"] = {"rules": ids, "ok": ids == ["100110"] * 6}; ok &= ids == ["100110"] * 6
    mix = []
    for i in range(30):
        mix += [sl(i, "192.0.2.31", f"/g1_{i}", 404), cl("192.0.2.31", f"/g1_{i}", 404)]
    g = run(mix)
    f20 = [("SIEMLAB" if k % 2 == 0 else "combined") + f" #{k // 2 + 1}" for k, (rid, _, _) in enumerate(g) if rid == "110020"]
    no31151 = all(rid != "31151" for rid, _, _ in g)
    good = f20 == ["SIEMLAB #15", "SIEMLAB #30"] and no31151
    det["g1_110020"] = {"fired_at": f20, "khong_co_31151": no31151, "ok": good}; ok &= good
    return ok, det


def sha(b):
    return hashlib.sha256(b).hexdigest()


def active(ops):
    rc, out = ops.env.mgr(["sh", "-c", f"if [ -e {DST} ]; then cat {DST}; fi"])
    return out if rc == 0 else None


def log(cmd, rec):
    p = os.path.join(SIG, "runs", f"rules_{cmd}_{datetime.now().strftime('%Y%m%d-%H%M%S')}.json")
    os.makedirs(os.path.dirname(p), exist_ok=True)
    json.dump(rec, open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1); print("nhật ký ->", os.path.relpath(p, ROOT))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["status", "check", "install", "remove"]); ap.add_argument("--yes", action="store_true")
    a = ap.parse_args()
    ops = AR.Ops(AR.Env())
    src = open(SRC, "rb").read() if os.path.exists(SRC) else None
    cur = active(ops)
    print(f"file trên host: {SRC} sha256 {sha(src)[:16] if src else '(không có)'}")
    print(f"file trên Manager: {DST} " + ("(không có)" if not cur else f"sha256 {sha(cur.encode())[:16]}"))
    if a.cmd == "status":
        return 0
    if a.cmd == "check":
        ok, det = functional(ops); print(("CHỨC NĂNG ĐẠT " if ok else "CHỨC NĂNG KHÔNG ĐẠT ") + json.dumps(det, ensure_ascii=False)); return 0 if ok else 2
    rec = {"cmd": a.cmd, "start_utc": datetime.now(timezone.utc).isoformat(), "src_sha256": sha(src) if src else None}
    if a.cmd == "install":
        if src is None or b"<srcip>" in src:
            sys.exit("thiếu file luật, hoặc đang trỏ nhầm biến thể thăm dò (có <srcip>)")
        if cur and sha(cur.encode()) == sha(src):
            print("Manager đã có đúng file này — không làm gì"); return 0
    elif not cur:
        print("Manager không có file luật chữ ký — không có gì để gỡ"); return 0
    if not a.yes and input(f"  {a.cmd} + khởi động lại tiến trình Wazuh trong container? [y/N] ").strip().lower() not in ("y", "yes"):
        print("Hủy."); return 1
    hok, hdet = ops.health("sig-pre"); rec["health_before"] = {"ok": hok, "det": hdet}
    print(f"  • sức khỏe trước: {'ĐẠT' if hok else 'KHÔNG ĐẠT'}")
    if not hok:
        log(a.cmd, rec); sys.exit("hệ thống không khỏe trước khi đổi — dừng")
    base = ops.messages()
    old = cur or ""

    def write(text):
        if text:
            rc, o = ops.env.mgr(["sh", "-c", f"cat > {DST} && chown wazuh:wazuh {DST} && chmod 660 {DST}"], inp=text)
        else:
            rc, o = ops.env.mgr(["rm", "-f", DST])
        if rc != 0:
            raise RuntimeError(o[-300:])

    def back(why):
        print(f"  ! khôi phục ({why})"); write(old); vok, _, vnew = ops.validate(base)
        rok, _ = ops.restart(); h2, d2 = ops.health("sig-rollback")
        rec["rollback"] = {"why": why, "validate_ok": vok, "restart_ok": rok, "health_ok": h2}
        print(f"  • sau khôi phục: analysisd {'OK' if vok else 'LỖI'}, sức khỏe {'ĐẠT' if h2 else 'KHÔNG ĐẠT'}")

    write(src.decode("utf-8") if a.cmd == "install" else "")
    vok, vout, vnew = ops.validate(base); rec["validate"] = {"ok": vok, "new": vnew}
    print(f"  • analysisd -t: {'OK' if vok else 'KHÔNG ĐẠT'}" + (f" — thông báo mới: {vnew}" if vnew else ""))
    if not vok:
        write(old); rec["result"] = "chặn ở analysisd -t, đã ghi lại file cũ, KHÔNG khởi động lại"; log(a.cmd, rec); return 2
    t = time.time(); rok, rout = ops.restart(); rec["restart"] = {"ok": rok, "s": round(time.time() - t, 1)}
    print(f"  • wazuh-control (trong container): {'OK' if rok else 'LỖI'} ({rec['restart']['s']} s)")
    hok, hdet = (False, {"skip": "restart lỗi"}) if not rok else ops.health("sig-" + a.cmd)
    rec["health_after"] = {"ok": hok, "det": hdet}; print(f"  • sức khỏe sau: {'ĐẠT' if hok else 'KHÔNG ĐẠT'} {hdet}")
    fok, fdet = (False, {}) if not hok else (functional(ops) if a.cmd == "install" else (True, {"bo_qua": "remove"}))
    rec["functional"] = {"ok": fok, "det": fdet}
    if a.cmd == "install":
        print(f"  • chức năng (logtest): {'ĐẠT' if fok else 'KHÔNG ĐẠT'} {json.dumps(fdet, ensure_ascii=False)}")
    if not (hok and fok):
        back("sức khỏe/chức năng không đạt"); rec["result"] = "rolled_back"; log(a.cmd, rec); return 2
    rec["result"] = "ok"; rec["end_utc"] = datetime.now(timezone.utc).isoformat(); log(a.cmd, rec)
    print(f"✓ {a.cmd} xong"); return 0


if __name__ == "__main__":
    sys.exit(main())
