#!/usr/bin/env python3
"""sig_probe.py — thăm dò ngữ nghĩa luật trên Wazuh Manager đang chạy, bằng wazuh-logtest.

Chạy trên HOST (WSL, cần docker):   python3 -B sig_probe.py [--phase A B] [--out DIR]
                         dọn khẩn:   python3 -B sig_probe.py --cleanup

Cách làm (cùng kiểu scripts/wazuh_probe.py, KHÔNG khởi động lại tiến trình nào của Manager):
  1. Kiểm file tạm /var/ossec/etc/rules/zy_siem10_sigprobe.xml chưa tồn tại; ghi lại cảnh báo hiện có của analysisd -t.
  2. Mỗi pha: ghi file tạm -> analysisd -t (ghi lại cảnh báo MỚI) -> mỗi ca một phiên wazuh-logtest -> LUÔN xóa file
     (kể cả khi lỗi / Ctrl+C) -> analysisd -t lại, phải trở về đúng các cảnh báo ban đầu.
  Tên "zy_" để file nạp đúng vị trí của bộ luật thật sau này: sau local_rules.xml, trước zz_siem10_ai_rules.xml.
  analysisd đang chạy KHÔNG nạp file này (chỉ nạp khi khởi động); wazuh-logtest nạp lại ruleset cho mỗi phiên.
  Mọi luật thăm dò mới (1199xx) chỉ khớp srcip 192.0.2.0/24. Pha B có khai báo overwrite cho luật dựng sẵn 31101,
  31120-31123, 31151, 31161-31163: chúng chỉ áp cho sự kiện web-accesslog, mà agent hiện KHÔNG gửi access_log.
  Nếu Manager tự khởi động lại đúng lúc file tạm còn đó: chạy --cleanup rồi
  `docker exec siem10-wazuh.manager-1 /var/ossec/bin/wazuh-control` với tham số khởi động lại, bên trong container.

Câu hỏi mỗi ca trả lời: xem CASES. Kết quả: <out>/result.json + bảng in ra.
"""
import argparse, json, os, re, signal, subprocess, sys, time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from replay_logtest import parse  # noqa: E402

C = "siem10-wazuh.manager-1"
F = "/var/ossec/etc/rules/zy_siem10_sigprobe.xml"
BIN = "/var/ossec/bin"
NET = "192.0.2.0/24"


def R(rid, level, body, if_sid="31100"):
    return (f'  <rule id="{rid}" level="{level}">\n    <if_sid>{if_sid}</if_sid>\n    <srcip>{NET}</srcip>\n{body}'
            f'    <description>sigprobe {rid}</description>\n  </rule>\n')


def U(p):
    return f'    <url type="pcre2">{p}</url>\n'


PROBE_RULES = (
    R(119950, 8, U("(?i)sp_pcre"))                       # pcre2 + (?i)
    + R(119951, 8, U("sp_g3a"))                          # G3: L8 so với 31105 L6 / 31101 L5
    + R(119952, 7, U("sp_g3b"))                          # G3: L7 so với 31103 L7 (file dựng sẵn nạp trước)
    + R(119953, 6, U("sp_g3c"))                          # G3: L6 so với 31105 L6
    + R(119954, 5, U("sp_g3d"))                          # G3: L5 so với 31101 L5
    + R(119955, 8, U("sp_g2a"))                          # G2: chỉ if_sid 31100
    + R(119956, 8, U("sp_g2b"), if_sid="31100,31108")     # G2: if_sid 31100,31108
    + R(119957, 8, U(r"sp_hex\x3cb"))                    # \x3c thay cho <
    + R(119958, 8, U(r"sp_amp\x26z"))                    # \x26 thay cho &
    + R(119959, 8, U("sp_m1") + U("sp_m2"))               # hai thẻ <url>: VÀ / HOẶC / nối chuỗi?
    + R(119960, 8, U("sp_case"))                         # pcre2 không (?i): phân biệt hoa thường?
    + R(119961, 8, U("sp_ua"))                           # <url> có xét User-Agent không
    + R(119962, 8, U(r"sp_bs\\\\"))                      # sau thoát ký tự của Apache: \\ trong url
)

OVERWRITE_B = """  <rule id="31101" level="0" overwrite="yes">
    <if_sid>31100</if_sid>
    <id>^4</id>
    <description>Web server 400 error code. (siem10: tat alert, trung luong SIEMLAB)</description>
  </rule>
  <rule id="31120" level="0" overwrite="yes">
    <if_sid>31100</if_sid>
    <id>^50</id>
    <description>Web server 500 error code (server error). (siem10: tat alert)</description>
  </rule>
  <rule id="31121" level="0" overwrite="yes">
    <if_sid>31120</if_sid>
    <id>^501</id>
    <description>Web server 501 error code (Not Implemented). (siem10: tat alert)</description>
  </rule>
  <rule id="31122" level="0" overwrite="yes">
    <if_sid>31120</if_sid>
    <id>^500</id>
    <description>Web server 500 error code (Internal Error). (siem10: tat alert)</description>
  </rule>
  <rule id="31123" level="0" overwrite="yes">
    <if_sid>31120</if_sid>
    <id>^503</id>
    <description>Web server 503 error code (Service unavailable). (siem10: tat alert)</description>
  </rule>
  <rule id="31151" level="0" frequency="14" timeframe="90" overwrite="yes">
    <if_matched_sid>31101</if_matched_sid>
    <same_source_ip />
    <description>Multiple web server 400 error codes from same source ip. (siem10: tat, bo nhom web_scan)</description>
    <group>recon,</group>
  </rule>
  <rule id="31161" level="0" frequency="14" timeframe="120" overwrite="yes">
    <if_matched_sid>31121</if_matched_sid>
    <same_source_ip />
    <description>Multiple web server 501 error code (Not Implemented). (siem10: tat, bo nhom web_scan)</description>
    <group>recon,</group>
  </rule>
  <rule id="31162" level="0" frequency="14" timeframe="120" overwrite="yes">
    <if_matched_sid>31122</if_matched_sid>
    <same_source_ip />
    <description>Multiple web server 500 error code (Internal Error). (siem10: tat)</description>
    <group>system_error,</group>
  </rule>
  <rule id="31163" level="0" frequency="14" timeframe="120" overwrite="yes">
    <if_matched_sid>31123</if_matched_sid>
    <same_source_ip />
    <description>Multiple web server 503 error code (Service unavailable). (siem10: tat, bo nhom web_scan)</description>
    <group>recon,</group>
  </rule>
"""


def xml(phase):
    body = PROBE_RULES + (OVERWRITE_B if phase == "B" else "")
    return ("<!-- TAM THOI - sig_probe.py tu xoa. Luat 1199xx chi khop srcip 192.0.2.0/24. -->\n"
            '<group name="siem10_sigprobe,">\n' + body + "</group>\n")


UA = "Mozilla/5.0 sigprobe"


def cl(ip, url, st, ua=UA):
    return f'{ip} - - [15/Nov/2026:08:00:00 +0000] "GET {url} HTTP/1.1" {st} 100 "-" "{ua}"'


def sl(i, ip, url, st):
    return f'SIEMLAB {int(time.time() * 1e6) + i} {ip} "GET {url} HTTP/1.1" {st} 10'


def single(rows):
    """rows: (nhãn, url, status[, ua]) -> mỗi dòng một IP riêng 192.0.2.10.. để không có luật tần suất nào chen vào."""
    out = []
    for k, r in enumerate(rows):
        lab, url, st = r[:3]
        out.append((lab, cl(f"192.0.2.{10 + k}", url, st, r[3] if len(r) > 3 else UA)))
    return out


SHELLSHOCK = "() { :; }; echo sigprobe"
CASES_A = {
    "syntax_g3": single([
        ("pcre2 (?i), 404", "/x?q=SP_PCRE", 404),
        ("pcre2 (?i), 200 có ?", "/x?q=sp_pcre", 200),
        ("G3 L8 vs 31105 L6", "/x?q=sp_g3a%3Cscript", 404),
        ("G3 L7 vs 31103 L7", "/x?q=sp_g3b+union%20select", 404),
        ("G3 L6 vs 31105 L6", "/x?q=sp_g3c%3Cscript", 404),
        ("G3 L5 vs 31101 L5", "/x?q=sp_g3d", 404),
        ("G3 L5 vs 31105 L6", "/x?q=sp_g3d%3Cscript", 404),
        ("G2 if_sid 31100, 200 không ?", "/sp_g2a/index.html", 200),
        ("G2 if_sid 31100, 301 không ?", "/sp_g2a", 301),
        ("G2 if_sid 31100, 200 có ?", "/sp_g2a?x=1", 200),
        ("G2 if_sid 31100, 200 %27 không ?", "/sp_g2a%27", 200),
        ("G2 if_sid 31100, 200 ../ không ?", "/sp_g2a/../index.html", 200),
        ("G2 if_sid 31100, 404 không ?", "/sp_g2a", 404),
        ("G2 if_sid 31100+31108, 200 không ?", "/sp_g2b/index.html", 200),
        ("G2 if_sid 31100+31108, 200 có ?", "/sp_g2b?x=1", 200),
        ("\\x3c khớp <", "/x?q=sp_hex<b", 404),
        ("\\x3c với %3C (không mong khớp)", "/x?q=sp_hex%3Cb", 404),
        ("\\x26 khớp &", "/x?a=sp_amp&z=1", 404),
        ("2 thẻ url: chỉ m1", "/x?q=sp_m1", 404),
        ("2 thẻ url: chỉ m2", "/x?q=sp_m2", 404),
        ("2 thẻ url: m1 ... m2", "/x?q=sp_m1&r=sp_m2", 404),
        ("2 thẻ url: m1m2 liền", "/x?q=sp_m1sp_m2", 404),
        ("pcre2 không (?i), chữ thường", "/x?q=sp_case", 404),
        ("pcre2 không (?i), chữ HOA", "/x?q=SP_CASE", 404),
        ("<url> với marker chỉ ở UA", "/x?q=1", 404, "sp_ua-agent"),
        ("url có \\\\ (Apache thoát \\)", "/x?q=sp_bs\\\\x", 404),
        ("url có \\\" (Apache thoát \")", '/x?q=a\\"b', 404),
        ("url có khoảng trắng thô", "/x?q=a b", 404),
        ("url %22 (dấu nháy mã hóa)", "/x?q=a%22b", 404),
        ("không luật thăm dò: 404 thường", "/khong_co", 404),
        ("không luật thăm dò: 200 thường", "/index.html", 200),
        ("không luật thăm dò: 500", "/x", 500),
        ("không luật thăm dò: Shellshock UA, 404", "/cgi-bin/a.cgi", 404, SHELLSHOCK),
    ]),
}


def g1_mix(st):
    ip, out = "192.0.2.200", []
    for i in range(30):
        out.append((f"SIEMLAB #{i + 1}", sl(i, ip, f"/g1_{st}_{i}", st)))
        out.append((f"combined #{i + 1}", cl(ip, f"/g1_{st}_{i}", st)))
    return out


def g1_only(st):
    return [(f"SIEMLAB #{i + 1}", sl(i, "192.0.2.201", f"/g1o_{st}_{i}", st)) for i in range(30)]


def combined_only(st, n=30):
    return [(f"combined #{i + 1}", cl("192.0.2.202", f"/co_{st}_{i}", st)) for i in range(n)]


CASES_A.update({"g1_siemlab_only_404": g1_only(404), "g1_mix_404": g1_mix(404), "g1_mix_401": g1_mix(401),
                "combined_only_404": combined_only(404)})
CASES_B = {"overwrite_single": CASES_A["syntax_g3"], "g1_mix_404": g1_mix(404), "g1_mix_401": g1_mix(401),
           "combined_only_404": combined_only(404), "combined_only_501": combined_only(501, 20)}


# ------------------------------------------------------------------ docker
def ex(args, inp=None, timeout=300):
    p = subprocess.run(["docker", "exec", "-i", C] + args, input=inp, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


def msgs():
    rc, out = ex([f"{BIN}/wazuh-analysisd", "-t"])
    return rc, sorted(set(re.findall(r"((?:WARNING|ERROR|CRITICAL): .*)", out))), out


def exists():
    return ex(["test", "-e", F])[0] == 0


def remove():
    ex(["rm", "-f", F])
    return not exists()


def logtest(lines):
    rc, out = ex([f"{BIN}/wazuh-logtest"], inp="".join(l + "\n" for l in lines), timeout=600)
    return parse(out), out


def short(r):
    if not r.get("decoder"):
        return "(không decoder)"
    s = f"{r.get('rule_id')} L{r.get('level')}" + ("" if r.get("alert") else " (không alert)")
    return s + f" [{r.get('decoder')}]"


# ------------------------------------------------------------------ main
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--phase", nargs="*", default=["A", "B"], choices=["A", "B"])
    ap.add_argument("--out", default=None); ap.add_argument("--cleanup", action="store_true")
    ap.add_argument("--print-xml", action="store_true", help="chỉ in file luật của từng pha, không đụng docker")
    a = ap.parse_args(argv)
    if a.print_xml:
        for ph in a.phase:
            print(f"===== pha {ph}\n{xml(ph)}")
        return 0
    if a.cleanup:
        ok = remove(); rc, m, _ = msgs()
        print(f"xóa {F}: {'OK' if ok else 'KHÔNG ĐƯỢC'}; analysisd -t rc={rc}, cảnh báo: {m or 'không'}")
        return 0 if ok else 1

    def stop(signum, frame):
        raise KeyboardInterrupt(f"signal {signum}")
    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(s, stop)

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = a.out or os.path.join(os.path.dirname(HERE), "runs", f"p1c_{ts}")
    os.makedirs(out, exist_ok=True)
    if exists():
        sys.exit(f"{F} đang tồn tại (lần chạy trước bị ngắt?) — chạy --cleanup trước, không ghi đè.")
    rc0, base, _ = msgs()
    print(f"analysisd -t trước khi thăm dò: rc={rc0}, cảnh báo: {base or 'không'}")
    if rc0 != 0:
        sys.exit("ruleset hiện tại không qua analysisd -t — dừng, không thăm dò.")
    res = {"started_utc": datetime.now(timezone.utc).isoformat(), "file": F, "baseline_messages": base, "phases": {}}
    try:
        for ph in a.phase:
            text = xml(ph)
            open(os.path.join(out, f"probe_{ph}.xml"), "w", encoding="utf-8").write(text)
            rc, o = ex(["sh", "-c", f"cat > {F} && chown wazuh:wazuh {F} && chmod 660 {F}"], inp=text)
            if rc != 0:
                raise RuntimeError(f"không ghi được {F}: {o[-300:]}")
            rc, m, raw = msgs()
            new = sorted(set(m) - set(base))
            P = res["phases"][ph] = {"analysisd_rc": rc, "new_messages": new, "cases": {}}
            print(f"\n===== PHA {ph}: analysisd -t rc={rc}, cảnh báo MỚI: {new or 'không'}")
            if rc != 0:
                open(os.path.join(out, f"analysisd_{ph}.txt"), "w", encoding="utf-8").write(raw)
                print("  analysisd -t lỗi -> bỏ pha này"); continue
            for name, feed in (CASES_A if ph == "A" else CASES_B).items():
                parsed, raw = logtest([l for _, l in feed])
                open(os.path.join(out, f"raw_{ph}_{name}.txt"), "w", encoding="utf-8").write(raw)
                rows = []
                for k, (lab, line) in enumerate(feed):
                    r = parsed[k] if k < len(parsed) else {}
                    rows.append({"label": lab, "line": line, **{x: r.get(x) for x in
                                 ("decoder", "url", "status", "rule_id", "level", "description", "groups", "alert")}})
                P["cases"][name] = {"n_lines": len(feed), "n_parsed": len(parsed), "rows": rows}
                print(f"\n-- {ph}/{name} ({len(parsed)}/{len(feed)} khối)")
                if name.startswith(("g1_", "combined_only")):
                    hits = [(row["label"], row["rule_id"], row["level"]) for row in rows
                            if row["rule_id"] not in ("100012", "100011", "31101", "31121") and row["rule_id"]]
                    base_ids = sorted({row["rule_id"] for row in rows if row["rule_id"]})
                    print(f"   rule xuất hiện: {base_ids}")
                    print(f"   dòng khác luật cơ sở: {hits or 'không có'}")
                    print(f"   số dòng có alert: {sum(1 for row in rows if row['alert'])}/{len(rows)}")
                else:
                    for row in rows:
                        print(f"   {row['label']:<40} -> {short(row)}  url={row['url']!r}")
    except KeyboardInterrupt as e:
        print(f"\n!! bị ngắt ({e}) — dọn file tạm"); res["interrupted"] = str(e)
    except Exception as e:
        print(f"\n!! lỗi: {e} — dọn file tạm"); res["error"] = str(e)
    finally:
        ok = remove()
        rc, m, _ = msgs()
        res["cleanup"] = {"file_removed": ok, "analysisd_rc": rc, "messages": m, "back_to_baseline": m == base and rc == 0}
        res["ended_utc"] = datetime.now(timezone.utc).isoformat()
        json.dump(res, open(os.path.join(out, "result.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
        print(f"\nDỌN: file tạm {'đã xóa' if ok else 'CÒN — chạy --cleanup'}; analysisd -t rc={rc}; "
              f"{'trở về đúng cảnh báo ban đầu' if res['cleanup']['back_to_baseline'] else 'KHÁC ban đầu: ' + str(m)}")
        print(f"-> {out}/result.json")
    return 0 if res["cleanup"]["back_to_baseline"] and ok else 1


if __name__ == "__main__":
    sys.exit(main())
