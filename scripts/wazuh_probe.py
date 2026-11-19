#!/usr/bin/env python3
"""wazuh_probe.py — đo NGỮ NGHĨA THẬT của luật tần suất trên Wazuh Manager đang chạy, bằng wazuh-logtest.

Chạy trên HOST (cần docker), từ thư mục project:   python3 scripts/wazuh_probe.py
Không restart Manager, không đụng local_rules.xml. Cách làm:
  1. Ghi TẠM file /var/ossec/etc/rules/zz_siem10_probe.xml (trong container manager) chứa vài luật thăm dò id 1199xx,
     chỉ khớp srcip 192.0.2.0/24 (TEST-NET, không bao giờ có trong traffic lab).
  2. `wazuh-analysisd -t` kiểm cú pháp.
  3. Mỗi ca = MỘT phiên wazuh-logtest (trạng thái đếm riêng): bơm dòng SIEMLAB giả qua stdin, có thể chờ giữa các dòng
     (logtest dùng giờ hiện tại làm thời điểm sự kiện), rồi đọc rule nào khớp ở từng dòng.
  4. LUÔN xóa file thăm dò (kể cả khi lỗi / Ctrl+C) và kiểm cú pháp lại.
Ghi kết quả ra output/wazuh_probe_<giờ>.json + in bảng. Điều cần biết trước khi tin mô phỏng luật offline:
  - luật frequency=N khớp ở sự kiện thứ mấy, và có khớp LẶP LẠI ở các sự kiện sau không;
  - sự kiện đã thành alert luật con (1199xx) có còn được đếm cho lần sau không;
  - same_srcip tách đếm theo IP;  timeframe tính theo giờ Manager nhận (chờ > timeframe thì đếm lại);
  - different_url: chỉ so với sự kiện hiện tại hay đòi URL khác nhau đôi một;
  - logtest có nạp file rule mới mà không cần restart không (nếu luật thăm dò không bao giờ khớp -> KHÔNG kết luận được).
"""
import argparse, json, os, re, subprocess, sys, time
from datetime import datetime

PROJECT = os.environ.get("SIEM_PROJECT", "siem10")
SVC = os.environ.get("MANAGER_SVC", "wazuh.manager")
COMPOSE = ["docker", "compose", "-p", PROJECT]
PROBE = "/var/ossec/etc/rules/zz_siem10_probe.xml"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NET = "192.0.2."

RULES = """<!-- TẠM THỜI — wazuh_probe.py tự xóa. Chỉ khớp srcip 192.0.2.0/24 (TEST-NET), mỗi cặp luật một dải riêng. -->
<group name="siem10_probe,">
  <rule id="119901" level="3" frequency="{n}" timeframe="{tf}">
    <if_matched_sid>100012</if_matched_sid>
    <same_srcip />
    <srcip>192.0.2.0/27</srcip>
    <description>probe: 404 x{n} / {tf}s cung srcip</description>
  </rule>
  <rule id="119902" level="3" frequency="{n}" timeframe="{tf}">
    <if_matched_sid>100011</if_matched_sid>
    <same_srcip />
    <different_url />
    <srcip>192.0.2.0/27</srcip>
    <description>probe: 401 x{n} / {tf}s cung srcip, different_url</description>
  </rule>
  <!-- tương tác (2b-2): luật đếm theo NHÓM web_scan (403/404) và luật đếm theo nhóm siemlab_observed (mọi mã) cùng
       thấy một chuỗi 404. Cặp 1 (192.0.2.64/28): web_scan đứng TRƯỚC; cặp 2 (192.0.2.96/28): mọi mã đứng TRƯỚC. -->
  <rule id="119903" level="10" frequency="3" timeframe="{tf}">
    <if_matched_group>web_scan</if_matched_group>
    <same_srcip />
    <srcip>192.0.2.64/28</srcip>
    <description>probe: web_scan x3 (cap 1, dung truoc)</description>
  </rule>
  <rule id="119904" level="10" frequency="5" timeframe="{tf}">
    <if_matched_group>siemlab_observed</if_matched_group>
    <same_srcip />
    <srcip>192.0.2.64/28</srcip>
    <description>probe: moi ma x5 (cap 1, dung sau)</description>
  </rule>
  <rule id="119906" level="10" frequency="5" timeframe="{tf}">
    <if_matched_group>siemlab_observed</if_matched_group>
    <same_srcip />
    <srcip>192.0.2.96/28</srcip>
    <description>probe: moi ma x5 (cap 2, dung truoc)</description>
  </rule>
  <rule id="119905" level="10" frequency="3" timeframe="{tf}">
    <if_matched_group>web_scan</if_matched_group>
    <same_srcip />
    <srcip>192.0.2.96/28</srcip>
    <description>probe: web_scan x3 (cap 2, dung sau)</description>
  </rule>
</group>
"""
INTERACTION = {"interact_scan_first": ("119903", "119904"), "interact_any_first": ("119905", "119906")}


def sh(args, inp=None, timeout=120):
    p = subprocess.run(COMPOSE + ["exec", "-T", SVC] + args, input=inp, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


def line(i, ip, url, st):
    return f'SIEMLAB {int(time.time() * 1e6) + i} {ip} "GET {url} HTTP/1.1" {st} 10'


def logtest(feed):
    """feed: list (dòng, giây chờ TRƯỚC dòng). Trả list rule id khớp theo thứ tự dòng (None nếu không alert/không đọc được)."""
    p = subprocess.Popen(COMPOSE + ["exec", "-T", SVC, "/var/ossec/bin/wazuh-logtest"], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for ln, wait in feed:
        if wait: time.sleep(wait)
        p.stdin.write(ln + "\n"); p.stdin.flush()
    time.sleep(2)
    out, _ = p.communicate(timeout=120)
    blocks = out.split("**Phase 1: Completed pre-decoding.")[1:]
    ids = []
    for b in blocks:
        m = re.search(r"\*\*Phase 3: Completed filtering \(rules\)\.\s*\n\s*id: '(\d+)'", b)
        ids.append(m.group(1) if m else None)
    return ids, out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, default=3, help="frequency của luật thăm dò")
    ap.add_argument("--tf", type=int, default=8, help="timeframe (giây) của luật thăm dò")
    ap.add_argument("--cases", nargs="*", default=None, help="chỉ chạy các ca này (mặc định: tất cả)")
    ap.add_argument("--allow-with-ai-rules", action="store_true",
                    help="vẫn chạy khi đang có file luật AI (luật AI không giới hạn IP có thể khớp cả dòng thăm dò)")
    a = ap.parse_args()
    n, tf = a.n, a.tf
    A, B = NET + "10", NET + "20"
    cases = {
        # tên: (mô tả, feed, rule kỳ vọng nếu luật "đếm N sự kiện cha cùng IP trong tf giây")
        "fire_index": ("404 liên tục, cùng IP, URL khác nhau: khớp ở sự kiện thứ mấy, có lặp lại không",
                       [(line(i, A, f"/p{i}", 404), 0) for i in range(2 * n + 2)]),
        "same_srcip": ("404 xen kẽ 2 IP: mỗi IP có đếm riêng không",
                       [(line(i, A if i % 2 == 0 else B, f"/q{i}", 404), 0) for i in range(2 * n + 2)]),
        "timeframe": (f"n-1 sự kiện, chờ {tf + 3}s (> timeframe), rồi thêm sự kiện: có còn khớp ngay không",
                      [(line(i, A, f"/t{i}", 404), 0) for i in range(n - 1)]
                      + [(line(100, A, "/t100", 404), tf + 3)] + [(line(101 + i, A, f"/t{101 + i}", 404), 0) for i in range(n)]),
        "different_url_same": ("401 lặp CÙNG một URL (different_url): có khớp không",
                               [(line(i, A, "/private/", 401), 0) for i in range(2 * n + 2)]),
        "different_url_cycle": ("401 xoay vòng 2 URL (different_url): khớp không -> nếu có thì KHÔNG đòi URL khác đôi một",
                                [(line(i, A, f"/u{i % 2}", 401), 0) for i in range(2 * n + 4)]),
        # 22 dòng 404: nếu hai luật độc lập, web_scan (N=3) khớp ở 3,6,9,...,21 và mọi mã (N=5) ở 5,10,15,20; dòng 15
        # cả hai cùng muốn khớp -> xem luật nào thắng và luật thua có "đếm lại" hay khớp bù ở dòng sau
        "interact_scan_first": ("404 x22: luật nhóm web_scan (N=3, đứng trước) và luật mọi mã (N=5, đứng sau)",
                                [(line(i, NET + "70", f"/i{i}", 404), 0) for i in range(22)]),
        "interact_any_first": ("404 x22: luật mọi mã (N=5, đứng trước) và luật nhóm web_scan (N=3, đứng sau)",
                               [(line(i, NET + "100", f"/j{i}", 404), 0) for i in range(22)]),
        # xen 200 với 404: luật mọi mã đếm cả 200, luật web_scan chỉ đếm 404
        "interact_mixed": ("200/404 xen kẽ x20: web_scan chỉ đếm 404, mọi mã đếm cả hai",
                           [(line(i, NET + "71", f"/m{i}", 404 if i % 2 else 200), 0) for i in range(20)]),
    }
    if a.cases:
        cases = {k: v for k, v in cases.items() if k in a.cases}
    rc_ai, _ = sh(["test", "-e", "/var/ossec/etc/rules/zz_siem10_ai_rules.xml"])
    if rc_ai == 0 and not a.allow_with_ai_rules:
        sys.exit("Đang có file luật AI (zz_siem10_ai_rules.xml): luật AI không giới hạn IP nên có thể khớp cả dòng thăm dò "
                 "và làm sai kết quả. Chạy probe TRƯỚC khi áp luật AI, hoặc thêm --allow-with-ai-rules nếu biết mình làm gì.")
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    res = {"created": ts, "project": PROJECT, "frequency": n, "timeframe": tf, "cases": {}}
    rc, out = sh(["/var/ossec/bin/wazuh-control", "info"])
    res["wazuh_info"] = out.strip()[:500]
    try:
        rc, out = sh(["sh", "-c", f"cat > {PROBE} && chown wazuh:wazuh {PROBE} 2>/dev/null; chmod 660 {PROBE}"],
                     inp=RULES.format(n=n, tf=tf))
        if rc != 0: sys.exit(f"Không ghi được {PROBE}: {out}")
        rc, out = sh(["/var/ossec/bin/wazuh-analysisd", "-t"])
        res["analysisd_t_with_probe"] = {"rc": rc, "out": out.strip()[-800:]}
        if rc != 0:
            print(out); sys.exit("Luật thăm dò sai cú pháp (đã xóa file). Dừng.")
        for name, (desc, feed) in cases.items():
            t0 = time.time()
            ids, raw = logtest(feed)
            res["cases"][name] = {"desc": desc, "ips": [ln.split()[2] for ln, _ in feed], "urls": [ln.split()[4] for ln, _ in feed],
                                  "rule_ids": ids, "n_lines": len(feed), "n_blocks": len(ids), "seconds": round(time.time() - t0, 1)}
            if len(ids) != len(feed):
                res["cases"][name]["raw_tail"] = raw[-1500:]
            print(f"\n[{name}] {desc}")
            for k, ((ln, w), rid) in enumerate(zip(feed, ids + [None] * (len(feed) - len(ids))), 1):
                print(f"  {k:2d}. {'(chờ %ds) ' % w if w else ''}{ln.split()[2]:12s} {ln.split()[4]:12s} {ln.split()[5]} -> {rid}")
            if name in INTERACTION or name == "interact_mixed":
                pair = INTERACTION.get(name, ("119903", "119904"))
                for r in pair:
                    pos = [k + 1 for k, x in enumerate(ids) if x == r]
                    res["cases"][name].setdefault("fired", {})[r] = pos
                    print(f"     luật {r} khớp ở dòng: {pos}")
    finally:
        sh(["rm", "-f", PROBE])
        rc, out = sh(["/var/ossec/bin/wazuh-analysisd", "-t"])
        res["analysisd_t_after_cleanup"] = {"rc": rc, "probe_file_removed": sh(["test", "-e", PROBE])[0] != 0}
        os.makedirs(os.path.join(ROOT, "output"), exist_ok=True)
        fn = os.path.join(ROOT, "output", f"wazuh_probe_{ts}.json")
        try:
            json.dump(res, open(fn, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
            print(f"\nĐã xóa file thăm dò: {res['analysisd_t_after_cleanup']['probe_file_removed']}; "
                  f"analysisd -t sau khi xóa: rc={rc}. Kết quả: {os.path.relpath(fn, ROOT)}")
        except OSError as e:
            print(f"Không ghi được kết quả ({e}); dùng: sudo chown -R $USER output")
    if not any(r in (c["rule_ids"]) for c in res["cases"].values() for r in ("119901", "119902")):
        print("\nCẢNH BÁO: luật thăm dò KHÔNG khớp ở ca nào -> có thể wazuh-logtest không nạp file rule mới khi chưa "
              "restart. Không kết luận gì về ngữ nghĩa; báo lại để đổi cách đo.")


if __name__ == "__main__":
    main()
