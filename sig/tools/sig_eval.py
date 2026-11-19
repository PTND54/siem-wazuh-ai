#!/usr/bin/env python3
"""sig_eval.py — đo bộ luật trên Manager thật bằng wazuh-logtest, hai cấu hình:
  base = ruleset đang chạy (luật dựng sẵn nguyên vẹn, CHƯA có file luật chữ ký)
  sig  = thêm TẠM file luật chữ ký (biến thể thăm dò: mọi luật 1001xx kèm srcip 192.0.2.0/24; phần overwrite cách 2 như pha B
         của sig_probe.py) ở /var/ossec/etc/rules/zy_siem10_sigeval.xml -> logtest -> LUÔN xóa -> analysisd -t về ban đầu.

Chạy trên HOST (WSL, cần docker):
  python3 -B sig_eval.py --rules ../rules/probe_zy_siem10_sig_rules.xml --out ../runs/<tên lần chạy> \
      --input dev=../runs/p3a_dev/access_log.txt benign_dev=../runs/p3a_benign_dev/access_log.txt \
              regress=../runs/p3_regress/gen_distinct_access.log
  python3 -B sig_eval.py --cleanup

Mỗi khối 254 dòng = một phiên logtest; dòng thứ k của khối mang IP 192.0.2.(k+1) (mỗi dòng một IP, không luật tần suất nào
chen vào). KHÔNG khởi động lại tiến trình nào; analysisd đang chạy không nạp file tạm.
Kết quả: <out>/<cấu hình>_<tên>.jsonl (mỗi dòng: n, line, decoder, url, status, rule_id, level, alert, groups) + summary.json
"""
import argparse, json, os, re, signal, sys, time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
from replay_logtest import parse  # noqa: E402
from sig_probe import ex, msgs, C, BIN  # noqa: E402

F = "/var/ossec/etc/rules/zy_siem10_sigeval.xml"
CHUNK = 254


def exists():
    return ex(["test", "-e", F])[0] == 0


def remove():
    ex(["rm", "-f", F]); return not exists()


def replay(path, out_jsonl):
    raw = open(path, "rb").read().split(b"\n")
    items = [(n, b.decode("ascii")) for n, b in enumerate(raw, 1)
             if b.strip() and all(0x20 <= c <= 0x7e for c in b)]
    skipped = sum(1 for b in raw if b.strip()) - len(items)
    t0, bad = time.time(), 0
    with open(out_jsonl, "w", encoding="utf-8") as fo:
        for c0 in range(0, len(items), CHUNK):
            part = items[c0:c0 + CHUNK]
            sent = [re.sub(r"^\S+", f"192.0.2.{k + 1}", ln, count=1) for k, (n, ln) in enumerate(part)]
            rc, out = ex([f"{BIN}/wazuh-logtest"], inp="".join(s + "\n" for s in sent), timeout=900)
            res = parse(out)
            if len(res) != len(sent):
                bad += 1
                res = []
                for s in sent:
                    r = parse(ex([f"{BIN}/wazuh-logtest"], inp=s + "\n")[1])
                    res.append(r[0] if len(r) == 1 else {"error": "parse"})
            for (n, ln), r in zip(part, res):
                r = dict(r); r.pop("full_event", None); r.update(n=n, line=ln)
                fo.write(json.dumps(r, ensure_ascii=False) + "\n")
    return {"lines": len(items), "skipped_non_ascii": skipped, "chunks_resent": bad, "seconds": round(time.time() - t0, 1)}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rules"); ap.add_argument("--out"); ap.add_argument("--input", nargs="*", default=[])
    ap.add_argument("--configs", nargs="*", default=["base", "sig"], choices=["base", "sig", "builtin"],
                    help="builtin: khi bộ luật chữ ký ĐÃ CÀI, ghi tạm file vô hiệu hóa các luật 1001xx (overwrite, mẫu không thể khớp) "
                         "để đo riêng luật dựng sẵn")
    ap.add_argument("--cleanup", action="store_true")
    a = ap.parse_args()
    if a.cleanup:
        ok = remove(); rc, m, _ = msgs(); print(f"xóa {F}: {'OK' if ok else 'KHÔNG ĐƯỢC'}; analysisd -t rc={rc}, {m or 'không cảnh báo'}")
        return 0 if ok else 1
    inputs = [x.split("=", 1) for x in a.input]
    rules = open(a.rules, encoding="utf-8").read() if "sig" in a.configs else None
    if rules is not None and "<srcip>192.0.2.0/24</srcip>" not in rules:
        sys.exit("file luật không phải biến thể thăm dò (thiếu srcip 192.0.2.0/24) — dùng probe_zy_siem10_sig_rules.xml")
    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(s, lambda n, f: (_ for _ in ()).throw(KeyboardInterrupt(f"signal {n}")))
    os.makedirs(a.out, exist_ok=True)
    if exists():
        sys.exit(f"{F} đang tồn tại — chạy --cleanup trước")
    rc0, base, _ = msgs()
    if rc0 != 0:
        sys.exit("analysisd -t lỗi trên ruleset hiện tại — dừng")
    summ = {"started_utc": datetime.now(timezone.utc).isoformat(), "baseline_messages": base, "runs": {}}
    try:
        if "base" in a.configs:
            for name, path in inputs:
                summ["runs"][f"base_{name}"] = r = replay(path, os.path.join(a.out, f"base_{name}.jsonl")); print("base", name, r, flush=True)
        if "builtin" in a.configs:
            sys.path.insert(0, HERE); import sig_rules_gen as G
            neut = "<!-- TAM THOI - sig_eval.py: vo hieu hoa luat nhom de do rieng luat dung san -->\n<group name=\"siem10_sigeval,\">\n" + "".join(
                f'  <rule id="{rid}" level="8" overwrite="yes">\n    <if_sid>31100,31108</if_sid>\n'
                f'    <url type="pcre2">^SIEM10_SIGEVAL_KHONG_BAO_GIO_KHOP$</url>\n    <description>tam tat {rid}</description>\n  </rule>\n'
                for rid, _, _, _ in G.RULES) + "</group>\n"
            open(os.path.join(a.out, "neutralizer_used.xml"), "w", encoding="utf-8").write(neut)
            rc, o = ex(["sh", "-c", f"cat > {F} && chown wazuh:wazuh {F} && chmod 660 {F}"], inp=neut)
            if rc != 0:
                raise RuntimeError(o[-300:])
            rc, m, raw = msgs(); new = sorted(set(m) - set(base))
            summ["builtin_analysisd"] = {"rc": rc, "new_messages": new}
            print(f"analysisd -t với file vô hiệu hóa: rc={rc}, cảnh báo MỚI: {new or 'không'}", flush=True)
            if rc != 0 or new:
                raise RuntimeError("file vô hiệu hóa có lỗi/cảnh báo — không đo")
            for name, path in inputs:
                summ["runs"][f"base_{name}"] = r = replay(path, os.path.join(a.out, f"base_{name}.jsonl")); print("builtin(base)", name, r, flush=True)
            remove()
        if "sig" in a.configs:
            open(os.path.join(a.out, "rules_used.xml"), "w", encoding="utf-8").write(rules)
            rc, o = ex(["sh", "-c", f"cat > {F} && chown wazuh:wazuh {F} && chmod 660 {F}"], inp=rules)
            if rc != 0:
                raise RuntimeError(o[-300:])
            rc, m, raw = msgs(); new = sorted(set(m) - set(base))
            summ["sig_analysisd"] = {"rc": rc, "new_messages": new}
            print(f"analysisd -t với file luật chữ ký: rc={rc}, cảnh báo MỚI: {new or 'không'}", flush=True)
            if rc != 0 or new:
                open(os.path.join(a.out, "analysisd_sig.txt"), "w", encoding="utf-8").write(raw)
                raise RuntimeError("file luật có lỗi/cảnh báo — không đo")
            for name, path in inputs:
                summ["runs"][f"sig_{name}"] = r = replay(path, os.path.join(a.out, f"sig_{name}.jsonl")); print("sig", name, r, flush=True)
    except KeyboardInterrupt as e:
        print(f"!! ngắt: {e}"); summ["interrupted"] = str(e)
    except Exception as e:
        print(f"!! lỗi: {e}"); summ["error"] = str(e)
    finally:
        ok = remove(); rc, m, _ = msgs()
        summ["cleanup"] = {"file_removed": ok, "rc": rc, "back_to_baseline": rc == 0 and m == base}
        summ["ended_utc"] = datetime.now(timezone.utc).isoformat()
        json.dump(summ, open(os.path.join(a.out, "summary.json"), "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        print(f"DỌN: {'đã xóa' if ok else 'CÒN — chạy --cleanup'}; analysisd -t rc={rc}; "
              f"{'trở về đúng ban đầu' if summ['cleanup']['back_to_baseline'] else 'KHÁC ban đầu'}")
    return 0 if summ["cleanup"]["back_to_baseline"] and "error" not in summ else 1


if __name__ == "__main__":
    sys.exit(main())
