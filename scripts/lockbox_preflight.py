#!/usr/bin/env python3
"""lockbox_preflight.py — kiểm điều kiện hợp lệ TRƯỚC khi chạy lockbox (docs/LOCKBOX_PREREG.md mục 4). Không đổi gì.

  python3 scripts/lockbox_preflight.py [--batch-id lockbox1] [--idle-minutes 5] [--idle-cpu 20]
  -> output/lockbox_preflight_<giờ>.json ; mã thoát 0 chỉ khi MỌI điều kiện đạt.

Chạy trên HOST (cần docker). Kiểm theo thứ tự:
  1. bản kê code + cấu hình trùng docs/lockbox_manifest.json (model, file luật AI, cấu hình manager, code);
  2. data/.lockbox_seed CHƯA tồn tại (chưa ai sinh/xem seed) và data/runs/<batch-id> chưa có;
  3. đề xuất 'applied' đúng bộ trong bản kê; apply_rule sync trùng; apply_rule health ĐẠT;
  4. ossec.conf ĐANG CHẠY trong manager: vulnerability-detection tắt, syscollector tắt;
  5. ai-service đang chạy, lệnh dùng models/full1/model.joblib + --op fp5, khởi động SAU lần ghi model;
  6. không có container lab nào đang chạy (không batch nào khác);
  7. Manager nhàn rỗi: CPU container < ngưỡng ở MỌI mẫu trong N phút liên tục (đo cuối cùng, mẫu mỗi 10 s).
"""
import argparse, json, os, re, subprocess, sys, time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import lockbox_manifest as LM

MGR = "siem10-wazuh.manager-1"


def sh(cmd, timeout=600):
    p = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, timeout=timeout, cwd=ROOT)
    return p.returncode, (p.stdout + p.stderr).strip()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--batch-id", default="lockbox1")
    ap.add_argument("--idle-minutes", type=float, default=5.0); ap.add_argument("--idle-cpu", type=float, default=20.0)
    ap.add_argument("--interval", type=float, default=10.0)
    a = ap.parse_args(argv)
    R = {"created": datetime.now().astimezone().isoformat(timespec="seconds"), "batch_id": a.batch_id, "checks": []}

    def rec(name, ok, detail):
        R["checks"].append({"check": name, "ok": bool(ok), "detail": detail})
        print(f"[{'ĐẠT' if ok else 'KHÔNG ĐẠT':9s}] {name}: {detail if isinstance(detail, str) else json.dumps(detail, ensure_ascii=False)}")
        return ok

    # 1
    if os.path.exists(LM.OUT):
        saved = json.load(open(LM.OUT, encoding="utf-8")); cur = LM.build(); d = LM.compare(saved, cur)
        rec("1. bản kê code + cấu hình", not d, f"digest {cur['digest']}" if not d else d[:20])
        R["manifest_digest"] = cur["digest"]
    else:
        saved = None; rec("1. bản kê code + cấu hình", False, "chưa có docs/lockbox_manifest.json (chưa chốt PREREG)")
    # 2
    seed = os.path.join(ROOT, "data", ".lockbox_seed"); bdir = os.path.join(ROOT, "data", "runs", a.batch_id)
    rec("2. seed lockbox chưa tồn tại", not os.path.exists(seed), seed if os.path.exists(seed) else "chưa có (đúng)")
    rec("2b. batch chưa có", not os.path.exists(bdir), bdir if os.path.exists(bdir) else "chưa có (đúng)")
    # 3
    applied = LM.applied_proposals()
    want = saved["applied_proposals"] if saved else None
    rec("3. đề xuất 'applied' đúng bộ đã khóa", want is not None and applied == want, {"đang": applied, "khóa": want})
    rc, out = sh([sys.executable, "scripts/apply_rule.py", "sync"])
    rec("3b. apply_rule sync", rc == 0 and "trùng nhau" in out, out.splitlines()[-1] if out else rc)
    rc, out = sh([sys.executable, "scripts/apply_rule.py", "health"])
    rec("3c. apply_rule health", rc == 0 and "ĐẠT" in out and "KHÔNG ĐẠT" not in out, out.splitlines()[-1] if out else rc)
    # 4
    rc, conf = sh(["docker", "exec", MGR, "cat", "/var/ossec/etc/ossec.conf"])
    vd = re.search(r"<vulnerability-detection>\s*<enabled>(\w+)</enabled>", conf or "")
    sc = re.search(r'<wodle name="syscollector">\s*<disabled>(\w+)</disabled>', conf or "")
    rec("4. ossec.conf đang chạy", rc == 0 and vd and vd.group(1) == "no" and sc and sc.group(1) == "yes",
        {"vulnerability-detection enabled": vd and vd.group(1), "syscollector disabled": sc and sc.group(1)})
    # 5
    rc, st = sh(["docker", "inspect", "-f", "{{.State.Running}}|{{.State.StartedAt}}|{{json .Config.Cmd}}", "ai-service"])
    ok5, det5 = False, st
    if rc == 0:
        running, started, cmd = st.split("|", 2)
        mt = os.path.getmtime(os.path.join(ROOT, "models", "full1", "model.joblib"))
        try:
            st_ts = datetime.fromisoformat(re.sub(r"\.(\d{6})\d*", r".\1", started.replace("Z", "+00:00"))).timestamp()
        except ValueError:
            st_ts = 0
        ok5 = running == "true" and "models/full1/model.joblib" in cmd and "fp5" in cmd and st_ts > mt
        det5 = {"running": running, "started": started, "model_mtime": datetime.fromtimestamp(mt).isoformat(timespec="seconds"),
                "khởi động sau khi ghi model": st_ts > mt, "cmd": cmd}
    rec("5. ai-service", ok5, det5)
    # 6
    rc, ps = sh("docker ps --format '{{.Names}}' | grep -E 'lab-run' || true")
    rec("6. không batch nào đang chạy", ps.strip() == "", ps.strip() or "không có container lab")
    # 7
    n = max(1, int(round(a.idle_minutes * 60 / a.interval))); samples = []
    print(f"... đo CPU manager {n} mẫu / {a.idle_minutes:g} phút")
    for i in range(n):
        t0 = time.time()
        rc, v = sh(["docker", "stats", "--no-stream", "--format", "{{.CPUPerc}}", MGR], timeout=60)
        try:
            samples.append(float(v.strip().rstrip("%")))
        except ValueError:
            samples.append(float("nan"))
        time.sleep(max(0.0, a.interval - (time.time() - t0)))
    ok7 = all(x == x and x < a.idle_cpu for x in samples)
    rec(f"7. Manager nhàn rỗi (< {a.idle_cpu:g}% mọi mẫu)", ok7, {"max": max(samples), "mean": round(sum(samples) / len(samples), 2), "samples": samples})
    R["passed"] = all(c["ok"] for c in R["checks"])
    os.makedirs(os.path.join(ROOT, "output"), exist_ok=True)
    fn = os.path.join(ROOT, "output", f"lockbox_preflight_{datetime.now():%Y%m%d-%H%M%S}.json")
    json.dump(R, open(fn, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print(f"\nTỔNG: {'ĐẠT — được chạy lockbox' if R['passed'] else 'KHÔNG ĐẠT — KHÔNG chạy lockbox'}  -> {os.path.relpath(fn, ROOT)}")
    return 0 if R["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
