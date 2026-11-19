#!/usr/bin/env python3
"""tool_run.py — chạy MỘT công cụ thật (nmap, nikto, dirb, hydra, ab...) từ container có IP riêng và ghi manifest.

Dùng qua setup/run_tools.sh (mỗi lần một `docker run --ip <IP>` để srcip khác nhau). Nhãn là Ý ĐỊNH của spec:
nmap/nikto/dirb/gobuster/hydra/ab-flood = malicious; wget-mirror/curl-loop/ab-light = benign. Riêng ab (cùng một
công cụ) vừa là flood vừa là load-test nhẹ: đó là CỐ Ý (ca nhập nhằng), và là hạn chế của việc gán nhãn theo ý định.

Tập này dùng để ĐÁNH GIÁ độ tổng quát hóa sang công cụ chưa thấy (leave-tool-out), không phải để huấn luyện chính.
"""
import argparse, json, os, shlex, shutil, socket, subprocess, sys, time

WL = "/usr/share/dirb/wordlists/common.txt"
PASSFILE = "/tmp/pass300.txt"


def specs(host):
    u = f"http://{host}"
    return {
        # ---- malicious ----
        "nmap_httpenum_T4": (1, "recon", ["nmap", "-Pn", "-p", "80", "-T4", "--script", "http-enum", host], 300),
        "nmap_httpenum_T2": (1, "recon", ["nmap", "-Pn", "-p", "80", "-T2", "--script", "http-enum", host], 900),
        "nikto": (1, "recon", ["nikto", "-h", u, "-maxtime", "180s", "-nointeractive"], 240),
        "dirb_default": (1, "recon", ["dirb", u + "/", WL, "-S", "-w"], 300),
        "dirb_slow": (1, "recon", ["dirb", u + "/", WL, "-S", "-w", "-z", "400"], 300),
        "gobuster": (1, "recon", ["gobuster", "dir", "-u", u, "-w", WL, "-t", "10", "-q", "--no-error"], 300),
        "ffuf": (1, "recon", ["ffuf", "-u", u + "/FUZZ", "-w", WL, "-s", "-t", "20"], 300),
        "hydra_t4": (1, "cred", ["hydra", "-l", "student", "-P", PASSFILE, "-t", "4", "-s", "80", host, "http-get", "/private/"], 300),
        "hydra_t1_slow": (1, "cred", ["hydra", "-l", "student", "-P", PASSFILE, "-t", "1", "-w", "3", "-s", "80", host, "http-get", "/private/"], 900),
        # ab không giới hạn tốc độ (có thể > 1000 rps): vượt eps agent, dựa vào queue_size 20000 của agent để không rơi;
        # audit_coverage.py --alerts phải xác nhận số alert ~ số dòng siem.log cho các phiên này.
        "ab_flood": (1, "flood", ["ab", "-n", "6000", "-c", "50", u + "/index.html"], 180),
        "ab_flood_keepalive": (1, "flood", ["ab", "-k", "-n", "8000", "-c", "20", u + "/index.html"], 180),
        # ---- benign ----
        "wget_mirror": (0, "benign", ["wget", "-q", "-r", "-l", "2", "-np", "-nd", "-P", "/tmp/mirror", "--wait=0.3", "--random-wait", u + "/index.html"], 600),
        # bash (không phải sh/dash): dash không có $RANDOM -> mọi request sẽ là p-0000
        "curl_loop_1s": (0, "benign", ["bash", "-c", f"for i in $(seq 1 90); do curl -s -o /dev/null {u}/products/p-$(printf %04d $((RANDOM%300))).html; sleep 1; done"], 200),
        "curl_login_typos": (0, "benign", ["sh", "-c", f"for p in x y z; do curl -s -o /dev/null -u student:$p {u}/private/; sleep 2; done; curl -s -o /dev/null -u student:LabOnly-2026 {u}/private/"], 60),
        "ab_light": (0, "benign", ["ab", "-n", "300", "-c", "2", u + "/index.html"], 120),
    }


VERSION_ARGS = {"nmap": ["--version"], "hydra": ["-h"], "nikto": ["-Version"], "gobuster": ["version"], "ffuf": ["-V"],
                "wget": ["--version"], "curl": ["--version"], "ab": ["-V"], "dirb": []}


def tool_version(binary):
    """Dòng đầu chứa phiên bản (để ghi provenance). Không bao giờ làm hỏng lần chạy."""
    if binary not in VERSION_ARGS: return None
    try:
        r = subprocess.run([binary] + VERSION_ARGS[binary], capture_output=True, text=True, timeout=15)
        for line in (r.stdout + "\n" + r.stderr).splitlines():
            if any(ch.isdigit() for ch in line): return line.strip()[:100]
    except Exception:
        pass
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", required=True); ap.add_argument("--target", default="apache-target")
    ap.add_argument("--out", default="data/runs/tools"); ap.add_argument("--rep", type=int, default=0)
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    sp = specs(a.target)
    if a.list:
        for k, (lab, fam, argv, to) in sp.items(): print(f"{k:22s} label={lab} {fam:6s} {shlex.join(argv)[:90]}")
        return
    label, fam, argv, timeout = sp[a.spec]
    os.makedirs(a.out, exist_ok=True)
    if not os.path.exists(PASSFILE):
        open(PASSFILE, "w").write("\n".join(f"wrong-pass-{i:03d}" for i in range(300)) + "\n")
    run_id = f"tool_{a.spec}_{a.rep:02d}"
    row = {"run_id": run_id, "scenario": a.spec, "family": fam, "label": label, "split": "tools", "kind": "real_tool",
           "argv": argv, "srcip": socket.gethostbyname(socket.gethostname()), "rep": a.rep}
    if shutil.which(argv[0]) is None:
        row.update(status="skipped", reason=f"không có {argv[0]} trong image (xem /opt/missing_tools.txt)", exit=127)
        print(row["reason"])
    else:
        row["tool_version"] = tool_version(argv[0])
        t0 = time.time()
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            row.update(status="done", exit=r.returncode, stdout_tail=r.stdout[-300:], stderr_tail=r.stderr[-300:])
        except subprocess.TimeoutExpired as e:
            row.update(status="timeout", exit=None, note="bị dừng do hết thời gian; vẫn dùng được (phiên bị cắt)")
        row.update(t_first=round(t0, 3), t_last=round(time.time(), 3))
    open(os.path.join(a.out, "sessions.jsonl"), "a", encoding="utf-8").write(json.dumps(row) + "\n")
    print(json.dumps({k: row[k] for k in ("run_id", "srcip", "status", "exit") if k in row}))


if __name__ == "__main__":
    main()
