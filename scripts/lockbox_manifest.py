#!/usr/bin/env python3
"""lockbox_manifest.py — bản kê sha256 của mọi thứ được KHÓA cho lockbox (docs/LOCKBOX_PREREG.md mục 2).

  python3 scripts/lockbox_manifest.py write     # lúc CHỐT PREREG -> docs/lockbox_manifest.json (không ghi đè, trừ --force)
  python3 scripts/lockbox_manifest.py check     # so hiện trạng với bản kê đã chốt; mã thoát 1 nếu có gì khác
  python3 scripts/lockbox_manifest.py show      # chỉ in (không ghi) — để xem trước

Chạy trên HOST (chỉ cần python3). Gồm: code (scripts, setup, tests), cấu hình Apache/site, rule + decoder Wazuh, cấu hình
agent + manager, compose, model + metrics, file luật AI đang áp (bản host), danh sách đề xuất 'applied'. KHÔNG gồm docs/,
data/, output/ (thay đổi theo lúc chạy). Digest tổng = sha256 của các dòng "đường_dẫn sha256" đã sắp xếp.
"""
import argparse, glob, hashlib, json, os, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "docs", "lockbox_manifest.json")
PATTERNS = ["scripts/*.py", "setup/*.sh", "tests/*.py", "Dockerfile", "requirements.txt", "docker-compose.yml",
            "apache/Dockerfile", "apache/*.conf", "apache/*.py", "apache/htdocs/**/*",
            "wazuh/local_rules.xml", "wazuh/local_decoder.xml", "agent/ossec.conf",
            "vendor/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf",
            "models/full1/model.joblib", "models/full1/metrics.json", "wazuh/ai_rules/zz_siem10_ai_rules.xml"]
MUST = ["models/full1/model.joblib", "wazuh/ai_rules/zz_siem10_ai_rules.xml",
        "vendor/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf", "scripts/lockbox_eval.py",
        "scripts/lockbox_preflight.py"]


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def run_batch_digest():
    """Đúng công thức run_batch.code_digest() (không import để chạy được trên host không có thư viện)."""
    h = hashlib.sha256()
    for f in ("site_model.py", "scenarios.py", "traffic.py", "run_batch.py"):
        h.update(open(os.path.join(ROOT, "scripts", f), "rb").read())
    return h.hexdigest()[:16]


def applied_proposals():
    out = []
    pdir = os.path.join(ROOT, "proposals")
    for fn in sorted(os.listdir(pdir)) if os.path.isdir(pdir) else []:
        if fn.endswith(".json"):
            try:
                c = json.load(open(os.path.join(pdir, fn), encoding="utf-8"))
            except Exception:
                continue
            if c.get("status") == "applied":
                out.append(c.get("proposal_id", fn[:-5]))
    return out


def build():
    files = {}
    for pat in PATTERNS:
        for p in sorted(glob.glob(os.path.join(ROOT, pat), recursive=True)):
            if os.path.isfile(p) and "__pycache__" not in p:
                files[os.path.relpath(p, ROOT)] = sha(p)
    missing = [m for m in MUST if m not in files]
    digest = hashlib.sha256("".join(f"{k} {v}\n" for k, v in sorted(files.items())).encode()).hexdigest()
    return {"created": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "digest": digest, "n_files": len(files),
            "model_sha256": files.get("models/full1/model.joblib"),
            "ai_rules_sha256": files.get("wazuh/ai_rules/zz_siem10_ai_rules.xml"),
            "manager_conf_sha256": files.get("vendor/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf"),
            "run_batch_code_digest": run_batch_digest(), "applied_proposals": applied_proposals(),
            "missing_required": missing, "files": files}


def compare(saved, cur):
    diffs = []
    for k in sorted(set(saved["files"]) | set(cur["files"])):
        a, b = saved["files"].get(k), cur["files"].get(k)
        if a != b:
            diffs.append(f"{k}: {'(mới)' if a is None else a[:12]} -> {'(mất)' if b is None else b[:12]}")
    if saved["applied_proposals"] != cur["applied_proposals"]:
        diffs.append(f"đề xuất 'applied': {saved['applied_proposals']} -> {cur['applied_proposals']}")
    return diffs


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=("write", "check", "show"))
    ap.add_argument("--manifest", default=OUT); ap.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)
    cur = build()
    head = (f"digest tổng {cur['digest']} ({cur['n_files']} file)\nmodel.joblib sha256 {cur['model_sha256']}\n"
            f"file luật AI sha256 {cur['ai_rules_sha256']}\ncấu hình manager sha256 {cur['manager_conf_sha256']}\n"
            f"run_batch.code_digest {cur['run_batch_code_digest']}\nđề xuất applied: {cur['applied_proposals']}")
    if a.cmd == "show":
        print(head + (f"\nTHIẾU file bắt buộc: {cur['missing_required']}" if cur["missing_required"] else ""))
        return 0
    if a.cmd == "write":
        if cur["missing_required"]:
            print(f"THIẾU file bắt buộc: {cur['missing_required']} — không ghi"); return 1
        if os.path.exists(a.manifest) and not a.force:
            print(f"{a.manifest} đã có (đã chốt) — không ghi đè; dùng 'check'. --force chỉ khi ghi sai lệch vào PREREG mục 9")
            return 1
        json.dump(cur, open(a.manifest, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        print(head + f"\n-> {os.path.relpath(a.manifest, ROOT)}  (điền các số trên vào docs/LOCKBOX_PREREG.md mục 2)")
        return 0
    if not os.path.exists(a.manifest):
        print(f"chưa có {a.manifest} — chạy 'write' lúc chốt PREREG"); return 1
    saved = json.load(open(a.manifest, encoding="utf-8"))
    d = compare(saved, cur)
    if d:
        print(f"KHÁC bản kê đã chốt ({len(d)}):"); [print("  " + x) for x in d[:40]]
        return 1
    print(f"TRÙNG bản kê đã chốt: digest {cur['digest']} ({cur['n_files']} file), applied {cur['applied_proposals']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
