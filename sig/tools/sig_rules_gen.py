#!/usr/bin/env python3
"""sig_rules_gen.py — nguồn DUY NHẤT của bộ luật chữ ký: sinh rules/zy_siem10_sig_rules.xml và mô phỏng nhanh
bằng `re` của Python (gần đúng PCRE2 cho các mẫu dùng ở đây) trên dev/benign_dev trước khi kiểm thật bằng wazuh-logtest.

  python3 -B sig_rules_gen.py --xml ../rules/zy_siem10_sig_rules.xml          # sinh file luật
  python3 -B sig_rules_gen.py --sim                                           # mô phỏng trên runs/p3a_* (CHỈ dev)

Nguyên tắc: mỗi luật MỘT thẻ <url type="pcre2"> (hai thẻ bị nối, NOTES 16); level 8 (che luật dựng sẵn, NOTES 17) và >= 6
(không bị 31101 L0 che, NOTES 22); if_sid 31100,31108 (NOTES 18); không dùng ký tự < hoặc & trong mẫu (viết \\x3c, \\x26).
Mỗi ký tự đặc biệt được chấp nhận ở dạng thô, %XX (E2) và %25XX (E3) — xem hàm E(). Không dựa vào tên tham số.
Luật viết thủ công; KHÔNG do mô hình AI của hệ thống sinh.
"""
import argparse, json, os, re, sys, collections

HERE = os.path.dirname(os.path.abspath(__file__)); SIG = os.path.dirname(HERE)


def E(hexcode, raw=None):
    """một ký tự: thô (nếu có) | %XX | %25XX | %2525XX (không phân biệt hoa thường nhờ (?i) ở đầu mẫu)"""
    enc = f"%(?:25){{0,2}}{hexcode}"
    return f"(?:{raw}|{enc})" if raw else f"(?:{enc})"


R_DQ, R_PIPE, R_AMP, R_HASH, R_LT, R_GT = r"\x22", "[|]", r"\x26", "#", r"\x3c", r"\x3e"
Q = f"(?:{E('27', chr(39))}|{E('22', R_DQ)}|`|%(?:25){{0,2}}60)"          # ' " `
LP, RP = E("28", r"\("), E("29", r"\)")
EQ = E("3d", "=")
SEMI = E("3b", ";")
LT = rf"(?:\x3c|%(?:25){{0,2}}3c|\\x3c|\\u003c|\x26lt;?|\x26#0*60;?|\x26#x0*3c;?)"
SL = E("2f", "/")
BS = rf"(?:\\|%(?:25){{0,2}}5c|%c0%5c|%c1%9c|%u2216)"
SEP = rf"(?:{SL}|{BS}|%c0%af|%u2215|%uefc8|%uf025)"
DOT = rf"(?:\.|%(?:25){{0,2}}2e|%c0%ae|%c0%2e|%e0%80%ae|%u002e|%uff0e)"
# "khoảng trắng" của SQL/lệnh: %20 tab LF CR VT FF NBSP, dấu + (khoảng trắng trong query), chú thích /**/
WS = rf"(?:%(?:25){{0,2}}(?:20|09|0a|0b|0c|0d|a0)|\+|/\*.*?\*/|%(?:25){{0,2}}2f%(?:25){{0,2}}2a.*?%(?:25){{0,2}}2a%(?:25){{0,2}}2f)"
CMDSEP = rf"(?:{SEMI}|{E('7c', R_PIPE)}|{E('26', R_AMP)}|`|%(?:25){{0,2}}60|\$(?:{LP}|\{{)|%(?:25){{0,2}}24%(?:25){{0,2}}28|%(?:25){{0,2}}0a|%(?:25){{0,2}}0d|\\n)"
CMT = rf"(?:/\*.*?\*/|%(?:25){{0,2}}2f%(?:25){{0,2}}2a.*?%(?:25){{0,2}}2a%(?:25){{0,2}}2f)"
VSTART = rf"(?:=|{SL})"            # đầu giá trị tham số, hoặc ngay sau một dấu /
END = rf"(?={WS}|{SEMI}|{E('7c', R_PIPE)}|{E('26', R_AMP)}|`|%(?:25){{0,2}}60|{SL}|{RP}|{LP}|-|$)"

RULES = [
    # id, nhóm, mô tả (không dấu), mẫu
    (100110, "sqli", "SIG SQLi: UNION [ALL] SELECT",
     rf"union{WS}+(?:all{WS}+|distinct{WS}+)?(?:{LP}{WS}*)?select"),
    (100111, "sqli", "SIG SQLi: dau nhay dong chuoi roi OR/AND/toan tu",
     rf"{Q}(?:{WS}|{RP})*(?:or|and|xor|\|\||%(?:25){{0,2}}7c%(?:25){{0,2}}7c|\x26\x26|%(?:25){{0,2}}26%(?:25){{0,2}}26){WS}*(?:{LP}|{Q}|\d|[a-z_]+{WS}*{EQ}|not{WS}|exists|sleep|true|false|null|{WS})"),
    (100112, "sqli", "SIG SQLi: dau nhay roi chu thich/ket thuc lenh",
     rf"{Q}(?:{WS}|{RP})*(?:--|{E('23', R_HASH)}|/\*|%(?:25){{0,2}}2f%(?:25){{0,2}}2a|{SEMI})"),
    (100113, "sqli", "SIG SQLi: tautology so (or 1=1)",
     rf"{WS}(?:or|and|xor|\|\||\x26\x26){WS}+(\d+|{Q}[a-z0-9]*{Q}){WS}*(?:{EQ}|like|{E('3c', R_LT)}|{E('3e', R_GT)}){WS}*(?:\d|{Q})"),
    (100114, "sqli", "SIG SQLi: ham/bien he thong (sleep, benchmark, @@version, information_schema...)",
     rf"(?:(?:sleep|benchmark|pg_sleep|randomblob|extractvalue|updatexml|load_file|convert|cast|char|chr|concat|group_concat|ascii|substring|substr|mid|md5|user|database|version|count|if|iif|elt|exp|floor|rand)\s*{LP}.{{0,200}}(?:{RP}|,)|waitfor{WS}+delay|@@(?:version|datadir|hostname|basedir)|information_schema|sysobjects|syscolumns|dbms_pipe|utl_inaddr|xp_cmdshell|into{WS}+(?:out|dump)file|declare{WS}+@|exec(?:ute)?{WS}*(?:{LP}{WS}*@|{WS}+xp)|select{WS}+(?:top{WS}+\d|@)|{LP}{WS}*select{WS}|in{WS}*{LP}{WS}*select\b|0x[0-9a-f]{{16,}})"),
    (100115, "sqli", "SIG SQLi: ORDER BY / GROUP BY so, hoac cau lenh noi tiep sau ;",
     rf"(?:(?:order|group){WS}+by{WS}+(?:\d|[a-z_]\w*{WS}+having)|having{WS}+\d+{WS}*{EQ}|{SEMI}{WS}*(?:select|insert|update|delete|drop|create|alter|exec|execute|shutdown|declare|truncate)\b)"),
    (100116, "sqli", "SIG SQLi: OR/AND ngay dau gia tri tham so",
     rf"{VSTART}(?:{WS}|{RP})*(?:or|and|xor|\|\||%(?:25){{0,2}}7c%(?:25){{0,2}}7c){WS}+(?:\d+{WS}*(?:{EQ}|like|{E('3c', R_LT)}|{E('3e', R_GT)})|[a-z_]\w*{WS}*{EQ}|{Q}|{LP}|not{WS}|exists|true\b|false\b|null\b)"),
    (100117, "sqli", "SIG SQLi: tautology hai ve giong nhau (a=a, 1=1, 'x'='x')",
     rf"{WS}(?:or|and|xor|\|\||\x26\x26){WS}+([a-z_0-9]+|{Q}[a-z0-9_]*{Q}){WS}*{EQ}{WS}*\1(?![a-z0-9_])"),
    (100118, "sqli", "SIG SQLi: chen chu thich giua tu (uni/**/on, sel/**/ect)",
     rf"[a-z]{{2,}}{CMT}[a-z]{{2,}}"),
    (100120, "xss", "SIG XSS: the HTML nguy hiem",
     rf"{LT}(?:{WS}|{SL})*(?:script|svg|img|iframe|frame|frameset|body|details|video|audio|source|object|embed|applet|input|marquee|math|style|link|meta|form|base|isindex|xss|bgsound|layer|ilayer|table|div|textarea|keygen|button|select|plaintext|xmp|html|x|a)(?![a-z0-9_-])"),
    (100121, "xss", "SIG XSS: thuoc tinh su kien on...=",
     rf"(?:{WS}|{SL}|{Q}|\\x0[9acd]|{E('3c', R_LT)}[a-z]+{WS}*)on[a-z]{{3,25}}(?:{WS}|\\x0[9acd])*{EQ}"),
    (100122, "xss", "SIG XSS: giao thuc javascript:/vbscript:/data:text/html",
     rf"(?:javascript|vbscript|livescript|java\x26#?\w+;?script|data{WS}*(?::|%(?:25){{0,2}}3a){WS}*text/html)(?:{WS}|\\x0[9acd]|\x26#\w+;?)*(?::|%(?:25){{0,2}}3a|\x26colon;)"),
    (100123, "xss", "SIG XSS: ham/doi tuong JS (alert, prompt, document.cookie...)",
     rf"(?:(?:alert|prompt|confirm|eval|settimeout|setinterval|fromcharcode|atob|expression)(?:{WS})*(?:{LP}|`|%(?:25){{0,2}}60)|document{DOT}(?:cookie|domain|write|location)|window{DOT}(?:location|open)|\.innerhtml)"),
    (100130, "traversal", "SIG Path traversal: ../ lap tu 2 lan (moi dang ma hoa)",
     rf"(?:{DOT}{{2,}}{SEP}+(?:{DOT}*{SEP}*)*){{2,}}|(?:{SEP}{DOT}{{2,}}){{2,}}"),
    (100131, "traversal", "SIG Path traversal/LFI: tep he thong nhay cam",
     rf"(?:etc{SEP}+(?:passwd|shadow|group|hosts|issue|motd|crontab|sudoers|fstab|hostname|resolv{DOT}conf)|proc{SEP}+self{SEP}|(?:win|boot|system){DOT}ini|system32|inetpub|global{DOT}asa|web{DOT}config|wp-config|{DOT}ht(?:passwd|access)|var{SEP}+(?:log|mail|adm|spool|lib{SEP}+mysql){SEP}|{DOT}ssh{SEP}|id_rsa|{DOT}bash_history)"),
    (100132, "traversal", "SIG Path traversal/LFI: ../ mot lan ket hop tep he thong, byte rong, wrapper",
     rf"(?:{DOT}{{2}}{SEP}.{{0,40}}(?:etc|windows|winnt|boot|proc|var|usr){SEP}|%(?:25){{0,2}}00|(?:php|file|zip|phar|expect|glob|data){WS}*(?::|%(?:25){{0,2}}3a)(?:{SL}){{2}})"),
    (100133, "traversal", "SIG LFI: duong dan tuyet doi toi tep cau hinh/nhat ky he thong",
     rf"{VSTART}{SL}etc{SEP}[a-z]|{VSTART}(?:{SL}(?:etc|var|usr|opt|proc|root|home|private|volumes|srv|logs?|apache\d*|nginx|xampp|lampp)|[a-z](?::|%(?:25){{0,2}}3a)(?:{BS}|{SL}))[^\x26?#\s]{{0,200}}?(?:\.(?:conf|cnf|cfg|ini|log|err|config|default|pl|htpasswd)|_log|error_log|access_log|passwd|shadow|ftpusers|inittab|sshd_config|xferlog|messages|sendmail|hosts|my\.ini)(?![a-z0-9])"),
    (100142, "cmdi", "SIG Command injection: bien IFS thay khoang trang (${IFS}, $IFS)",
     rf"(?:\$|%(?:25){{0,2}}24)(?:\{{|%(?:25){{0,2}}7b)?ifs"),
    (100140, "cmdi", "SIG Command injection: ky tu noi lenh roi lenh he thong",
     rf"{CMDSEP}{WS}*(?:{Q})?(?:/(?:usr/)?(?:s?bin)/)?(?:id|whoami|uname|cat|ls|dir|ping|nc|ncat|netcat|wget|curl|bash|sh|zsh|dash|python[23]?|perl|php|ruby|nslookup|sleep|echo|ifconfig|ipconfig|netstat|ps|net|systeminfo|type|powershell|cmd|hostname|pwd|env|ver|tasklist|rm|chmod|touch|telnet|ssh|base64|xterm|dig|reg|phpinfo|system|exec|passthru|shell_exec|popen|proc_open|eval)(?:{DOT}exe)?{END}"),
    (100141, "cmdi", "SIG Command injection: duong dan shell/trinh thong dich",
     rf"(?:{SL}(?:usr{SL})?s?bin{SL}(?:ba|z|da|k|c|tc)?sh|{SL}(?:usr{SL})?s?bin{SL}(?:id|cat|nc|ls|ping|wget|curl|python[23]?|perl)\b|cmd{DOT}exe|powershell{DOT}exe|\b(?:system|passthru|shell_exec|popen|proc_open){WS}*{LP})"),
]
# Không dùng luật tần suất. Đo trên Manager thật: frequency="5" +
# if_matched_group siem10_sig_sqli bắn ở lần 3 và 6 thay vì 5 (nghi Wazuh đếm mỗi sự kiện hai lần khi luật con có hai cha
# if_sid 31100,31108 — CHƯA kiểm nguyên nhân). Id 1001x9 để trống.
FREQ = []

OVERWRITE = open(os.path.join(HERE, "overwrite_cach2.xml"), encoding="utf-8").read() if os.path.exists(
    os.path.join(HERE, "overwrite_cach2.xml")) else None


def pat(p):
    return "(?i)" + p


def xml(probe=False):
    for rid, g, d, p in RULES:
        assert "<" not in p and "&" not in p, (rid, "dùng \\x3c / \\x26")
        re.compile(pat(p))
    out = ["<!-- siem10: luat chu ky cho tan cong theo noi dung URL (SQLi, XSS, path traversal, command injection).",
           "     Sinh tu sig/tools/sig_rules_gen.py - KHONG sua tay. Luat viet thu cong; khong do mo hinh AI cua he thong sinh.",
           "     Phan 1: ha 9 luat dung san chi xet ma trang thai ve level 0 (cach 2, xem sig/ref/NOTES.md muc 21).",
           "     Phan 2: 20 luat chu ky 1001xx (level 8); khong co luat tan suat. -->", ""]
    out.append(OVERWRITE.strip() if OVERWRITE else "<!-- (thieu overwrite_cach2.xml) -->")
    out += ["", '<group name="web,accesslog,attack,siem10_sig,">']
    for rid, g, d, p in RULES:
        out += [f'  <rule id="{rid}" level="8">', "    <if_sid>31100,31108</if_sid>"] + (
            ["    <srcip>192.0.2.0/24</srcip>"] if probe else []) + [
                f'    <url type="pcre2">{pat(p)}</url>', f"    <description>{d}</description>",
                f"    <group>siem10_sig_{g},</group>", "  </rule>"]
    for rid, g in FREQ:
        out += [f'  <rule id="{rid}" level="10" frequency="5" timeframe="60">',
                f"    <if_matched_group>siem10_sig_{g}</if_matched_group>", "    <same_source_ip />"] + (
            ["    <srcip>192.0.2.0/24</srcip>"] if probe else []) + [
                f"    <description>SIG {g}: tu 5 lan trong 60s tu cung nguon</description>",
                f"    <group>siem10_sig_{g}_freq,</group>", "  </rule>"]
    out += ["</group>", ""]
    return "\n".join(out)


URLRX = re.compile(r'^\S+ \S+ \S+ \[[^\]]+\] "\S+ (\S+) HTTP\S+" (\d{3}) ')


def sim(sets=("dev", "benign_dev")):
    comp = [(rid, g, re.compile(pat(p))) for rid, g, d, p in RULES]
    res = {}
    for st in sets:
        C = [json.loads(l) for l in open(os.path.join(SIG, "payloads", st, "cases.jsonl"), encoding="utf-8")]
        A = open(os.path.join(SIG, "runs", f"p3a_{st}", "access_log.txt"), encoding="latin-1").read().splitlines()
        rows = []
        for c, a in zip(C, A):
            m = URLRX.match(a)
            url = m.group(1) if m else None
            hit = [rid for rid, g, rx in comp if url is not None and rx.search(url)]
            rows.append({**c, "logurl": url, "status": m.group(2) if m else None, "sig": hit[0] if hit else None,
                         "sig_all": hit})
        res[st] = rows
    return res


def report(res):
    for st, rows in res.items():
        print(f"=== {st}: {sum(1 for r in rows if r['sig'])}/{len(rows)} ca khớp luật chữ ký")
        t = collections.defaultdict(lambda: [0, 0])
        for r in rows:
            for k in [(r["category"], "*"), (r["category"], r["encoding"])]:
                t[k][0] += bool(r["sig"]); t[k][1] += 1
        for k in sorted(t):
            print(f"   {k[0]:<12} {k[1]:<3} {t[k][0]:>4}/{t[k][1]:<4} {100 * t[k][0] / t[k][1]:5.1f}%")
        cnt = collections.Counter(r["sig"] for r in rows if r["sig"])
        print("   theo luật:", dict(sorted(cnt.items())))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--xml"); ap.add_argument("--sim", action="store_true")
    ap.add_argument("--probe", action="store_true", help="biến thể thăm dò: thêm <srcip>192.0.2.0/24</srcip> cho luật 1001xx")
    ap.add_argument("--dump-miss", default=None, help="in các ca dev KHÔNG khớp của loại này (vd sqli)")
    ap.add_argument("--dump-fp", action="store_true", help="in các ca benign_dev bị khớp")
    a = ap.parse_args()
    if a.xml:
        open(a.xml, "w", encoding="utf-8").write(xml(a.probe)); print("->", a.xml)
    if a.sim or a.dump_miss or a.dump_fp:
        R = sim(); report(R)
        if a.dump_miss:
            for r in R["dev"]:
                if r["category"] == a.dump_miss and not r["sig"]:
                    print("  MISS", r["encoding"], r["logurl"][:150])
        if a.dump_fp:
            for r in R["benign_dev"]:
                if r["sig"]:
                    print("  FP", r["sig"], r["encoding"], r["logurl"])
