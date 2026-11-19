# NOTES — sự thật về Wazuh đã đo trên Manager thật (4.14.7)

Mỗi mục ghi: nguồn (file output) và mức kiểm. Chỉ ghi những gì đã đo hoặc đã đọc từ tệp luật.

## Đo ngày 14/11/2026 (`runs/p0/2.txt`, `3.txt`)

1. Decoder `web-accesslog` tách `url` NGUYÊN dạng mã hóa: gửi `%27%20` thì `url` vẫn là `%27%20`.
2. Dòng `GET /index.html?id=1%27%20union%20select%201,2--` mã 200 khớp 31106 level 6, nhóm `web, accesslog, attack`.
3. `wazuh-analysisd -t` hiện không in cảnh báo nào (mốc so sánh cho mọi lần thêm file luật).
4. `/var/ossec/etc/rules/` có 7 file `local_rules.xml.bak.*` (của root, từ 22/10). Không gây cảnh báo.
5. Nhóm đang bị đếm bởi `if_matched_group`: authentication_failed (2 luật), web_scan (1 = 110020), siemlab_observed
   (1 = 110030), virus, connection_attempt, authentication_failures, attacks. Luật chữ ký không được mang các nhóm này.
   `attack` (số ít), `web`, `accesslog` không bị luật nào đếm.
6. File trạng thái logcollector của agent in JSON có TAB sau dấu hai chấm (`"drops":<TAB>0`). Mẫu grep
   `'"drops": *[0-9]*'` (dùng trong `setup/03_verify.sh` bước 9) KHÔNG bắt được số -> phép kiểm drops ở đó luôn "đạt".
   Các công cụ trong sig/tools đọc file này bằng bộ đọc JSON.
7. Script khởi động của agent chép file gắn vào volume: `/var/ossec/etc/ossec.conf` trong agent trùng `agent/ossec.conf`.

## Đọc tệp luật web của Wazuh và đo trên nikto ngày 15/11/2026

Nguồn: `ref/0245-web_rules.xml` (sha256 1226e135…), `ref/0270-web_appsec_rules.xml` (0236ec01…),
`ref/0375-web-accesslog_decoders.xml` (2b04d8c0…) chép từ Manager thật; `runs/p1_nikto/builtin.jsonl` (8.469 dòng nikto
khác nhau của tools2 qua wazuh-logtest, mỗi dòng một IP TEST-NET, 29 s, 0 khối lỗi, 8.469/8.469 dòng logtest in lại đúng).

8. Luật thật:
   - 31100 L0 `category web-log`. 31108 L0: `id ^2|^3` + `is_simple_http_request`.
   - 31101 L5: MỌI mã 4xx, nhóm `attack,…`. 31102 L0 (con 31101): đuôi ảnh/css/js.
   - 31103 L7 SQLi, `if_sid 31100,31108`; 31104 L6 "Common web attack" (traversal + lệnh + %00/%0A/%0D…);
     31105 L6 XSS; 31106 L6 con của 31103/31104/31105 khi mã `^200`; 31107 L0 bỏ qua /search.php, /index.php?searchword=.
   - SQLi còn ở 31109, 31164, 31165, 31170, 31171 (L6, chỉ `if_sid 31100`). 31110 L6 PHP-CGI `?-s`.
   - 31115 L13 URL > 7900 ký tự. 31120–31123 mã 5xx.
   - Tần suất: 31151 L10 14×31101/90 s nhóm **web_scan,recon**; 31152 8×31103/120 s; 31153 10×31104/120 s;
     31154 10×31105/120 s; 31161 (501), 31163 (503) cũng nhóm **web_scan**; 31162 (500).
   - 31166/31167 L6, 31168/31169 L15: Shellshock, regex trên CẢ DÒNG (bắt payload trong User-Agent/Referer).
   - 0270-web_appsec_rules.xml: 31501–31550, phần lớn con của 31100, cần cả `<url>` lẫn `<regex>` cụ thể theo ứng dụng
     (wp, timthumb, cart.php…); 31516 L6 `.swp$|.bak$|/.htaccess|/server-status|…`.
   - Ngoài 0245: `0999-malicious-ioc-rules.xml` có luật con của 31103–31106, 31109, 31164, 31165, 31170, 31171
     (đối chiếu danh sách IP độc hại).
9. Mẫu `<url>` mặc định (osmatch) KHÔNG phân biệt hoa thường: số dòng khớp chuỗi mẫu khi so không phân biệt hoa thường
   trùng đúng số dòng nhận 31103/31104/31105 (5/393/296), so có phân biệt thì thiếu. Nhưng VẪN phân biệt dạng mã hóa
   (`%3Cscript` ≠ `<script` ≠ `%253Cscript`).
10. Thứ tự giữa các luật anh em (cùng cha 31100): luật level CAO hơn thắng dù đứng sau trong file (dòng 4xx có mẫu XSS ra
    31105 L6, không ra 31101 L5 đứng trước). Cùng level: luật đứng trước trong file thắng (7 dòng khớp cả mẫu 31104 và 31105
    đều ra 31104). Trường hợp luật nằm ở FILE KHÁC nạp sau: xem mục 17.
11. Decoder: 8.461/8.469 dòng ra `web-accesslog`, `url` nguyên dạng mã hóa. **7 dòng có `\\\"` (Apache thoát dấu nháy)
    trong URL bị decoder `pure-transfer` (FTP) nhận nhầm -> luật 11310 L0, không alert web nào.** 1 dòng có dòng yêu cầu
    sai dạng (`"<script>…</script> / HTTP/1.1"`) không decoder nào nhận. Chỗ mù này do định dạng log, không do mẫu luật.
12. Combined log CÓ ghi Referer và User-Agent (31166 bắt 113 dòng Shellshock nằm trong header). Header khác, Cookie, thân POST
    không được ghi.
13. Phân bố trên nikto (định hướng, không có nhãn): 7.529 dòng chỉ ra 31101 (mã 4xx chung); luật nội dung (31103/04/05/06/10/
    66/68/516) bắt 853 dòng (~10%); 21 dòng mã 200 có `?` không khớp mẫu nào ra 31100 L0 (không alert); 14 dòng mã 2xx/3xx
    "đơn giản" ra 31108 L0.
14. Hệ quả khi bật access_log với bộ luật nguyên vẹn: MỖI request 4xx sinh thêm một alert 31101 L5 (trùng chức năng alert
    SIEMLAB 100011–100013/100016), và 31151 L10 bắn mỗi 14 lỗi 4xx/90 s cùng IP.

## Đo bằng file luật tạm ngày 15/11/2026 (`runs/p1c_20261115-190925/`, bảng in ở `runs/p1c_last.txt`)

File tạm `zy_siem10_sigprobe.xml` (nạp sau local_rules.xml, trước zz_siem10_ai_rules.xml); analysisd -t hai pha 0 cảnh
báo mới; đã xóa và trở về đúng cảnh báo ban đầu.

15. Cú pháp: `<url type="pcre2">` nạp không cảnh báo và khớp đúng. pcre2 PHÂN BIỆT hoa thường mặc định; `(?i)` có tác dụng.
    `\x3c` khớp `<`, `\x26` khớp `&` (không cần `&lt;`/`&amp;`). `<url>` chỉ xét trường url (không xét User-Agent).
16. Hai thẻ `<url type="pcre2">` trong một luật được NỐI thành một mẫu (chỉ `sp_m1sp_m2` liền nhau khớp) -> mỗi luật MỘT thẻ.
17. Thứ tự khi luật nằm ở file nạp sau: giữa các luật anh em, level cao hơn thắng kể cả khi nằm ở file nạp sau (L8 thắng 31105 L6); cùng
    level thì luật của Wazuh (nạp trước) thắng (L7 thua 31103, L6 thua 31105, L5 thua 31101). => Luật chữ ký level 8 luôn che
    các rule xét nội dung của bộ luật web mặc định (tối đa L7) khi cùng khớp, trừ 31115 (L13, URL > 7900 ký tự).
18. Rule 31108 và luật chỉ khai `if_sid 31100`: request mã 2xx/3xx KHÔNG có `?` khớp 31108 (L0) và luật chỉ khai `if_sid 31100` không bao giờ được xét,
    kể cả khi đường dẫn có `%27` hay `../`. Khai `<if_sid>31100,31108</if_sid>` thì luật khớp cả hai trường hợp.
19. URL có `\\` (Apache thoát `\`) giữ nguyên hai ký tự `\\` trong trường url; mẫu `\\\\` (pcre2) khớp. URL có `\"`
    được decode bình thường trong ca thử; URL có khoảng trắng thô: KHÔNG decoder nào nhận.
20. Tương tác với luật 110020: với bộ luật nguyên vẹn, xen SIEMLAB 404 với combined 404 cùng IP -> 110020 bắn ở
    combined #14 (thay chỗ 31151), KHÔNG ở SIEMLAB #15 như khi chỉ có SIEMLAB. Tức là luật 110020 đếm cả sự kiện 31151 (nhóm
    web_scan) và alert của nó rơi vào sự kiện web-accesslog (ai-service, audit không thấy). 110011 (401) không bị ảnh hưởng.
21. Ghi đè (pha B, overwrite 31101, 31120–31123 về L0; 31151, 31161–31163 về L0 và bỏ nhóm web_scan): analysisd -t không
    cảnh báo; overwrite GIỮ nguyên luật cha và điều kiện (`id ^4` vẫn chỉ áp 4xx). 404/501 thường: 0 alert. các rule XSS,
    SQLi của bộ luật web mặc định và Shellshock (31166, con của 31101) vẫn bắn. 110020 bắn lại đúng SIEMLAB #15/#30, 110011 đúng #12/#24
    -> hết tương tác ở mục 20.
22. Hệ quả của overwrite: 31101 giữ vị trí cũ trong thứ tự anh em (như luật L5) nhưng khớp ở L0 và dừng xét các luật sau
    -> luật chữ ký level <= 5 sẽ bị nó che trên dòng 4xx. Luật chữ ký phải từ level 6 trở lên (bộ luật dùng level 8).


## Đã đo khi cài thật (15/11/2026)

23. Luật tần suất `frequency="5" timeframe="60"` + `<if_matched_group>siem10_sig_sqli</if_matched_group>` + same_source_ip,
    mà luật được đếm (100110) có `<if_sid>31100,31108</if_sid>`: bắn ở sự kiện 3 và 6 thay vì 5. Luật tương quan (luật con có một cha)
    bắn đúng N. Giả thuyết CHƯA KIỂM: mỗi sự kiện được ghi hai lần vào danh sách đếm vì luật con đăng ký dưới hai cha.
    Vì vậy bộ luật không dùng luật tần suất.
24. Tệp compose phụ: với `-f docker-compose.yml -f sig/docker-compose.sig.yml`, agent có đúng MỘT mount tới
    /wazuh-config-mount/etc/ossec.conf (trỏ vào sig/agent/ossec.conf); file phụ thay mục gốc, không thêm mục thứ hai.
