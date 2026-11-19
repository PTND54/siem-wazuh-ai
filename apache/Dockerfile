FROM httpd:2.4

COPY htdocs/ /usr/local/apache2/htdocs/
COPY httpd-siemlab.conf /usr/local/apache2/conf/extra/httpd-siemlab.conf
COPY .htpasswd /usr/local/apache2/conf/.htpasswd

# - bật mod_rewrite (dùng cho đường dẫn trả 500)
# - ảnh httpd chính thức ghi access log ra stdout (/proc/self/fd/1), KHÔNG ra file. Thêm file combined
#   để (nếu muốn) agent đọc được access_log chuẩn cho bộ luật web có sẵn của Wazuh (xem agent/ossec.conf).
# - Define 2 biến cho httpd-siemlab.conf (sinh từ scripts/site_model.py)
RUN sed -i 's/^#LoadModule rewrite_module/LoadModule rewrite_module/' /usr/local/apache2/conf/httpd.conf \
 && printf '%s\n' \
    'Define SIEM_HTDOCS /usr/local/apache2/htdocs' \
    'Define SIEM_HTPASSWD /usr/local/apache2/conf/.htpasswd' \
    'CustomLog "logs/access_log" combined' \
    'Include conf/extra/httpd-siemlab.conf' >> /usr/local/apache2/conf/httpd.conf \
 && httpd -t
