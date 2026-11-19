# Image "lab": Python (trainer/ai-service/generator) + công cụ tấn công/benign THẬT dùng cho tập "công cụ thật".
# Công cụ cài theo kiểu best-effort: gói nào không có trong repo của python:3.11-slim thì ghi vào /opt/missing_tools.txt
# (setup/01_preflight.sh và tool_run.py báo rõ), KHÔNG làm hỏng build.
# nikto không có trong repo main của Debian (bookworm): nếu apt thiếu, lấy bản chính thức từ GitHub, ghim tag 2.5.0.
FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive PYTHONUNBUFFERED=1
RUN apt-get update >/dev/null \
 && touch /opt/missing_tools.txt \
 && for p in iproute2 iputils-ping curl wget apache2-utils nmap hydra dirb nikto gobuster ffuf; do \
      apt-get install -y --no-install-recommends "$p" >/dev/null 2>&1 || echo "$p" >> /opt/missing_tools.txt; \
    done \
 && if grep -qx nikto /opt/missing_tools.txt; then \
      apt-get install -y --no-install-recommends perl git ca-certificates libnet-ssleay-perl >/dev/null 2>&1 \
      && git clone --depth 1 --branch 2.5.0 https://github.com/sullo/nikto.git /opt/nikto >/dev/null 2>&1 \
      && printf '#!/bin/sh\ncd /opt/nikto/program && exec perl ./nikto.pl "$@"\n' > /usr/local/bin/nikto \
      && chmod +x /usr/local/bin/nikto && sed -i '/^nikto$/d' /opt/missing_tools.txt \
      || echo "  (cài nikto từ GitHub thất bại, giữ trong missing_tools)"; \
    fi \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r /tmp/requirements.txt

WORKDIR /workspace
CMD ["python3", "-c", "print('siem-ai-lab image ready')"]
