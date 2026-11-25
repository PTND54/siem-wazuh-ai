# siem10, Active Response: image agent = wazuh-agent 4.14.7 + iptables (để firewall-drop có sẵn của Wazuh chạy được).
# Đã thử 24/11/2026: Amazon Linux 2023, dnf cài iptables-nft -> iptables v1.8.8 (nf_tables) chạy được trong
# không gian mạng của apache-target khi có NET_ADMIN.
FROM wazuh/wazuh-agent:4.14.7
RUN dnf install -y -q iptables-nft && dnf clean all && iptables -V
