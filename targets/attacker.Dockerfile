# Aegis attacker box — read-only recon tools baked in at BUILD time (has internet),
# so the runtime container can stay on the internet-isolated ptlab network.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
      nmap masscan fping nbtscan \
      whatweb wafw00f nikto sslscan \
      enum4linux-ng smbmap ldap-utils \
      onesixtyone snmp snmpcheck \
      openssh-client sshpass \
      ca-certificates iputils-ping dnsutils curl wget unzip && \
    rm -rf /var/lib/apt/lists/*

# nuclei (ProjectDiscovery) is a Go binary, not in apt — fetch the matching-arch release.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in arm64) na=arm64;; amd64) na=amd64;; *) na="$arch";; esac; \
    ver="3.3.7"; \
    wget -qO /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${ver}/nuclei_${ver}_linux_${na}.zip" && \
    (cd /tmp && unzip -o -q nuclei.zip nuclei && mv nuclei /usr/local/bin/nuclei && chmod +x /usr/local/bin/nuclei) && \
    rm -f /tmp/nuclei.zip || echo "nuclei install skipped (offline build)"

CMD ["tail", "-f", "/dev/null"]
