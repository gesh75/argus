# Aegis lab — intentionally-misconfigured Linux SSH target (lab use ONLY).
# Exercises the host-audit module: SUID root shell, NOPASSWD sudo, weak sshd, world-writable.
FROM debian:stable-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
      openssh-server sudo lynis procps iproute2 && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /run/sshd && \
    useradd -m -s /bin/bash pentest && echo 'pentest:pentest' | chpasswd && \
    # --- intentional misconfigurations (LAB ONLY) ---
    cp /bin/bash /usr/local/bin/rootbash && chmod 4755 /usr/local/bin/rootbash && \
    echo 'pentest ALL=(ALL) NOPASSWD: /usr/bin/find' >> /etc/sudoers && \
    install -m 0777 /dev/null /tmp/world_writable && \
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
