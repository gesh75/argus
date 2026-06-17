# Aegis SSH-helper — minimal Debian box with an SSH client, used by the host-audit
# module to reach credentialed targets. Decoupled from the Kali mirror for resilience.
FROM debian:stable-slim
RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
      openssh-client sshpass ldap-utils ca-certificates && \
    rm -rf /var/lib/apt/lists/*
CMD ["tail", "-f", "/dev/null"]
