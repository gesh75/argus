# Aegis lab — OpenLDAP directory with ANONYMOUS bind allowed (LAB ONLY) to exercise the
# AD/LDAP module's anonymous-enumeration checks. Seeds a small directory of users.
FROM debian:stable-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends slapd ldap-utils && \
    rm -rf /var/lib/apt/lists/*

# Configure base DN dc=ecp,dc=lab with admin/admin, then seed users; anonymous read allowed.
RUN echo "slapd slapd/no_configuration boolean false" | debconf-set-selections && \
    echo "slapd slapd/domain string ecp.lab" | debconf-set-selections && \
    echo "slapd shared/organization string ECP" | debconf-set-selections && \
    echo "slapd slapd/password1 password admin" | debconf-set-selections && \
    echo "slapd slapd/password2 password admin" | debconf-set-selections && \
    dpkg-reconfigure -f noninteractive slapd

COPY seed_ldap.ldif /seed.ldif
RUN service slapd start && sleep 2 && \
    ldapadd -x -D "cn=admin,dc=ecp,dc=lab" -w admin -f /seed.ldif && \
    service slapd stop

EXPOSE 389
CMD ["/usr/sbin/slapd", "-d", "0", "-h", "ldap:///"]
