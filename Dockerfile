# EVE-NG Community 6.2.0-4 — ambiente de laboratório
# Base: Ubuntu 22.04 (Apache 2.4.52, PHP 8.1).

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Dependências
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        apache2 libapache2-mod-php php php-cli php-xml php-mysql php-sqlite3 libiscsi7 \
        php-zip php-yaml php-imagick libcurl3-gnutls librbd1 libssh2-1 \
        mysql-server sudo psmisc cgroup-tools net-tools iproute2 bridge-utils \
        uml-utilities tcpdump telnet unzip zip genisoimage sqlite3 curl \
        qemu-system-x86 qemu-utils python3-pexpect ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Pacote oficial, extraído da ISO
COPY debs/eve-ng_6.2.0-4_amd64.deb /tmp/eve-ng.deb
RUN dpkg-deb -x /tmp/eve-ng.deb / && rm /tmp/eve-ng.deb

# Etapas equivalentes ao postinst (sem GRUB/kernel/initramfs)
RUN groupadd -g 32768 -f unl && \
    chmod 0440 /etc/sudoers.d/unetlab && \
    a2enmod rewrite proxy_http proxy_wstunnel xml2enc >/dev/null && \
    a2dissite 000-default >/dev/null && \
    a2ensite unetlab >/dev/null && \
    sed -i 's/^ServerName.*$/ServerName eve-ng/' /etc/apache2/sites-available/unetlab.conf && \
    echo "ServerName eve-ng" >> /etc/apache2/apache2.conf && \
    chmod 755 /opt/unetlab/wrappers/* /opt/unetlab/scripts/* && \
    mkdir -p /opt/unetlab/data/Logs /opt/unetlab/data/Exports /opt/unetlab/labs \
             /opt/unetlab/tmp /opt/unetlab/addons/qemu

# Arquivos gerados pelo ovfstartup/postinst e lidos pelo init.php
RUN printf 'vmx' > /opt/unetlab/platform && \
    printf 'none\n' > /opt/unetlab/hypervisor

COPY debs/eve-ng-qemu_6.0.1-0_amd64.deb /tmp/eve-ng-qemu.deb
RUN dpkg-deb -x /tmp/eve-ng-qemu.deb / && rm /tmp/eve-ng-qemu.deb && \
    ln -sfn /opt/qemu-2.12.0 /opt/qemu && \
    /opt/qemu/bin/qemu-img --version

RUN mkdir -p /opt/unetlab/addons/qemu/linux-poc && \
    /opt/qemu/bin/qemu-img create -f qcow2 /opt/unetlab/addons/qemu/linux-poc/hda.qcow2 64M >/dev/null

COPY files/schema.sql /usr/local/share/eve/schema.sql
COPY files/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 80
CMD ["/usr/local/bin/entrypoint.sh"]
