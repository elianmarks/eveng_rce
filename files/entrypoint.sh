#!/bin/bash
# Sobe MySQL e Apache em primeiro plano (sem systemd).
set -e

mkdir -p /var/run/mysqld && chown mysql:mysql /var/run/mysqld && chmod 755 /var/run/mysqld

if [ ! -f /var/lib/mysql/.eve-initialized ]; then
  echo "[eve] inicializando banco"
  mysqld --user=mysql --skip-networking &
  for i in $(seq 1 60); do mysqladmin ping --silent && break; sleep 1; done
  mysql -uroot <<'SQL'
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'eve-ng';
SQL
  mysql -uroot -peve-ng < /usr/local/share/eve/schema.sql
  mysqladmin -uroot -peve-ng shutdown
  wait || true
  touch /var/lib/mysql/.eve-initialized
fi

mysqld --user=mysql &
for i in $(seq 1 60); do mysqladmin -uroot -peve-ng ping --silent 2>/dev/null && break; sleep 1; done

# Primeira subida: cria o lab de teste (teste.unl) com um node QEMU pela propria
# API, garantindo um .unl valido. Sobe o Apache temporariamente so para isso.
if [ ! -f /opt/unetlab/labs/.poc-seeded ]; then
  echo "[eve] criando lab de teste (teste.unl)"
  apache2ctl start
  for i in $(seq 1 30); do curl -sf -o /dev/null http://127.0.0.1/ && break; sleep 1; done
  JAR=$(mktemp)
  curl -s -c "$JAR" -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"eve","html5":"-1"}' \
    http://127.0.0.1/api/auth/login >/dev/null
  curl -s -b "$JAR" -H 'Content-Type: application/json' \
    -d '{"path":"/","name":"teste","version":"1","author":"poc","description":"PoC RCE","body":""}' \
    http://127.0.0.1/api/labs >/dev/null
  echo -n "[eve] node: "; curl -s -b "$JAR" -H 'Content-Type: application/json' \
    -d '{"type":"qemu","template":"linux","name":"poc","image":"linux-poc","icon":"Server.png","ram":"256","cpu":"1","ethernet":"1","left":"50","top":"50"}' \
    http://127.0.0.1/api/labs/teste.unl/nodes
  echo
  rm -f "$JAR"
  apache2ctl stop; sleep 2
  touch /opt/unetlab/labs/.poc-seeded
fi

# Mesma etapa do postinst oficial
/opt/unetlab/wrappers/unl_wrapper -a fixpermissions >/dev/null 2>&1 || true

echo "[eve] EVE-NG Community $(cat /opt/unetlab/html/themes/adminLTE/VERSION 2>/dev/null) pronto  (admin / eve)"
exec apache2ctl -D FOREGROUND
