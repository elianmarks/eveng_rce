-- Esquema mínimo do EVE-NG Community 6.2.0-4.
-- O esquema oficial vem do pacote eve-ng-schema (Pre-Depends), que não está
-- no .deb principal; as tabelas abaixo foram reconstruídas a partir das
-- consultas em includes/functions.php e includes/api_authentication.php.

CREATE DATABASE IF NOT EXISTS eve_ng_db;
CREATE USER IF NOT EXISTS 'eve-ng'@'localhost' IDENTIFIED WITH mysql_native_password BY 'eve-ng';
GRANT ALL ON eve_ng_db.* TO 'eve-ng'@'localhost';

USE eve_ng_db;

CREATE TABLE IF NOT EXISTS users (
  username   VARCHAR(255) PRIMARY KEY,
  cookie     TEXT,
  email      TEXT,
  expiration INT DEFAULT -1,
  name       TEXT,
  password   TEXT,
  session    INT,
  ip         TEXT,
  role       TEXT,
  folder     TEXT,
  html5      INT DEFAULT 1
);

CREATE TABLE IF NOT EXISTS pods (
  id         INT PRIMARY KEY,
  expiration INT DEFAULT -1,
  username   VARCHAR(255),
  lab_id     TEXT,
  INDEX username_pods (username)
);

CREATE TABLE IF NOT EXISTS html5 (
  username VARCHAR(255),
  pod      VARCHAR(32),
  token    TEXT,
  PRIMARY KEY (username, pod)
);

-- admin / eve  (mesmo hash inserido pelo preinst oficial)
INSERT IGNORE INTO users VALUES
  ('admin', NULL, 'root@localhost', -1, 'Eve-NG Administrator',
   '85262adf74518bbb70c7cb94cd6159d91669e5a81edf1efebd543eadbda9fa2b',
   NULL, '', 'admin', '', 1);
INSERT IGNORE INTO pods (id, expiration, username) VALUES (0, -1, 'admin');

-- Banco do Guacamole (console HTML5): a API exige a conexão no login.
CREATE DATABASE IF NOT EXISTS guacdb;
CREATE USER IF NOT EXISTS 'guacuser'@'localhost' IDENTIFIED WITH mysql_native_password BY 'eve-ng';
CREATE USER IF NOT EXISTS 'guacuser'@'127.0.0.1' IDENTIFIED WITH mysql_native_password BY 'eve-ng';
GRANT ALL ON guacdb.* TO 'guacuser'@'localhost';
GRANT ALL ON guacdb.* TO 'guacuser'@'127.0.0.1';

USE guacdb;

CREATE TABLE IF NOT EXISTS guacamole_connection (
  connection_id   INT PRIMARY KEY,
  connection_name VARCHAR(128),
  protocol        VARCHAR(32)
);
CREATE TABLE IF NOT EXISTS guacamole_connection_parameter (
  connection_id   INT,
  parameter_name  VARCHAR(128),
  parameter_value VARCHAR(4096),
  PRIMARY KEY (connection_id, parameter_name)
);
CREATE TABLE IF NOT EXISTS guacamole_entity (
  entity_id INT AUTO_INCREMENT PRIMARY KEY,
  name      VARCHAR(128),
  type      VARCHAR(16),
  UNIQUE KEY (type, name)
);
CREATE TABLE IF NOT EXISTS guacamole_user (
  user_id       INT AUTO_INCREMENT PRIMARY KEY,
  entity_id     INT,
  username      VARCHAR(128),
  password_hash BINARY(32),
  password_salt BINARY(32),
  password_date DATETIME
);
CREATE TABLE IF NOT EXISTS guacamole_connection_permission (
  entity_id     INT,
  connection_id INT,
  permission    VARCHAR(16),
  PRIMARY KEY (entity_id, connection_id, permission)
);
CREATE TABLE IF NOT EXISTS guacamole_user_permission (
  entity_id          INT,
  affected_user_id   INT,
  permission         VARCHAR(16),
  PRIMARY KEY (entity_id, affected_user_id, permission)
);
CREATE TABLE IF NOT EXISTS guacamole_sharing_profile (
  sharing_profile_id   INT AUTO_INCREMENT PRIMARY KEY,
  sharing_profile_name VARCHAR(128),
  primary_connection_id INT
);
CREATE TABLE IF NOT EXISTS guacamole_sharing_profile_permission (
  entity_id          INT,
  sharing_profile_id INT,
  permission         VARCHAR(16),
  PRIMARY KEY (entity_id, sharing_profile_id, permission)
);

FLUSH PRIVILEGES;
