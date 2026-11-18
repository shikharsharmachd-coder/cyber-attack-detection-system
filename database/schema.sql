CREATE DATABASE IF NOT EXISTS cyber_attack_detection CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE cyber_attack_detection;

CREATE TABLE IF NOT EXISTS security_logs (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  event_time DATETIME NOT NULL,
  source_ip VARCHAR(45) NOT NULL,
  username VARCHAR(120) NOT NULL,
  event_type VARCHAR(40) NOT NULL,
  path VARCHAR(500) NOT NULL,
  status_code INT NOT NULL,
  details VARCHAR(1000) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_log_time (event_time), INDEX idx_log_ip (source_ip), INDEX idx_log_type (event_type)
);

CREATE TABLE IF NOT EXISTS security_alerts (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  log_id BIGINT NULL,
  source_ip VARCHAR(45) NOT NULL,
  severity VARCHAR(20) NOT NULL,
  rule_name VARCHAR(120) NOT NULL,
  message VARCHAR(1000) NOT NULL,
  occurred_at DATETIME NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'OPEN',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_alert_time (occurred_at), INDEX idx_alert_status (status),
  CONSTRAINT fk_alert_log FOREIGN KEY (log_id) REFERENCES security_logs(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS detection_settings (
  setting_key VARCHAR(100) PRIMARY KEY,
  setting_value VARCHAR(2000) NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
