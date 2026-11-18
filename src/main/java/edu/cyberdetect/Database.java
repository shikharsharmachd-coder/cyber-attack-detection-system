package edu.cyberdetect;

import java.sql.*;
import java.time.LocalDateTime;
import java.util.*;

public final class Database {
    private final String url = System.getenv().getOrDefault("DB_URL", "jdbc:mysql://localhost:3306/cyber_attack_detection?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC");
    private final String user = System.getenv().getOrDefault("DB_USER", "root");
    private final String password = System.getenv().getOrDefault("DB_PASSWORD", "");

    private Connection connect() throws SQLException { return DriverManager.getConnection(url, user, password); }
    public void initialize() throws SQLException {
        try (Connection c = connect(); Statement s = c.createStatement()) {
            s.executeUpdate("CREATE TABLE IF NOT EXISTS security_logs (id BIGINT PRIMARY KEY AUTO_INCREMENT,event_time DATETIME NOT NULL,source_ip VARCHAR(45) NOT NULL,username VARCHAR(120) NOT NULL,event_type VARCHAR(40) NOT NULL,path VARCHAR(500) NOT NULL,status_code INT NOT NULL,details VARCHAR(1000) NOT NULL,created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,INDEX idx_log_time(event_time),INDEX idx_log_ip(source_ip))");
            s.executeUpdate("CREATE TABLE IF NOT EXISTS security_alerts (id BIGINT PRIMARY KEY AUTO_INCREMENT,log_id BIGINT NULL,source_ip VARCHAR(45) NOT NULL,severity VARCHAR(20) NOT NULL,rule_name VARCHAR(120) NOT NULL,message VARCHAR(1000) NOT NULL,occurred_at DATETIME NOT NULL,status VARCHAR(20) NOT NULL DEFAULT 'OPEN',created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,INDEX idx_alert_time(occurred_at),INDEX idx_alert_status(status))");
            s.executeUpdate("CREATE TABLE IF NOT EXISTS detection_settings (setting_key VARCHAR(100) PRIMARY KEY,setting_value VARCHAR(2000) NOT NULL,updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)");
        }
    }
    public long addLog(LogEntry log) throws SQLException {
        String q = "INSERT INTO security_logs(event_time,source_ip,username,event_type,path,status_code,details) VALUES(?,?,?,?,?,?,?)";
        try (Connection c=connect(); PreparedStatement p=c.prepareStatement(q, Statement.RETURN_GENERATED_KEYS)) {
            p.setTimestamp(1, Timestamp.valueOf(log.time())); p.setString(2,log.ip()); p.setString(3,log.username()); p.setString(4,log.type()); p.setString(5,log.path()); p.setInt(6,log.status()); p.setString(7,log.details()); p.executeUpdate();
            try(ResultSet r=p.getGeneratedKeys()){r.next(); return r.getLong(1);}
        }
    }
    public void addAlert(long logId, String ip, String severity, String rule, String message, LocalDateTime at) throws SQLException {
        try(Connection c=connect(); PreparedStatement p=c.prepareStatement("INSERT INTO security_alerts(log_id,source_ip,severity,rule_name,message,occurred_at) VALUES(?,?,?,?,?,?)")){
            p.setLong(1,logId);p.setString(2,ip);p.setString(3,severity);p.setString(4,rule);p.setString(5,message);p.setTimestamp(6,Timestamp.valueOf(at));p.executeUpdate();
        }
    }
    public List<Map<String,Object>> logs(String query, int limit) throws SQLException {
        String q="SELECT id,event_time,source_ip,username,event_type,path,status_code,details FROM security_logs WHERE (?='' OR source_ip LIKE ? OR username LIKE ? OR event_type LIKE ? OR path LIKE ?) ORDER BY event_time DESC,id DESC LIMIT ?";
        try(Connection c=connect();PreparedStatement p=c.prepareStatement(q)){String like="%"+query+"%";p.setString(1,query);for(int i=2;i<=5;i++)p.setString(i,like);p.setInt(6,limit);try(ResultSet r=p.executeQuery()){List<Map<String,Object>> out=new ArrayList<>();while(r.next()){Map<String,Object> m=new LinkedHashMap<>();m.put("id",r.getLong("id"));m.put("time",r.getTimestamp("event_time").toLocalDateTime().toString());m.put("ip",r.getString("source_ip"));m.put("username",r.getString("username"));m.put("type",r.getString("event_type"));m.put("path",r.getString("path"));m.put("status",r.getInt("status_code"));m.put("details",r.getString("details"));out.add(m);}return out;}}
    }
    public List<Map<String,Object>> alerts(String query, int limit) throws SQLException {
        String q="SELECT id,source_ip,severity,rule_name,message,occurred_at,status FROM security_alerts WHERE (?='' OR source_ip LIKE ? OR rule_name LIKE ? OR message LIKE ?) ORDER BY occurred_at DESC,id DESC LIMIT ?";
        try(Connection c=connect();PreparedStatement p=c.prepareStatement(q)){String like="%"+query+"%";p.setString(1,query);for(int i=2;i<=4;i++)p.setString(i,like);p.setInt(5,limit);try(ResultSet r=p.executeQuery()){List<Map<String,Object>> out=new ArrayList<>();while(r.next()){Map<String,Object> m=new LinkedHashMap<>();m.put("id",r.getLong("id"));m.put("ip",r.getString("source_ip"));m.put("severity",r.getString("severity"));m.put("rule",r.getString("rule_name"));m.put("message",r.getString("message"));m.put("time",r.getTimestamp("occurred_at").toLocalDateTime().toString());m.put("status",r.getString("status"));out.add(m);}return out;}}
    }
    public Map<String,Object> summary() throws SQLException {
        Map<String,Object> m=new LinkedHashMap<>();try(Connection c=connect();Statement s=c.createStatement()){
            try(ResultSet r=s.executeQuery("SELECT COUNT(*) total,COUNT(DISTINCT source_ip) ips FROM security_logs WHERE event_time >= NOW()-INTERVAL 24 HOUR")){r.next();m.put("events24h",r.getLong("total"));m.put("uniqueIps",r.getLong("ips"));}
            try(ResultSet r=s.executeQuery("SELECT COUNT(*) total,SUM(status='OPEN') openCount,SUM(severity='CRITICAL' AND status='OPEN') critical FROM security_alerts")){r.next();m.put("alerts",r.getLong("total"));m.put("openAlerts",r.getLong("openCount"));m.put("criticalAlerts",r.getLong("critical"));}
            try(ResultSet r=s.executeQuery("SELECT source_ip,COUNT(*) hits FROM security_logs WHERE event_time >= NOW()-INTERVAL 24 HOUR GROUP BY source_ip ORDER BY hits DESC LIMIT 1")){m.put("topIp",r.next()?r.getString("source_ip"):"—");}
        }return m;
    }
    public void resolveAlert(long id) throws SQLException {try(Connection c=connect();PreparedStatement p=c.prepareStatement("UPDATE security_alerts SET status='RESOLVED' WHERE id=?")){p.setLong(1,id);p.executeUpdate();}}
    public Map<String,String> settings() throws SQLException {Map<String,String> m=new HashMap<>();try(Connection c=connect();Statement s=c.createStatement();ResultSet r=s.executeQuery("SELECT setting_key,setting_value FROM detection_settings")){while(r.next())m.put(r.getString(1),r.getString(2));}m.putIfAbsent("failedThreshold","5");m.putIfAbsent("windowMinutes","10");m.putIfAbsent("frequencyThreshold","30");m.putIfAbsent("blockedIps","");return m;}
    public void saveSettings(Map<String,String> values) throws SQLException {try(Connection c=connect();PreparedStatement p=c.prepareStatement("INSERT INTO detection_settings(setting_key,setting_value) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)")){for(var e:values.entrySet()){p.setString(1,e.getKey());p.setString(2,e.getValue());p.addBatch();}p.executeBatch();}}
    public String exportCsv() throws SQLException {StringBuilder b=new StringBuilder("id,time,ip,username,type,path,status,details\r\n");for(Map<String,Object> row:logs("",10000)){for(String k:List.of("id","time","ip","username","type","path","status","details")){if(k!="id")b.append(',');String v=String.valueOf(row.get(k)).replace("\"","\"\"");b.append('"').append(v).append('"');}b.append("\r\n");}return b.toString();}
}
