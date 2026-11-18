package edu.cyberdetect;

import java.sql.SQLException;
import java.time.LocalDateTime;
import java.util.*;

public final class DetectionService {
    private final Database db;
    private final List<DetectionRule> rules=List.of(new RepeatedLoginRule(),new RequestFrequencyRule(),new BlockedIpRule(),new SuspiciousPathRule());
    // Per-IP queues make the sliding frequency window explicit; counters avoid recounting in-memory events.
    private final Map<String,Deque<LocalDateTime>> eventWindows=new HashMap<>(), failedWindows=new HashMap<>();
    private final Map<String,Integer> eventCounters=new HashMap<>(), failedCounters=new HashMap<>();
    public DetectionService(Database db){this.db=db;}

    public synchronized List<String> ingest(LogEntry log) throws SQLException {
        long id=db.addLog(log);
        Map<String,String> cfg=db.settings();
        int failedThreshold=Integer.parseInt(cfg.get("failedThreshold"));
        int window=Integer.parseInt(cfg.get("windowMinutes"));
        int frequencyThreshold=Integer.parseInt(cfg.get("frequencyThreshold"));
        boolean failed=log.status()==401||log.type().toUpperCase(Locale.ROOT).contains("FAIL");
        int inMemoryEvents=record(eventWindows,eventCounters,log.ip(),log.time(),window);
        int inMemoryFailed=failed?record(failedWindows,failedCounters,log.ip(),log.time(),window):count(failedWindows,failedCounters,log.ip(),log.time(),window);
        // Include records from before this process started so the rolling rule survives restarts.
        int eventCount=Math.max(inMemoryEvents,recentCount(log.ip(),"ALL",window));
        int failedCount=Math.max(inMemoryFailed,recentCount(log.ip(),"FAILED_LOGIN",window));
        Set<String> blocked=new HashSet<>();
        for(String ip:cfg.getOrDefault("blockedIps","").split("[,\\s]+"))if(!ip.isBlank())blocked.add(ip.trim());
        RuleContext context=new RuleContext(failedCount,eventCount,failedThreshold,frequencyThreshold,window,Set.copyOf(blocked),log.time());
        List<String> detected=new ArrayList<>();
        for(DetectionRule rule:rules)rule.evaluate(log,context).ifPresent(alert->{
            try{db.addAlert(id,log.ip(),alert.severity(),alert.rule(),alert.message(),alert.occurredAt());detected.add(alert.rule());}
            catch(SQLException e){throw new DatabaseWriteException(e);}
        });
        return detected;
    }
    private static int record(Map<String,Deque<LocalDateTime>> queues,Map<String,Integer> counters,String ip,LocalDateTime at,int window){
        Deque<LocalDateTime> q=queues.computeIfAbsent(ip,k->new ArrayDeque<>());
        q.addLast(at);counters.merge(ip,1,Integer::sum);
        return trim(q,counters,ip,at,window);
    }
    private static int count(Map<String,Deque<LocalDateTime>> queues,Map<String,Integer> counters,String ip,LocalDateTime at,int window){
        Deque<LocalDateTime> q=queues.get(ip);return q==null?0:trim(q,counters,ip,at,window);
    }
    private static int trim(Deque<LocalDateTime> q,Map<String,Integer> counters,String ip,LocalDateTime at,int window){
        LocalDateTime cutoff=at.minusMinutes(window);
        while(!q.isEmpty()&&q.peekFirst().isBefore(cutoff)){q.removeFirst();counters.computeIfPresent(ip,(k,n)->n<=1?null:n-1);}
        return counters.getOrDefault(ip,0);
    }
    private int recentCount(String ip,String eventType,int minutes)throws SQLException {
        try(var c=java.sql.DriverManager.getConnection(System.getenv().getOrDefault("DB_URL","jdbc:mysql://localhost:3306/cyber_attack_detection?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC"),System.getenv().getOrDefault("DB_USER","root"),System.getenv().getOrDefault("DB_PASSWORD",""));var p=c.prepareStatement("SELECT COUNT(*) FROM security_logs WHERE source_ip=? AND event_time>=NOW()-INTERVAL ? MINUTE AND (?='ALL' OR event_type LIKE '%FAIL%' OR status_code=401)")){
            p.setString(1,ip);p.setInt(2,minutes);p.setString(3,eventType);try(var r=p.executeQuery()){r.next();return r.getInt(1);}
        }
    }
    public LogEntry fromCsv(String[] row){
        if(row.length<6)throw new IllegalArgumentException("Each CSV record needs time, ip, username, type, path and status; details is optional.");
        LocalDateTime time=row[0].isBlank()?LocalDateTime.now():LocalDateTime.parse(row[0].trim().replace(" ","T"));
        return new LogEntry(time,row[1].trim(),row[2].trim(),row[3].trim().toUpperCase(Locale.ROOT),row[4].trim(),Integer.parseInt(row[5].trim()),row.length>6?row[6].trim():"");
    }
    private static final class DatabaseWriteException extends RuntimeException { DatabaseWriteException(SQLException cause){super(cause);} }
}
