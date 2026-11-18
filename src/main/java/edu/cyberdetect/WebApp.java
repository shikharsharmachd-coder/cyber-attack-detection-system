package edu.cyberdetect;

import com.sun.net.httpserver.*;
import java.io.*;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public final class WebApp implements HttpHandler {
    private final Database db; private final DetectionService detection;
    private final Set<String> sessions=ConcurrentHashMap.newKeySet();
    private final String adminPassword=System.getenv().getOrDefault("ADMIN_PASSWORD","admin123");
    public WebApp(Database db,DetectionService detection){this.db=db;this.detection=detection;}
    @Override public void handle(HttpExchange x)throws IOException {
        try {
            String path=x.getRequestURI().getPath(), method=x.getRequestMethod();
            if(path.equals("/")&&method.equals("GET")){serveIndex(x);return;}
            if(path.equals("/api/login")&&method.equals("POST")){login(x);return;}
            if(path.equals("/api/session")&&method.equals("GET")){json(x,200,Map.of("authenticated",authenticated(x)));return;}
            if(path.equals("/api/logout")&&method.equals("POST")){sessions.remove(cookie(x,"CADSID"));x.getResponseHeaders().add("Set-Cookie","CADSID=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");json(x,200,Map.of("ok",true));return;}
            if(!authenticated(x)){json(x,401,Map.of("error","Please sign in to continue."));return;}
            if(path.equals("/api/summary")&&method.equals("GET")){json(x,200,db.summary());return;}
            if(path.equals("/api/logs")&&method.equals("GET")){json(x,200,db.logs(param(x,"q"),500));return;}
            if(path.equals("/api/alerts")&&method.equals("GET")){json(x,200,db.alerts(param(x,"q"),500));return;}
            if(path.equals("/api/settings")&&method.equals("GET")){json(x,200,db.settings());return;}
            if(path.equals("/api/settings")&&method.equals("POST")){Map<String,String> f=form(x);int failed=bounded(f,"failedThreshold",2,100),window=bounded(f,"windowMinutes",1,1440),frequency=bounded(f,"frequencyThreshold",5,10000);String ips=f.getOrDefault("blockedIps","").trim();db.saveSettings(Map.of("failedThreshold",String.valueOf(failed),"windowMinutes",String.valueOf(window),"frequencyThreshold",String.valueOf(frequency),"blockedIps",ips));json(x,200,Map.of("ok",true));return;}
            if(path.equals("/api/logs")&&method.equals("POST")){Map<String,String> f=form(x);LogEntry l=new LogEntry(java.time.LocalDateTime.parse(f.getOrDefault("time",java.time.LocalDateTime.now().toString())),required(f,"ip"),f.getOrDefault("username","unknown"),f.getOrDefault("type","REQUEST").toUpperCase(Locale.ROOT),f.getOrDefault("path","/"),Integer.parseInt(f.getOrDefault("status","200")),f.getOrDefault("details",""));validateIp(l.ip());List<String> alerts=detection.ingest(l);json(x,201,Map.of("ok",true,"alerts",alerts));return;}
            if(path.equals("/api/import")&&method.equals("POST")){String csv=new String(x.getRequestBody().readAllBytes(),StandardCharsets.UTF_8);int inserted=0,alerted=0;List<String> errors=new ArrayList<>();String[] lines=csv.split("\\R");for(int i=1;i<lines.length;i++){if(lines[i].isBlank())continue;try{LogEntry l=detection.fromCsv(parseCsv(lines[i]));validateIp(l.ip());if(l.type().length()>40)throw new IllegalArgumentException("Event type is too long");List<String> a=detection.ingest(l);inserted++;alerted+=a.size();}catch(Exception ex){errors.add("Line "+(i+1)+": "+ex.getMessage());}}json(x,200,Map.of("inserted",inserted,"alerts",alerted,"errors",errors));return;}
            if(path.startsWith("/api/alerts/")&&path.endsWith("/resolve")&&method.equals("POST")){String[] p=path.split("/");db.resolveAlert(Long.parseLong(p[3]));json(x,200,Map.of("ok",true));return;}
            if(path.equals("/api/export")&&method.equals("GET")){byte[] body=db.exportCsv().getBytes(StandardCharsets.UTF_8);x.getResponseHeaders().set("Content-Type","text/csv; charset=utf-8");x.getResponseHeaders().set("Content-Disposition","attachment; filename=security-log-report.csv");x.sendResponseHeaders(200,body.length);x.getResponseBody().write(body);x.close();return;}
            json(x,404,Map.of("error","Not found."));
        } catch(IllegalArgumentException e){json(x,400,Map.of("error",safe(e.getMessage())));} catch(SQLException e){json(x,500,Map.of("error","Database operation failed. Check MySQL settings and try again."));System.err.println("Database error: "+e.getMessage());} catch(Exception e){json(x,500,Map.of("error","Request could not be completed."));e.printStackTrace();}
    }
    private void login(HttpExchange x)throws IOException{Map<String,String> f=form(x);if("admin".equals(f.get("username"))&&constantEquals(adminPassword,f.getOrDefault("password",""))){String token=UUID.randomUUID().toString();sessions.add(token);x.getResponseHeaders().add("Set-Cookie","CADSID="+token+"; Path=/; HttpOnly; SameSite=Lax");json(x,200,Map.of("ok",true));}else json(x,401,Map.of("error","Incorrect username or password."));}
    private boolean authenticated(HttpExchange x){return sessions.contains(cookie(x,"CADSID"));}
    private static boolean constantEquals(String a,String b){return java.security.MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8),b.getBytes(StandardCharsets.UTF_8));}
    private void serveIndex(HttpExchange x)throws IOException{try(InputStream in=getClass().getResourceAsStream("/static/index.html")){if(in==null){json(x,500,Map.of("error","Dashboard files are missing."));return;}byte[] b=in.readAllBytes();x.getResponseHeaders().set("Content-Type","text/html; charset=utf-8");x.getResponseHeaders().set("X-Content-Type-Options","nosniff");x.getResponseHeaders().set("Content-Security-Policy","default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:");x.sendResponseHeaders(200,b.length);x.getResponseBody().write(b);x.close();}}
    private static Map<String,String> form(HttpExchange x)throws IOException{String raw=new String(x.getRequestBody().readAllBytes(),StandardCharsets.UTF_8);Map<String,String> m=new HashMap<>();for(String pair:raw.split("&")){int i=pair.indexOf('=');if(i>=0)m.put(URLDecoder.decode(pair.substring(0,i),StandardCharsets.UTF_8),URLDecoder.decode(pair.substring(i+1),StandardCharsets.UTF_8));}return m;}
    private static String param(HttpExchange x,String key){String q=x.getRequestURI().getRawQuery();if(q==null)return "";for(String p:q.split("&")){String[] a=p.split("=",2);if(a.length==2&&URLDecoder.decode(a[0],StandardCharsets.UTF_8).equals(key))return URLDecoder.decode(a[1],StandardCharsets.UTF_8);}return "";}
    private static String cookie(HttpExchange x,String name){String all=x.getRequestHeaders().getFirst("Cookie");if(all==null)return "";for(String p:all.split(";")){String[] a=p.trim().split("=",2);if(a.length==2&&a[0].equals(name))return a[1];}return "";}
    private static String required(Map<String,String> f,String key){String v=f.getOrDefault(key,"").trim();if(v.isEmpty())throw new IllegalArgumentException(key+" is required.");return v;}
    private static int bounded(Map<String,String> f,String k,int min,int max){int n=Integer.parseInt(required(f,k));if(n<min||n>max)throw new IllegalArgumentException(k+" must be between "+min+" and "+max+".");return n;}
    private static void validateIp(String ip){if(ip.length()>45||!ip.matches("[0-9a-fA-F:.]+"))throw new IllegalArgumentException("Enter a valid IPv4 or IPv6 address.");}
    private static String[] parseCsv(String line){List<String> fields=new ArrayList<>();StringBuilder cur=new StringBuilder();boolean quoted=false;for(int i=0;i<line.length();i++){char c=line.charAt(i);if(c=='"'&&quoted&&i+1<line.length()&&line.charAt(i+1)=='"'){cur.append('"');i++;}else if(c=='"')quoted=!quoted;else if(c==','&&!quoted){fields.add(cur.toString());cur.setLength(0);}else cur.append(c);}fields.add(cur.toString());return fields.toArray(String[]::new);}
    private static String safe(String s){return s==null?"Invalid request.":s;}
    private static void json(HttpExchange x,int status,Object value)throws IOException{byte[] b=toJson(value).getBytes(StandardCharsets.UTF_8);x.getResponseHeaders().set("Content-Type","application/json; charset=utf-8");x.getResponseHeaders().set("Cache-Control","no-store");x.sendResponseHeaders(status,b.length);x.getResponseBody().write(b);x.close();}
    private static String toJson(Object v){if(v==null)return "null";if(v instanceof String||v instanceof Character)return "\""+escape(v.toString())+"\"";if(v instanceof Number||v instanceof Boolean)return v.toString();if(v instanceof Map<?,?> m){List<String> a=new ArrayList<>();m.forEach((k,val)->a.add(toJson(k.toString())+":"+toJson(val)));return "{"+String.join(",",a)+"}";}if(v instanceof Iterable<?> it){List<String>a=new ArrayList<>();it.forEach(z->a.add(toJson(z)));return "["+String.join(",",a)+"]";}return toJson(v.toString());}
    private static String escape(String s){return s.replace("\\","\\\\").replace("\"","\\\"").replace("\n","\\n").replace("\r","\\r").replace("\t","\\t");}
}
