# Cyber Attack Detection System

A small educational security log monitoring simulator built with HTML5, CSS, Core Java, JDBC, and MySQL. It uses predefined rules to flag suspicious sample activity; it does not inspect live network traffic, block attackers, or provide production grade intrusion prevention.

## Features

- Admin sign in and a responsive monitoring dashboard
- Add individual security events or import a CSV file
- Rule based detection for repeated failed logins, high request frequency, configured blocked IPs, and suspicious request paths
- Searchable log and incident history, alert resolution, and CSV report export
- Configurable detection thresholds stored in MySQL
- Prepared statements for database writes and searches

## Requirements

- JDK 21+
- Maven 3.9 or later
- MySQL 8.0 or later

## Setup

1. Create the database and tables by running `database/schema.sql` in MySQL Workbench or the MySQL command line. The application also creates its tables at startup, but it does not create the database itself.
2. Set the connection details for your local MySQL instance. PowerShell example:

   ```powershell
   $env:DB_URL = 'jdbc:mysql://localhost:3306/cyber_attack_detection?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC'
   $env:DB_USER = 'root'
   $env:DB_PASSWORD = 'your_mysql_password'
   $env:ADMIN_PASSWORD = 'choose_a_local_password'
   $env:APP_PORT = '8080'
   ```

   `DB_URL` defaults to the URL above, `DB_USER` defaults to `root`, `DB_PASSWORD` defaults to blank, and `ADMIN_PASSWORD` defaults to `admin123` for a quick local demo. Set your own admin password before using the app beyond a local classroom demo.
3. From the project directory run (the project includes a local Maven copy under `tools/`):

   ```powershell
   .\tools\apache-maven-3.10.1\bin\mvn.cmd compile exec:java
   ```

4. Open `http://localhost:8080`. Sign in as `admin` using the `ADMIN_PASSWORD` value.
5. Import `sample-data/security-logs.csv` from the dashboard to see events and generated alerts.

## CSV format

The first row is a header. Each following row uses this order:

```text
time,ip,username,type,path,status,details
```

Time is ISO local date/time, such as `2026-11-18T09:00:00`. `details` is optional. CSV values containing commas or quotes should be quoted using standard CSV escaping.

## Detection rules

- **Repeated failed logins:** high alert when events from the same source IP have a failed status (`401`) or a type containing `FAIL` at/above the configured threshold during the configured window.
- **High request frequency:** medium alert when the number of events from one source IP reaches the configured threshold during that window.
- **Blocked IP activity:** critical alert for any event from an IP in the comma or space separated blocked list.
- **Suspicious request path:** high alert for common `../`, `%2e%2e`, or `<script` markers in the request path.

The threshold and blocked IP settings are stored in MySQL in `detection_settings`. Rules run as each event is added or imported. The dashboard's activity bars summarize the latest imported events, not a live network stream.

## Project layout

```text
src/main/java/edu/cyberdetect/    Java application, JDBC persistence, detection rules, HTTP routes
src/main/resources/static/       HTML/CSS/JS dashboard
database/schema.sql              MySQL schema
sample-data/security-logs.csv    Importable demo activity
```

The HTTP server uses the JDK's built-in `HttpServer`, so there is no Spring Boot dependency or separate servlet container. MySQL Connector/J is managed by Maven.
