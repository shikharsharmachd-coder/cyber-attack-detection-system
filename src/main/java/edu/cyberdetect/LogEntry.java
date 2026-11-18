package edu.cyberdetect;
import java.time.LocalDateTime;
public record LogEntry(LocalDateTime time, String ip, String username, String type, String path, int status, String details) {}
