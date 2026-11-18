package edu.cyberdetect;
import java.time.LocalDateTime;
public record Alert(String severity, String rule, String message, LocalDateTime occurredAt) {}
