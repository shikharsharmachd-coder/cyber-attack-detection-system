package edu.cyberdetect;
import java.time.LocalDateTime;
import java.util.Set;
public record RuleContext(int failedAttempts, int eventCount, int failedThreshold,
                          int frequencyThreshold, int windowMinutes, Set<String> blockedIps,
                          LocalDateTime evaluatedAt) {}
