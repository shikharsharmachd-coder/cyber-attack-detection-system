package edu.cyberdetect;
import java.util.Optional;
public interface DetectionRule {
    Optional<Alert> evaluate(LogEntry event, RuleContext context);
}
