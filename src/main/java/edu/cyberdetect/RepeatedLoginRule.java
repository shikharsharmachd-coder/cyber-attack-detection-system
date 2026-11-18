package edu.cyberdetect;
import java.util.Locale;
import java.util.Optional;
public final class RepeatedLoginRule implements DetectionRule {
    @Override public Optional<Alert> evaluate(LogEntry e, RuleContext c) {
        if ((e.status()==401 || e.type().toUpperCase(Locale.ROOT).contains("FAIL")) && c.failedAttempts()>=c.failedThreshold())
            return Optional.of(new Alert("HIGH","Repeated failed logins",c.failedAttempts()+" failed login attempts from "+e.ip()+" in "+c.windowMinutes()+" minutes.",e.time()));
        return Optional.empty();
    }
}
