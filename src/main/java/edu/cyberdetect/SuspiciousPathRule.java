package edu.cyberdetect;
import java.util.Locale;
import java.util.Optional;
public final class SuspiciousPathRule implements DetectionRule {
    @Override public Optional<Alert> evaluate(LogEntry e, RuleContext c) {
        String path=e.path().toLowerCase(Locale.ROOT);
        return path.contains("../")||path.contains("%2e%2e")||path.contains("<script")?Optional.of(new Alert("HIGH","Suspicious request path","Potential traversal or script pattern in request path.",e.time())):Optional.empty();
    }
}
