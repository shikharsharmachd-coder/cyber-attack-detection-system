package edu.cyberdetect;
import java.util.Optional;
public final class BlockedIpRule implements DetectionRule {
    @Override public Optional<Alert> evaluate(LogEntry e, RuleContext c) {
        return c.blockedIps().contains(e.ip())?Optional.of(new Alert("CRITICAL","Blocked IP activity","Activity received from configured blocked IP "+e.ip()+".",e.time())):Optional.empty();
    }
}
