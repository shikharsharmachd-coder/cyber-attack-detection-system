package edu.cyberdetect;
import java.util.Optional;
public final class RequestFrequencyRule implements DetectionRule {
    @Override public Optional<Alert> evaluate(LogEntry e, RuleContext c) {
        return c.eventCount()>=c.frequencyThreshold()?Optional.of(new Alert("MEDIUM","High request frequency",c.eventCount()+" events from "+e.ip()+" in "+c.windowMinutes()+" minutes.",e.time())):Optional.empty();
    }
}
