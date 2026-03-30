package dev.aap.errors;
public class PhysicalWorldViolation extends AAPException {
    public final String agentId;
    public PhysicalWorldViolation(String agentId) {
        super("AAP-003: Physical World Rule: Autonomous (Level 4) is forbidden for physical agent '"
              + agentId + "'. Maximum level is Supervised (Level 3). Not configurable.");
        this.agentId = agentId;
    }
}
