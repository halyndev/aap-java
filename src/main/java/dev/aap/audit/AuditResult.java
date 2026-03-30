package dev.aap.audit;
public enum AuditResult {
    SUCCESS, FAILURE, BLOCKED, REVOKED;
    public String label() { return name().toLowerCase(); }
}
