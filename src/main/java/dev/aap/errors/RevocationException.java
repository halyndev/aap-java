package dev.aap.errors;
public class RevocationException extends AAPException {
    public RevocationException(String id) { super("AAP-005: '" + id + "' has been revoked"); }
}
