package dev.aap.errors;
public class SignatureException extends AAPException {
    public SignatureException(String msg) { super("AAP-002: signature error: " + msg); }
}
