package dev.aap.errors;
public abstract class AAPException extends RuntimeException {
    protected AAPException(String message) { super(message); }
}
