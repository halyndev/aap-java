package dev.aap.errors;
public class ValidationException extends AAPException {
    public final String field;
    public ValidationException(String field, String message) {
        super("AAP-001: validation error on '" + field + "': " + message);
        this.field = field;
    }
}
