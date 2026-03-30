package dev.aap.errors;
public class ChainException extends AAPException {
    public ChainException(String id) { super("AAP-006: audit chain broken at entry '" + id + "'"); }
}
