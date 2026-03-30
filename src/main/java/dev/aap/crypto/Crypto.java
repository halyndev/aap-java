package dev.aap.crypto;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.UUID;
public final class Crypto {
    private Crypto() {}
    public static String sha256(String data) { return sha256(data.getBytes(StandardCharsets.UTF_8)); }
    public static String sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(data);
            StringBuilder sb = new StringBuilder("sha256:");
            for (byte b : h) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) { throw new RuntimeException(e); }
    }
    public static String utcNow() { return Instant.now().toString(); }
    public static String uuidV4() { return UUID.randomUUID().toString(); }
}
