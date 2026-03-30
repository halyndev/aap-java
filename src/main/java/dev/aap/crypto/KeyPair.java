package dev.aap.crypto;
import dev.aap.errors.SignatureException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import java.security.SecureRandom;
import java.util.Base64;
public final class KeyPair {
    private final Ed25519PrivateKeyParameters priv;
    private final Ed25519PublicKeyParameters  pub;
    private KeyPair(Ed25519PrivateKeyParameters priv, Ed25519PublicKeyParameters pub) {
        this.priv = priv; this.pub = pub;
    }
    public static KeyPair generate() {
        Ed25519KeyPairGenerator gen = new Ed25519KeyPairGenerator();
        gen.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        AsymmetricCipherKeyPair pair = gen.generateKeyPair();
        return new KeyPair((Ed25519PrivateKeyParameters) pair.getPrivate(),
                           (Ed25519PublicKeyParameters)  pair.getPublic());
    }
    public String publicKeyB64() {
        return "ed25519:" + Base64.getEncoder().encodeToString(pub.getEncoded());
    }
    public String sign(byte[] data) {
        Ed25519Signer s = new Ed25519Signer();
        s.init(true, priv);
        s.update(data, 0, data.length);
        return "ed25519:" + Base64.getEncoder().encodeToString(s.generateSignature());
    }
    public static void verify(String pubB64, byte[] data, String sigB64) {
        try {
            byte[] pk = Base64.getDecoder().decode(strip(pubB64));
            byte[] sg = Base64.getDecoder().decode(strip(sigB64));
            Ed25519PublicKeyParameters key = new Ed25519PublicKeyParameters(pk, 0);
            Ed25519Signer v = new Ed25519Signer();
            v.init(false, key);
            v.update(data, 0, data.length);
            if (!v.verifySignature(sg)) throw new SignatureException("signature mismatch");
        } catch (SignatureException e) { throw e;
        } catch (Exception e) { throw new SignatureException("invalid key or sig: " + e.getMessage()); }
    }
    private static String strip(String s) { int c = s.indexOf(':'); return c >= 0 ? s.substring(c+1) : s; }
}
