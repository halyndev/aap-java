package dev.aap.authorization;
import com.google.gson.*;
import dev.aap.crypto.Crypto;
import dev.aap.crypto.KeyPair;
import dev.aap.errors.PhysicalWorldViolation;
import dev.aap.errors.RevocationException;
import java.nio.charset.StandardCharsets;
import java.util.List;
public final class Authorization {
    private static final Level PHYSICAL_MAX = Level.SUPERVISED;
    public final String aapVersion;
    public final String agentId;
    public final int    level;
    public final String levelName;
    public final List<String> scope;
    public final boolean physical;
    public final String grantedBy, grantedAt, sessionId;
    public       String signature;
    private      boolean revoked = false;
    private Authorization(String agentId, Level level, List<String> scope,
                          boolean physical, String grantedBy) {
        this.aapVersion="0.1"; this.agentId=agentId; this.level=level.value;
        this.levelName=level.label; this.scope=List.copyOf(scope);
        this.physical=physical; this.grantedBy=grantedBy;
        this.grantedAt=Crypto.utcNow(); this.sessionId=Crypto.uuidV4(); this.signature="";
    }
    public static Authorization create(String agentId, Level level, List<String> scope,
                                       boolean physical, KeyPair supKp, String supDid) {
        if (physical && level.value > PHYSICAL_MAX.value) throw new PhysicalWorldViolation(agentId);
        Authorization a = new Authorization(agentId, level, scope, physical, supDid);
        a.signature = supKp.sign(a.toJsonSignable().getBytes(StandardCharsets.UTF_8));
        return a;
    }
    public void revoke() { this.revoked=true; }
    public boolean isRevoked() { return revoked; }
    public boolean isValid()   { return !revoked; }
    public void check() { if(revoked) throw new RevocationException(sessionId); }
    public String toJson() { JsonObject o=buildJson(); o.addProperty("signature",signature); return new Gson().toJson(o); }
    String toJsonSignable() { return new Gson().toJson(buildJson()); }
    private JsonObject buildJson() {
        JsonObject o=new JsonObject();
        o.addProperty("aap_version",aapVersion); o.addProperty("agent_id",agentId);
        o.addProperty("level",level); o.addProperty("level_name",levelName);
        JsonArray arr=new JsonArray(); scope.forEach(arr::add); o.add("scope",arr);
        o.addProperty("physical",physical); o.addProperty("granted_by",grantedBy);
        o.addProperty("granted_at",grantedAt); o.addProperty("session_id",sessionId);
        return o;
    }
}
