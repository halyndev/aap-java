package dev.aap;
import dev.aap.audit.*; import dev.aap.authorization.*; import dev.aap.crypto.KeyPair;
import dev.aap.errors.PhysicalWorldViolation; import dev.aap.identity.Identity;
import dev.aap.provenance.Provenance; import java.util.List;
public final class Quickstart {
    public static void main(String[] args) {
        System.out.println("AAP — Agent Accountability Protocol\n=====================================\n");
        KeyPair sup=KeyPair.generate(), ag=KeyPair.generate();
        System.out.println("1. Keypairs generated (Ed25519 / Bouncy Castle)");
        Identity id=Identity.create("aap://acme/worker/deploy-bot@1.0.0",
            List.of("write:files","exec:deploy"),ag,sup,"did:key:z6Mk");
        System.out.println("2. Identity:  "+id.id+"\n   Scope:     "+id.scope);
        Authorization auth=Authorization.create(id.id,Level.SUPERVISED,
            List.of("write:files"),false,sup,"did:key:z6Mk");
        System.out.println("3. Auth:      level="+auth.levelName+" valid="+auth.isValid());
        boolean blocked=false;
        try { Authorization.create("aap://factory/robot/arm@1.0.0",Level.AUTONOMOUS,
            List.of("move:arm"),true,sup,"did:key:z6Mk"); }
        catch(PhysicalWorldViolation e){ blocked=true; }
        System.out.println("4. Physical World Rule blocked: "+blocked);
        Provenance prov=Provenance.create(id.id,"write:file",
            "input".getBytes(),"output".getBytes(),auth.sessionId,ag);
        System.out.println("5. Provenance: "+prov.artifactId.substring(0,8)+"...");
        AuditChain chain=new AuditChain();
        chain.append(id.id,"write:file",AuditResult.SUCCESS,prov.artifactId,ag,auth.level,false);
        AuditChain.VerifyResult v=chain.verify();
        System.out.println("6. Audit:     "+v.count+" entries, valid="+v.valid);
        System.out.println("\n✅ Every action identified, authorized, traced, audited.");
    }
}
