package dev.aap;
import dev.aap.audit.*; import dev.aap.authorization.*; import dev.aap.crypto.KeyPair;
import dev.aap.errors.*; import dev.aap.identity.Identity; import dev.aap.provenance.Provenance;
import org.junit.jupiter.api.Test; import java.util.List;
import static org.junit.jupiter.api.Assertions.*;
class AAPTest {
    private KeyPair sup(){return KeyPair.generate();}
    private KeyPair ag(){return KeyPair.generate();}
    private Identity id(KeyPair s,KeyPair a){
        return Identity.create("aap://acme/worker/bot@1.0.0",List.of("read:files","write:*"),a,s,"did:key:z");}
    @Test void identity_creates(){Identity i=id(sup(),ag());assertEquals("aap://acme/worker/bot@1.0.0",i.id);assertFalse(i.signature.isEmpty());}
    @Test void identity_rejects_bad_id(){assertThrows(ValidationException.class,()->Identity.create("bad",List.of("read:files"),ag(),sup(),"did:key:z"));}
    @Test void identity_rejects_empty_scope(){assertThrows(ValidationException.class,()->Identity.create("aap://x/y/z@1.0.0",List.of(),ag(),sup(),"did:key:z"));}
    @Test void identity_rejects_bad_scope(){assertThrows(ValidationException.class,()->Identity.create("aap://x/y/z@1.0.0",List.of("INVALID"),ag(),sup(),"did:key:z"));}
    @Test void identity_allows_exact(){assertTrue(id(sup(),ag()).allowsAction("read:files"));}
    @Test void identity_allows_wildcard(){assertTrue(id(sup(),ag()).allowsAction("write:anything"));}
    @Test void identity_denies_out_of_scope(){assertFalse(id(sup(),ag()).allowsAction("delete:files"));}
    @Test void identity_verify_correct_key(){KeyPair s=sup();Identity i=id(s,ag());assertDoesNotThrow(()->i.verify(s.publicKeyB64()));}
    @Test void identity_verify_wrong_key(){Identity i=id(sup(),ag());assertThrows(SignatureException.class,()->i.verify(sup().publicKeyB64()));}
    @Test void identity_verify_revoked(){KeyPair s=sup();Identity i=id(s,ag());i.revoked=true;assertThrows(RevocationException.class,()->i.verify(s.publicKeyB64()));}
    @Test void auth_creates_valid(){Authorization a=Authorization.create("aap://x/y/z@1.0.0",Level.SUPERVISED,List.of("w:f"),false,sup(),"did:key:z");assertTrue(a.isValid());assertEquals("supervised",a.levelName);}
    @Test void physical_world_rule_blocks(){assertThrows(PhysicalWorldViolation.class,()->Authorization.create("aap://factory/robot/arm@1.0.0",Level.AUTONOMOUS,List.of("move:arm"),true,sup(),"did:key:z"));}
    @Test void physical_supervised_ok(){assertDoesNotThrow(()->Authorization.create("aap://factory/robot/arm@1.0.0",Level.SUPERVISED,List.of("move:arm"),true,sup(),"did:key:z"));}
    @Test void digital_autonomous_ok(){assertDoesNotThrow(()->Authorization.create("aap://x/y/z@1.0.0",Level.AUTONOMOUS,List.of("read:files"),false,sup(),"did:key:z"));}
    @Test void auth_revoke(){Authorization a=Authorization.create("aap://x/y/z@1.0.0",Level.OBSERVE,List.of("r:f"),false,sup(),"did:key:z");a.revoke();assertFalse(a.isValid());assertThrows(RevocationException.class,a::check);}
    @Test void provenance_creates(){Provenance p=Provenance.create("aap://x/y/z@1.0.0","write:file","in".getBytes(),"out".getBytes(),"s1",ag());assertFalse(p.artifactId.isEmpty());assertTrue(p.inputHash.startsWith("sha256:"));}
    @Test void provenance_same_input_same_hash(){KeyPair a=ag();Provenance p1=Provenance.create("aap://x/y/z@1.0.0","r:f","x".getBytes(),"x".getBytes(),"s1",a);Provenance p2=Provenance.create("aap://x/y/z@1.0.0","r:f","x".getBytes(),"x".getBytes(),"s2",a);assertEquals(p1.inputHash,p2.inputHash);}
    @Test void audit_empty_valid(){AuditChain.VerifyResult v=new AuditChain().verify();assertTrue(v.valid);assertEquals(0,v.count);assertNull(v.brokenAt);}
    @Test void audit_one_entry_valid(){AuditChain c=new AuditChain();c.append("aap://x/y/z@1.0.0","w:f",AuditResult.SUCCESS,"p1",ag(),3,false);AuditChain.VerifyResult v=c.verify();assertTrue(v.valid);assertEquals(1,v.count);}
    @Test void audit_genesis_hash(){AuditChain c=new AuditChain();AuditEntry e=c.append("aap://x/y/z@1.0.0","r:f",AuditResult.SUCCESS,"p1",ag(),0,false);assertEquals("genesis",e.prevHash);}
    @Test void audit_five_entries(){AuditChain c=new AuditChain();KeyPair a=ag();for(int i=0;i<5;i++)c.append("aap://x/y/z@1.0.0","w:f",AuditResult.SUCCESS,"p"+i,a,3,false);AuditChain.VerifyResult v=c.verify();assertTrue(v.valid);assertEquals(5,v.count);}
    @Test void audit_blocked_recorded(){AuditChain c=new AuditChain();AuditEntry e=c.append("aap://factory/robot/arm@1.0.0","move:arm",AuditResult.BLOCKED,"p1",ag(),3,true);assertEquals("blocked",e.result);assertTrue(e.physical);}
}
