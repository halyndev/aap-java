package dev.aap.audit;
import dev.aap.crypto.Crypto;
import dev.aap.crypto.KeyPair;
import java.nio.charset.StandardCharsets;
import java.util.*;
public final class AuditChain {
    private final List<AuditEntry> entries = new ArrayList<>();
    public AuditEntry append(String agentId,String action,AuditResult result,
                             String provId,KeyPair agKp,int authLevel,boolean physical){
        AuditEntry e=new AuditEntry(Crypto.uuidV4(),lastHash(),agentId,action,result,
                                    Crypto.utcNow(),provId,authLevel,physical);
        e.signature=agKp.sign(e.toJsonSignable().getBytes(StandardCharsets.UTF_8));
        entries.add(e); return e;
    }
    public VerifyResult verify(){
        String prev="genesis";
        for(int i=0;i<entries.size();i++){
            AuditEntry e=entries.get(i);
            if(!e.prevHash.equals(prev)) return new VerifyResult(false,i,e.entryId);
            prev=Crypto.sha256(e.toJson());
        }
        return new VerifyResult(true,entries.size(),null);
    }
    public List<AuditEntry> entries(){return Collections.unmodifiableList(entries);}
    public int size(){return entries.size();}
    public boolean isEmpty(){return entries.isEmpty();}
    private String lastHash(){
        return entries.isEmpty()?"genesis":Crypto.sha256(entries.get(entries.size()-1).toJson());
    }
    public static final class VerifyResult {
        public final boolean valid; public final int count; public final String brokenAt;
        VerifyResult(boolean v,int c,String b){valid=v;count=c;brokenAt=b;}
    }
}
