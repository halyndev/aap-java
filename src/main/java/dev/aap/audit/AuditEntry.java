package dev.aap.audit;
import com.google.gson.*;
public final class AuditEntry {
    public final String aapVersion,entryId,prevHash,agentId,action,result,timestamp,provenanceId;
    public final int authorizationLevel;
    public final boolean physical;
    public String signature;
    AuditEntry(String entryId,String prevHash,String agentId,String action,AuditResult result,
               String ts,String provId,int authLevel,boolean physical){
        this.aapVersion="0.1";this.entryId=entryId;this.prevHash=prevHash;
        this.agentId=agentId;this.action=action;this.result=result.label();
        this.timestamp=ts;this.provenanceId=provId;this.authorizationLevel=authLevel;
        this.physical=physical;this.signature="";
    }
    public String toJson(){JsonObject o=buildJson();o.addProperty("signature",signature);return new Gson().toJson(o);}
    String toJsonSignable(){return new Gson().toJson(buildJson());}
    private JsonObject buildJson(){
        JsonObject o=new JsonObject();
        o.addProperty("aap_version",aapVersion);o.addProperty("entry_id",entryId);
        o.addProperty("prev_hash",prevHash);o.addProperty("agent_id",agentId);
        o.addProperty("action",action);o.addProperty("result",result);
        o.addProperty("timestamp",timestamp);o.addProperty("provenance_id",provenanceId);
        o.addProperty("authorization_level",authorizationLevel);o.addProperty("physical",physical);
        return o;
    }
}
