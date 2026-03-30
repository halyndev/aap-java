package dev.aap.provenance;
import com.google.gson.*;
import dev.aap.crypto.Crypto;
import dev.aap.crypto.KeyPair;
import java.nio.charset.StandardCharsets;
public final class Provenance {
    public final String aapVersion,artifactId,agentId,action,inputHash,outputHash,authorizationId,timestamp;
    public String signature;
    private Provenance(String agentId,String action,String ih,String oh,String authId){
        this.aapVersion="0.1";this.artifactId=Crypto.uuidV4();this.agentId=agentId;
        this.action=action;this.inputHash=ih;this.outputHash=oh;
        this.authorizationId=authId;this.timestamp=Crypto.utcNow();this.signature="";
    }
    public static Provenance create(String agentId,String action,byte[] in,byte[] out,String authId,KeyPair agKp){
        Provenance p=new Provenance(agentId,action,Crypto.sha256(in),Crypto.sha256(out),authId);
        p.signature=agKp.sign(p.toJsonSignable().getBytes(StandardCharsets.UTF_8));
        return p;
    }
    public String toJson(){JsonObject o=buildJson();o.addProperty("signature",signature);return new Gson().toJson(o);}
    String toJsonSignable(){return new Gson().toJson(buildJson());}
    private JsonObject buildJson(){
        JsonObject o=new JsonObject();
        o.addProperty("aap_version",aapVersion);o.addProperty("artifact_id",artifactId);
        o.addProperty("agent_id",agentId);o.addProperty("action",action);
        o.addProperty("input_hash",inputHash);o.addProperty("output_hash",outputHash);
        o.addProperty("authorization_id",authorizationId);o.addProperty("timestamp",timestamp);
        return o;
    }
}
