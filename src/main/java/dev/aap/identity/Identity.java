package dev.aap.identity;
import com.google.gson.*;
import dev.aap.crypto.Crypto;
import dev.aap.crypto.KeyPair;
import dev.aap.errors.RevocationException;
import dev.aap.errors.ValidationException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.regex.Pattern;
public final class Identity {
    private static final Pattern ID_RE = Pattern.compile(
        "^aap://[a-z0-9\\-\\.]+/[a-z0-9\\-]+/[a-z0-9\\-\\.]+@\\d+\\.\\d+\\.\\d+$");
    private static final Pattern SCOPE_RE = Pattern.compile("^[a-z]+:[a-z0-9_\\-\\*]+$");
    public final String aapVersion,id,publicKey,parent,issuedAt;
    public final List<String> scope;
    public boolean revoked;
    public String  signature;
    private Identity(String id,String pk,String parent,List<String> scope,String issuedAt){
        this.aapVersion="0.1";this.id=id;this.publicKey=pk;this.parent=parent;
        this.scope=List.copyOf(scope);this.issuedAt=issuedAt;this.revoked=false;this.signature="";
    }
    public static Identity create(String id,List<String> scope,KeyPair agKp,KeyPair parKp,String parDid){
        if(!ID_RE.matcher(id).matches())
            throw new ValidationException("id","invalid format '"+id+"' — expected aap://org/type/name@semver");
        if(scope==null||scope.isEmpty()) throw new ValidationException("scope","must contain at least one item");
        for(String s:scope) if(!SCOPE_RE.matcher(s).matches())
            throw new ValidationException("scope","invalid item '"+s+"' — expected verb:resource");
        Identity i=new Identity(id,agKp.publicKeyB64(),parDid,scope,Crypto.utcNow());
        i.signature=parKp.sign(i.toJsonSignable().getBytes(StandardCharsets.UTF_8));
        return i;
    }
    public boolean allowsAction(String action){
        int c=action.indexOf(':');
        String verb=c>=0?action.substring(0,c):action;
        String res =c>=0?action.substring(c+1):"";
        for(String s:scope){int sc=s.indexOf(':');String sv=sc>=0?s.substring(0,sc):s;String sr=sc>=0?s.substring(sc+1):"";
            if(sv.equals(verb)&&(sr.equals("*")||sr.equals(res)))return true;}
        return false;
    }
    public void verify(String parPubB64){
        if(revoked) throw new RevocationException(id);
        KeyPair.verify(parPubB64,toJsonSignable().getBytes(StandardCharsets.UTF_8),signature);
    }
    public String toJson(){JsonObject o=buildJson();o.addProperty("signature",signature);return new Gson().toJson(o);}
    String toJsonSignable(){return new Gson().toJson(buildJson());}
    private JsonObject buildJson(){
        JsonObject o=new JsonObject();
        o.addProperty("aap_version",aapVersion);o.addProperty("id",id);o.addProperty("public_key",publicKey);
        o.addProperty("parent",parent);JsonArray arr=new JsonArray();scope.forEach(arr::add);o.add("scope",arr);
        o.addProperty("issued_at",issuedAt);o.addProperty("revoked",revoked);return o;
    }
}
