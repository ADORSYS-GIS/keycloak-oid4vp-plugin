package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class Credential {

    @JsonProperty("id")
    private String id;

    @JsonProperty("format")
    private String format;

    @JsonProperty("meta")
    private Meta meta;

    @JsonProperty("claims")
    private List<Claim> claims;

    @JsonProperty("claim_sets")
    private List<List<String>> claimSets;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public Meta getMeta() {
        return meta;
    }

    public void setMeta(Meta meta) {
        this.meta = meta;
    }

    public List<Claim> getClaims() {
        return claims;
    }

    public void setClaims(List<Claim> claims) {
        this.claims = claims;
    }

    public List<List<String>> getClaimSets() {
        return claimSets;
    }

    public void setClaimSets(List<List<String>> claimSets) {
        this.claimSets = claimSets;
    }
}
