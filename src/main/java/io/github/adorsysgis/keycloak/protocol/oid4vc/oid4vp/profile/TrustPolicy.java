package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Issuer trust policy for one requested credential.
 */
public class TrustPolicy {

    public static final String SELF = "self";
    public static final String X5C = "x5c";

    @JsonProperty("type")
    private String type = SELF;

    @JsonProperty("anchors")
    private List<String> anchors;

    public String getType() {
        return type;
    }

    public TrustPolicy setType(String type) {
        this.type = type;
        return this;
    }

    public List<String> getAnchors() {
        return anchors;
    }

    public TrustPolicy setAnchors(List<String> anchors) {
        this.anchors = anchors;
        return this;
    }
}
