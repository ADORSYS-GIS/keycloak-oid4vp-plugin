package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Issuer trust policy for one requested credential.
 */
public class TrustPolicy {

    public static final String SELF = "self";
    public static final String X5C = "x5c";
    public static final String EUDI_PID_TRUST_LIST = "eudi_pid_trust_list";

    @JsonProperty("type")
    private String type = SELF;

    @JsonProperty("anchors")
    private List<String> anchors;

    @JsonProperty("trustListUrl")
    private String trustListUrl;

    @JsonProperty("trustListSigningCertificate")
    private String trustListSigningCertificate;

    @JsonProperty("serviceType")
    private String serviceType;

    @JsonProperty("issuer")
    private String issuer;

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

    public String getTrustListUrl() {
        return trustListUrl;
    }

    public TrustPolicy setTrustListUrl(String trustListUrl) {
        this.trustListUrl = trustListUrl;
        return this;
    }

    public String getTrustListSigningCertificate() {
        return trustListSigningCertificate;
    }

    public TrustPolicy setTrustListSigningCertificate(String trustListSigningCertificate) {
        this.trustListSigningCertificate = trustListSigningCertificate;
        return this;
    }

    public String getServiceType() {
        return serviceType;
    }

    public TrustPolicy setServiceType(String serviceType) {
        this.serviceType = serviceType;
        return this;
    }

    public String getIssuer() {
        return issuer;
    }

    public TrustPolicy setIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }
}
