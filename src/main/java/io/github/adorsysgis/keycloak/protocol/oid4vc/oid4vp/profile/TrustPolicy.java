package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.CertificateUtil;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.keycloak.utils.StringUtil;

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
    private List<X509Certificate> anchors;

    @JsonProperty("trustListUrl")
    private String trustListUrl;

    @JsonProperty("trustListSigningCertificate")
    private String trustListSigningCertificate;

    @JsonProperty("serviceType")
    private String serviceType;

    @JsonProperty("issuer")
    private String issuer;

    public TrustPolicy() {}

    @JsonCreator
    public static TrustPolicy create(
            @JsonProperty("type") String type,
            @JsonProperty("anchors") List<String> rawAnchors,
            @JsonProperty("trustListUrl") String trustListUrl,
            @JsonProperty("trustListSigningCertificate") String trustListSigningCertificate,
            @JsonProperty("serviceType") String serviceType,
            @JsonProperty("issuer") String issuer) {
        TrustPolicy policy = new TrustPolicy();
        policy.type = type != null ? type : SELF;
        policy.trustListUrl = trustListUrl;
        policy.trustListSigningCertificate = trustListSigningCertificate;
        policy.serviceType = serviceType;
        policy.issuer = issuer;
        policy.anchors = parseAnchors(rawAnchors);
        return policy;
    }

    private static List<X509Certificate> parseAnchors(List<String> rawAnchors) {
        if (rawAnchors == null) {
            return null;
        }

        if (rawAnchors.isEmpty()) {
            return List.of();
        }

        List<X509Certificate> parsed = new ArrayList<>();
        for (String raw : rawAnchors) {
            if (StringUtil.isBlank(raw)) {
                throw new IllegalArgumentException("Failed to parse x5c trust anchor: blank anchor");
            }
            try {
                parsed.add(CertificateUtil.parseCertificate(raw));
            } catch (Exception e) {
                throw new IllegalArgumentException(String.format("Failed to parse x5c trust anchor: %s", raw), e);
            }
        }

        return parsed;
    }

    public String getType() {
        return type;
    }

    public TrustPolicy setType(String type) {
        this.type = type;
        return this;
    }

    public List<X509Certificate> getAnchors() {
        return anchors;
    }

    public TrustPolicy setAnchors(List<X509Certificate> anchors) {
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
