package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import org.keycloak.VCFormat;

public class CredentialRequirement {

    /** Identity is derived from the presented credential's {@code sub}/{@code username} claims (login). */
    public static final String IDENTITY_SOURCE_CREDENTIAL = "credential";

    /**
     * Identity is taken from the session-bound brokered user (OID4VCI presentation during issuance): the
     * presented credential (e.g. a PID) is only matched against that user's attributes via binding rules.
     */
    public static final String IDENTITY_SOURCE_SESSION = "session";

    @JsonProperty("id")
    private String id;

    @JsonProperty("role")
    private CredentialRole role = CredentialRole.SUPPORTING;

    @JsonProperty("identitySource")
    private String identitySource = IDENTITY_SOURCE_CREDENTIAL;

    @JsonProperty("formats")
    private List<String> formats = List.of(VCFormat.SD_JWT_VC);

    @JsonProperty("credentialTypes")
    private List<String> credentialTypes;

    @JsonProperty("claims")
    private List<String> claims;

    @JsonProperty("trust")
    private List<TrustPolicy> trust = List.of(new TrustPolicy());

    @JsonProperty("binding")
    private List<BindingRule> binding = List.of();

    public String getId() {
        return id;
    }

    public CredentialRequirement setId(String id) {
        this.id = id;
        return this;
    }

    public CredentialRole getRole() {
        return role;
    }

    public CredentialRequirement setRole(CredentialRole role) {
        this.role = role;
        return this;
    }

    public String getIdentitySource() {
        return identitySource;
    }

    public CredentialRequirement setIdentitySource(String identitySource) {
        this.identitySource = identitySource;
        return this;
    }

    public boolean isSessionIdentity() {
        return IDENTITY_SOURCE_SESSION.equals(identitySource);
    }

    public List<String> getFormats() {
        return formats;
    }

    public CredentialRequirement setFormats(List<String> formats) {
        this.formats = formats;
        return this;
    }

    public List<String> getCredentialTypes() {
        return credentialTypes;
    }

    public CredentialRequirement setCredentialTypes(List<String> credentialTypes) {
        this.credentialTypes = credentialTypes;
        return this;
    }

    public List<String> getClaims() {
        return claims;
    }

    public CredentialRequirement setClaims(List<String> claims) {
        this.claims = claims;
        return this;
    }

    public List<TrustPolicy> getTrust() {
        return trust;
    }

    public CredentialRequirement setTrust(List<TrustPolicy> trust) {
        this.trust = trust;
        return this;
    }

    public List<BindingRule> getBinding() {
        return binding;
    }

    public CredentialRequirement setBinding(List<BindingRule> binding) {
        this.binding = binding;
        return this;
    }

    public boolean isPrimary() {
        return CredentialRole.PRIMARY.equals(role);
    }

    public boolean isSelfTrusted() {
        return trust == null
                || trust.isEmpty()
                || trust.stream().anyMatch(policy -> TrustPolicy.SELF.equals(policy.getType()));
    }
}
