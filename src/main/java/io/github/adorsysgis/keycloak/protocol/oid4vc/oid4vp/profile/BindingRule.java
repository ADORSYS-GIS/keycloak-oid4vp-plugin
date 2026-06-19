package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Rule binding a supporting credential to the primary credential or the authenticated Keycloak user.
 */
public class BindingRule {

    public static final String CLAIM_EQUALS_PRIMARY_CLAIM = "claim_equals_primary_claim";
    public static final String CLAIM_EQUALS_USER_ATTRIBUTE = "claim_equals_user_attribute";

    @JsonProperty("type")
    private String type;

    @JsonProperty("credentialClaim")
    private String credentialClaim;

    @JsonProperty("primaryCredentialClaim")
    private String primaryCredentialClaim;

    @JsonProperty("userAttribute")
    private String userAttribute;

    public String getType() {
        return type;
    }

    public BindingRule setType(String type) {
        this.type = type;
        return this;
    }

    public String getCredentialClaim() {
        return credentialClaim;
    }

    public BindingRule setCredentialClaim(String credentialClaim) {
        this.credentialClaim = credentialClaim;
        return this;
    }

    public String getPrimaryCredentialClaim() {
        return primaryCredentialClaim;
    }

    public BindingRule setPrimaryCredentialClaim(String primaryCredentialClaim) {
        this.primaryCredentialClaim = primaryCredentialClaim;
        return this;
    }

    public String getUserAttribute() {
        return userAttribute;
    }

    public BindingRule setUserAttribute(String userAttribute) {
        this.userAttribute = userAttribute;
        return this;
    }
}
