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

    /**
     * Optional id of the {@code oid4vp-binding-value-comparator} strategy used to compare the claim
     * value against the expected value. Defaults to the strict, schema-neutral {@code exact} strategy
     * when omitted. Deployments may reference a custom (e.g. locale-tolerant) comparator here.
     */
    @JsonProperty("comparator")
    private String comparator;

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

    public String getComparator() {
        return comparator;
    }

    public BindingRule setComparator(String comparator) {
        this.comparator = comparator;
        return this;
    }
}
