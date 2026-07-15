package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import org.keycloak.VCFormat;
import org.keycloak.utils.StringUtil;

public class CredentialRequirement {

    @JsonProperty("id")
    private String id;

    @JsonProperty("role")
    private CredentialRole role = CredentialRole.SUPPORTING;

    @JsonProperty("format")
    private String format = VCFormat.SD_JWT_VC;

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

    public String getFormat() {
        return format;
    }

    public CredentialRequirement setFormat(String format) {
        this.format = format;
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

    /**
     * Parses {@link #getClaims()} into {@link ClaimReference} entries, accepting the
     * {@code "namespace/name"} and bare {@code "name"} forms.
     */
    public List<ClaimReference> getClaimReferences() {
        if (claims == null || claims.isEmpty()) {
            return List.of();
        }
        return claims.stream()
                .filter(StringUtil::isNotBlank)
                .map(ClaimReference::parse)
                .toList();
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

    /**
     * Reference to a single claim, optionally namespaced.
     * <p>
     * For credential formats that organize claims under a namespace (e.g. mDoc, where claims
     * live under {@code nameSpaces.<namespace>.<elementIdentifier>}), the namespace may be
     * specified with a forward slash, e.g. {@code "org.iso.18013.5.1/document_number"}. For
     * formats with a flat claim layout (e.g. SD-JWT VC), or to match an element identifier
     * under any namespace, the namespace may be omitted, e.g. {@code "document_number"}.
     */
    public record ClaimReference(String namespace, String name) {

        public static final String SEPARATOR = "/";

        public ClaimReference {
            if (StringUtil.isBlank(name)) {
                throw new IllegalArgumentException("Claim name must not be blank");
            }
        }

        public boolean isNamespaced() {
            return StringUtil.isNotBlank(namespace);
        }

        public static ClaimReference parse(String spec) {
            int slash = spec.indexOf(SEPARATOR);
            if (slash < 0) {
                return new ClaimReference(null, spec);
            }
            return new ClaimReference(spec.substring(0, slash), spec.substring(slash + 1));
        }

        @Override
        public String toString() {
            return isNamespaced() ? namespace + SEPARATOR + name : name;
        }
    }
}
