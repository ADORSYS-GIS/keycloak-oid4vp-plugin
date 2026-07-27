package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.PROFILES_CONFIG;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialFormat;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.AuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement.ClaimReference;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Parses and validates OpenID4VP authentication profiles.
 */
public class OID4VPProfileConfig {

    private final List<AuthenticationProfile> profiles;

    public OID4VPProfileConfig(AuthenticatorConfigModel authConfig) {
        Map<String, String> config =
                (authConfig != null && authConfig.getConfig() != null) ? authConfig.getConfig() : Map.of();
        String configuredProfiles = config.get(PROFILES_CONFIG);
        this.profiles = StringUtil.isBlank(configuredProfiles)
                ? List.of(defaultProfile(authConfig))
                : parseProfiles(configuredProfiles);
        validateProfiles(this.profiles);
    }

    public List<AuthenticationProfile> getProfiles() {
        return profiles;
    }

    public AuthenticationProfile getProfile(String profileId) {
        String requestedProfile = StringUtil.isBlank(profileId) ? AuthenticationProfile.DEFAULT_PROFILE_ID : profileId;
        if (AuthenticationProfile.DEFAULT_PROFILE_ID.equals(requestedProfile)) {
            return profiles.stream()
                    .filter(AuthenticationProfile::isDefaultProfile)
                    .findFirst()
                    .orElseGet(profiles::getFirst);
        }
        return profiles.stream()
                .filter(profile -> Objects.equals(profile.getId(), requestedProfile))
                .findFirst()
                .orElseThrow(() ->
                        new IllegalArgumentException(String.format("Unknown OpenID4VP profile: %s", requestedProfile)));
    }

    public List<AuthenticationProfile> getProfilesForClient(String clientId) {
        return profiles.stream()
                .filter(profile -> profile.getEnabledForClients() == null
                        || profile.getEnabledForClients().isEmpty()
                        || profile.getEnabledForClients().contains(clientId))
                .toList();
    }

    private static List<AuthenticationProfile> parseProfiles(String profilesJson) {
        try {
            return JsonSerialization.mapper.readValue(
                    profilesJson,
                    JsonSerialization.mapper
                            .getTypeFactory()
                            .constructCollectionType(List.class, AuthenticationProfile.class));
        } catch (IOException e) {
            throw new IllegalStateException("Invalid OpenID4VP profiles configuration", e);
        }
    }

    private static AuthenticationProfile defaultProfile(AuthenticatorConfigModel authConfig) {
        AuthRequirements authRequirements = new AuthRequirements(authConfig);
        CredentialRequirement credential = new CredentialRequirement()
                .setId("identity")
                .setRole(CredentialRole.PRIMARY)
                .setFormat(CredentialFormat.SD_JWT_VC.getValue())
                .setCredentialTypes(authRequirements.getCredentialTypes())
                .setClaims(List.of(JsonWebToken.SUBJECT, OAuth2Constants.USERNAME));

        return new AuthenticationProfile()
                .setId(AuthenticationProfile.DEFAULT_PROFILE_ID)
                .setDisplayCta(Map.of("en", AuthenticationProfile.DEFAULT_CTA))
                .setCredentials(List.of(credential));
    }

    private static void validateProfiles(List<AuthenticationProfile> profiles) {
        if (profiles == null || profiles.isEmpty()) {
            throw new IllegalStateException("At least one OpenID4VP profile must be configured");
        }

        for (AuthenticationProfile profile : profiles) {
            String profileId = profile.getId();
            if (StringUtil.isBlank(profileId)) {
                throw new IllegalStateException("OpenID4VP profile id must not be blank");
            }

            if (profile.getCredentials() == null || profile.getCredentials().isEmpty()) {
                throw new IllegalStateException(
                        String.format("OpenID4VP profile must request at least one credential: %s", profileId));
            }

            long primaryCount = profile.getCredentials().stream()
                    .filter(CredentialRequirement::isPrimary)
                    .count();
            if (primaryCount != 1) {
                throw new IllegalStateException(
                        String.format("OpenID4VP profile must have exactly one primary credential: %s", profileId));
            }

            for (CredentialRequirement credential : profile.getCredentials()) {
                String credentialId = credential.getId();
                if (StringUtil.isBlank(credentialId)) {
                    throw new IllegalStateException(
                            String.format("OpenID4VP credential id must not be blank in profile: %s", profileId));
                }

                if (credential.getCredentialTypes() == null
                        || credential.getCredentialTypes().isEmpty()) {
                    throw new IllegalStateException(String.format(
                            "OpenID4VP credential must define credentialTypes values: %s/%s", profileId, credentialId));
                }

                if (credential.getClaims() == null || credential.getClaims().isEmpty()) {
                    throw new IllegalStateException(String.format(
                            "OpenID4VP credential must request at least one claim: %s/%s", profileId, credentialId));
                }

                if (CredentialFormat.MSO_MDOC.getValue().equals(credential.getFormat())) {
                    if (credential.getCredentialTypes().size() != 1) {
                        throw new IllegalStateException(String.format(
                                "mDoc credential must define exactly one credentialType (the docType): %s/%s",
                                profileId, credentialId));
                    }

                    for (ClaimReference ref : credential.getClaimReferences()) {
                        if (!ref.isNamespaced()) {
                            throw new IllegalStateException(String.format(
                                    "mDoc claims must be namespaced (\"namespace/name\"), got: %s in profile: %s/%s",
                                    ref.name(), profileId, credentialId));
                        }
                    }
                }

                validateTrustPolicy(credential, profileId);

                if (credential.isPrimary()) {
                    validatePrimaryCredential(profile, credential);
                }
            }

            long credentialIdCount = profile.getCredentials().stream()
                    .map(CredentialRequirement::getId)
                    .distinct()
                    .count();
            if (credentialIdCount != profile.getCredentials().size()) {
                throw new IllegalStateException(
                        String.format("OpenID4VP credential ids must be unique in profile: %s", profileId));
            }

            validateBindingRules(profile);
        }
    }

    private static void validateTrustPolicy(CredentialRequirement credential, String profileId) {
        List<TrustPolicy> trustPolicies = credential.getTrust();
        if (trustPolicies == null || trustPolicies.isEmpty()) {
            throw new IllegalStateException(String.format(
                    "Credential '%s/%s' must configure at least one trust policy", profileId, credential.getId()));
        }

        for (TrustPolicy trust : trustPolicies) {
            String type = trust.getType();
            if (StringUtil.isBlank(type)) {
                throw new IllegalStateException(
                        String.format("Trust policy type must not be blank: %s/%s", profileId, credential.getId()));
            }

            if (TrustPolicy.SELF.equals(type)) {
                if (CredentialFormat.MSO_MDOC.getValue().equals(credential.getFormat())) {
                    throw new IllegalStateException(String.format(
                            "Self-trust is not supported for mDoc credentials: %s/%s", profileId, credential.getId()));
                }
                continue;
            }

            if (!TrustPolicy.X5C.equals(type) && !TrustPolicy.EUDI_PID_TRUST_LIST.equals(type)) {
                throw new IllegalStateException(String.format(
                        "Unsupported trust policy type '%s': %s/%s", type, profileId, credential.getId()));
            }

            if (TrustPolicy.X5C.equals(type)) {
                List<X509Certificate> anchors = trust.getAnchors();
                if (anchors == null || anchors.isEmpty()) {
                    throw new IllegalStateException(String.format(
                            "x5c trust policy must declare at least one anchor: %s/%s", profileId, credential.getId()));
                }
            }
        }
    }

    private static void validateBindingRules(AuthenticationProfile profile) {
        String profileId = profile.getId();
        CredentialRequirement primary = profile.getPrimaryCredential();
        Set<String> primaryClaimNames = Set.copyOf(primary.getClaims());

        for (CredentialRequirement credential : profile.getCredentials()) {
            if (credential.isPrimary()) {
                continue;
            }

            Set<String> supportingClaimNames = Set.copyOf(credential.getClaims());

            for (BindingRule rule : credential.getBinding()) {
                if (StringUtil.isBlank(rule.getType())) {
                    throw new IllegalStateException(String.format(
                            "OpenID4VP binding rule type must not be blank: %s/%s", profileId, credential.getId()));
                }

                if (!BindingRule.CLAIM_EQUALS_PRIMARY_CLAIM.equals(rule.getType())
                        && !BindingRule.CLAIM_EQUALS_USER_ATTRIBUTE.equals(rule.getType())) {
                    throw new IllegalStateException(String.format(
                            "Unsupported OpenID4VP binding rule type '%s': %s/%s",
                            rule.getType(), profileId, credential.getId()));
                }

                if (StringUtil.isBlank(rule.getCredentialClaim())) {
                    throw new IllegalStateException(String.format(
                            "OpenID4VP binding rule credentialClaim must not be blank: %s/%s",
                            profileId, credential.getId()));
                }

                if (!supportingClaimNames.contains(rule.getCredentialClaim())) {
                    throw new IllegalStateException(String.format(
                            "OpenID4VP binding rule credentialClaim '%s' must be among the supporting"
                                    + " credential's requested claims: %s/%s",
                            rule.getCredentialClaim(), profileId, credential.getId()));
                }

                if (BindingRule.CLAIM_EQUALS_PRIMARY_CLAIM.equals(rule.getType())) {
                    if (StringUtil.isBlank(rule.getPrimaryCredentialClaim())) {
                        throw new IllegalStateException(String.format(
                                "OpenID4VP binding rule primaryCredentialClaim must not be blank for"
                                        + " type 'claim_equals_primary_claim': %s/%s",
                                profileId, credential.getId()));
                    }

                    if (!primaryClaimNames.contains(rule.getPrimaryCredentialClaim())) {
                        throw new IllegalStateException(String.format(
                                "OpenID4VP binding rule primaryCredentialClaim '%s' must be among the"
                                        + " primary credential's requested claims: %s/%s",
                                rule.getPrimaryCredentialClaim(), profileId, credential.getId()));
                    }
                }

                if (BindingRule.CLAIM_EQUALS_USER_ATTRIBUTE.equals(rule.getType())) {
                    if (StringUtil.isBlank(rule.getUserAttribute())) {
                        throw new IllegalStateException(String.format(
                                "OpenID4VP binding rule userAttribute must not be blank for"
                                        + " type 'claim_equals_user_attribute': %s/%s",
                                profileId, credential.getId()));
                    }
                }
            }
        }
    }

    /**
     * Validates the primary credential based on its identity source.
     *
     * <ul>
     *   <li>{@code credential} (login): the identity is derived from the presented credential, so it must
     *       request {@code sub} and {@code username}.
     *   <li>{@code session} (presentation during issuance): the identity comes from the brokered offer
     *       user, so {@code sub}/{@code username} are not required; instead binding rules are mandatory so
     *       the presented credential is actually matched against the user (otherwise the presentation
     *       requirement would be security-wise meaningless).
     * </ul>
     */
    private static void validatePrimaryCredential(AuthenticationProfile profile, CredentialRequirement credential) {
        if (credential.isSessionIdentity()) {
            if (credential.getBinding() == null || credential.getBinding().isEmpty()) {
                throw new IllegalStateException(
                        "OpenID4VP session-identity primary credential must define binding rules: " + profile.getId()
                                + "/" + credential.getId());
            }
            return;
        }
        List<ClaimReference> primaryRefs = credential.getClaimReferences();
        boolean hasSubject = primaryRefs.stream().anyMatch(ref -> JsonWebToken.SUBJECT.equals(ref.name()));
        boolean hasUsername = primaryRefs.stream().anyMatch(ref -> OAuth2Constants.USERNAME.equals(ref.name()));
        if (!hasSubject || !hasUsername) {
            throw new IllegalStateException("OpenID4VP primary credential must request sub and username: "
                    + profile.getId() + "/" + credential.getId());
        }
    }
}
