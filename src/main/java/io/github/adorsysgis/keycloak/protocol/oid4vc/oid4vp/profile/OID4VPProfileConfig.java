package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.PROFILES_CONFIG;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialFormat;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.AuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement.ClaimReference;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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

                if (credential.isPrimary()) {
                    List<ClaimReference> primaryRefs = credential.getClaimReferences();
                    boolean hasSubject = primaryRefs.stream().anyMatch(ref -> JsonWebToken.SUBJECT.equals(ref.name()));
                    boolean hasUsername =
                            primaryRefs.stream().anyMatch(ref -> OAuth2Constants.USERNAME.equals(ref.name()));
                    if (!hasSubject || !hasUsername) {
                        throw new IllegalStateException(String.format(
                                "OpenID4VP primary credential must request sub and username: %s/%s",
                                profileId, credentialId));
                    }
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
        }
    }
}
