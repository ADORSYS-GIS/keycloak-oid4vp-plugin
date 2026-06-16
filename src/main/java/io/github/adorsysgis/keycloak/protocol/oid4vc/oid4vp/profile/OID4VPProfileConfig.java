package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.PROFILES_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.VCT_CONFIG_DEFAULT;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthRequirements;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Parses and validates OpenID4VP authentication profiles.
 */
public class OID4VPProfileConfig {

    private final List<AuthenticationProfile> profiles;

    public OID4VPProfileConfig(KeycloakContext context, AuthenticatorConfigModel authConfig) {
        Map<String, String> config =
                (authConfig != null && authConfig.getConfig() != null) ? authConfig.getConfig() : Map.of();
        String configuredProfiles = config.get(PROFILES_CONFIG);
        this.profiles = StringUtil.isBlank(configuredProfiles)
                ? List.of(defaultProfile(context, authConfig))
                : parseProfiles(configuredProfiles);
        validateProfiles(this.profiles);
    }

    public List<AuthenticationProfile> getProfiles() {
        return profiles;
    }

    public AuthenticationProfile getProfile(String profileId) {
        String requestedProfile = StringUtil.isBlank(profileId) ? AuthenticationProfile.DEFAULT_PROFILE_ID : profileId;
        return profiles.stream()
                .filter(profile -> Objects.equals(profile.getId(), requestedProfile))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown OpenID4VP profile: " + requestedProfile));
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

    private static AuthenticationProfile defaultProfile(KeycloakContext context, AuthenticatorConfigModel authConfig) {
        SdJwtAuthRequirements authRequirements = new SdJwtAuthRequirements(context, authConfig);
        CredentialRequirement credential = new CredentialRequirement()
                .setId("identity")
                .setRole(CredentialRole.PRIMARY)
                .setCredentialTypes(
                        authRequirements.getExpectedVcts().isEmpty()
                                ? List.of(VCT_CONFIG_DEFAULT)
                                : authRequirements.getExpectedVcts())
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
            if (StringUtil.isBlank(profile.getId())) {
                throw new IllegalStateException("OpenID4VP profile id must not be blank");
            }
            if (profile.getCredentials() == null || profile.getCredentials().isEmpty()) {
                throw new IllegalStateException(
                        "OpenID4VP profile must request at least one credential: " + profile.getId());
            }
            long primaryCount = profile.getCredentials().stream()
                    .filter(CredentialRequirement::isPrimary)
                    .count();
            if (primaryCount != 1) {
                throw new IllegalStateException(
                        "OpenID4VP profile must have exactly one primary credential: " + profile.getId());
            }

            for (CredentialRequirement credential : profile.getCredentials()) {
                if (StringUtil.isBlank(credential.getId())) {
                    throw new IllegalStateException(
                            "OpenID4VP credential id must not be blank in profile: " + profile.getId());
                }
                if (credential.getCredentialTypes() == null
                        || credential.getCredentialTypes().isEmpty()) {
                    throw new IllegalStateException("OpenID4VP credential must define credentialTypes values: "
                            + profile.getId() + "/" + credential.getId());
                }
                if (credential.getClaims() == null || credential.getClaims().isEmpty()) {
                    throw new IllegalStateException("OpenID4VP credential must request at least one claim: "
                            + profile.getId() + "/" + credential.getId());
                }
                if (credential.isPrimary()
                        && (!credential.getClaims().contains(JsonWebToken.SUBJECT)
                                || !credential.getClaims().contains(OAuth2Constants.USERNAME))) {
                    throw new IllegalStateException("OpenID4VP primary credential must request sub and username: "
                            + profile.getId() + "/" + credential.getId());
                }
            }

            long credentialIdCount = profile.getCredentials().stream()
                    .map(CredentialRequirement::getId)
                    .distinct()
                    .count();
            if (credentialIdCount != profile.getCredentials().size()) {
                throw new IllegalStateException(
                        "OpenID4VP credential ids must be unique in profile: " + profile.getId());
            }
        }
    }
}
