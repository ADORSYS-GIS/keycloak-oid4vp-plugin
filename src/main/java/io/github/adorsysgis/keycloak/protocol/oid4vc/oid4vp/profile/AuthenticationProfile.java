package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.keycloak.utils.StringUtil;

public class AuthenticationProfile {

    public static final String DEFAULT_PROFILE_ID = "default";
    public static final String DEFAULT_CTA = "Sign in with a wallet";

    @JsonProperty("id")
    private String id;

    @JsonProperty("description")
    private String description;

    @JsonProperty("displayCta")
    private Map<String, String> displayCta;

    @JsonProperty("enabledForClients")
    private List<String> enabledForClients;

    @JsonProperty("credentials")
    private List<CredentialRequirement> credentials;

    public String getId() {
        return id;
    }

    public AuthenticationProfile setId(String id) {
        this.id = id;
        return this;
    }

    public String getDescription() {
        return description;
    }

    public AuthenticationProfile setDescription(String description) {
        this.description = description;
        return this;
    }

    public Map<String, String> getDisplayCta() {
        return displayCta;
    }

    public AuthenticationProfile setDisplayCta(Map<String, String> displayCta) {
        this.displayCta = displayCta;
        return this;
    }

    public List<String> getEnabledForClients() {
        return enabledForClients;
    }

    public AuthenticationProfile setEnabledForClients(List<String> enabledForClients) {
        this.enabledForClients = enabledForClients;
        return this;
    }

    public List<CredentialRequirement> getCredentials() {
        return credentials;
    }

    public AuthenticationProfile setCredentials(List<CredentialRequirement> credentials) {
        this.credentials = credentials;
        return this;
    }

    public String getDisplayCta(Locale locale) {
        if (displayCta == null || displayCta.isEmpty()) {
            return DEFAULT_CTA;
        }

        if (locale != null) {
            String language = locale.getLanguage();
            if (displayCta.containsKey(language)) {
                return displayCta.get(language);
            }
        }

        return displayCta.getOrDefault("en", displayCta.values().iterator().next());
    }

    public CredentialRequirement getPrimaryCredential() {
        return credentials.stream()
                .filter(CredentialRequirement::isPrimary)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Profile has no primary credential: " + id));
    }

    public CredentialRequirement getCredential(String credentialId) {
        return credentials.stream()
                .filter(credential -> credential.getId().equals(credentialId))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        "Profile does not define credential '%s': %s".formatted(credentialId, id)));
    }

    public boolean isDefaultProfile() {
        return StringUtil.isBlank(id) || DEFAULT_PROFILE_ID.equals(id);
    }
}
