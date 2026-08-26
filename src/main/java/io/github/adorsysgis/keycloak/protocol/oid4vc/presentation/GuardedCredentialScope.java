package io.github.adorsysgis.keycloak.protocol.oid4vc.presentation;

import static org.keycloak.constants.OID4VCIConstants.OID4VC_PROTOCOL;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode;
import java.util.Arrays;
import java.util.stream.Collectors;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.utils.StringUtil;

/**
 * Extended {@link CredentialScopeModel} for credential configurations requiring
 * the presentation of some other credential(s) prior to and during issuance.
 * Encodes the "presentation during issuance" policy.
 */
public class GuardedCredentialScope extends CredentialScopeModel {

    /**
     * Configures whether the credential requires a Verifiable Presentation prior to issuance,
     * as a comma-separated list of {@link PresentationDuringIssuanceMode}'s to be accepted, e.g.,
     * {@code "interactive_authorization,nested_oid4vp_flow"}. A present yet blank configuration
     * is understood as accept any presentation during issuance mode. Do not include the attribute
     * to mean no presentation during issuance required.
     */
    public static final String VC_REQUIRES_PRESENTATION_ATTR = "vc.requires_presentation";

    /**
     * Configures the ID of the OpenID4VP authentication profile that MUST be enforced
     * when a presentation is required during issuance of this credential. It must be nonblank
     * whenever {@link #VC_REQUIRES_PRESENTATION_ATTR} is configured.
     */
    public static final String VC_PRESENTATION_PROFILE_ID_ATTR = "vc.presentation_profile_id";

    public GuardedCredentialScope(ClientScopeModel clientScope) {
        super(clientScope);
    }

    public static GuardedCredentialScope from(CredentialScopeModel credentialScope) {
        return credentialScope == null ? null : new GuardedCredentialScope(credentialScope);
    }

    /**
     * Validates all OID4VC credential scopes in a realm.
     *
     * @throws IllegalStateException if a scope contains an invalid policy
     */
    public static void validateRealm(RealmModel realm) {
        realm.getClientScopesStream()
                .filter(scope -> OID4VC_PROTOCOL.equals(scope.getProtocol()))
                .map(CredentialScopeModel::new)
                .map(GuardedCredentialScope::new)
                .forEach(GuardedCredentialScope::validateConfiguration);
    }

    /**
     * Validates the presentation-during-issuance attributes of this credential scope.
     *
     * @throws IllegalStateException if a configured mode is unknown or a gated
     *     credential has no presentation profile
     */
    public void validateConfiguration() {
        ConfigurationValidator.validate(this);
    }

    /**
     * Whether the credential requires a Verifiable Presentation prior to issuance.
     */
    public boolean requiresPresentation() {
        return getAttribute(VC_REQUIRES_PRESENTATION_ATTR) != null;
    }

    /**
     * The OpenID4VP authentication profile enforced when presenting during issuance of this
     * credential, or {@code null} when none is configured.
     */
    public String getPresentationProfileId() {
        String profileId = getAttribute(VC_PRESENTATION_PROFILE_ID_ATTR);
        return StringUtil.isBlank(profileId) ? null : profileId;
    }

    /**
     * Whether this credential supports the given mode of presentation during issuance.
     * A blank configured string is understood as accept any mode.
     */
    public boolean supportsPresentationMode(PresentationDuringIssuanceMode mode) {
        return mode != null && supportsPresentationMode(mode.getValue());
    }

    /**
     * Whether this credential supports the given mode of presentation during issuance.
     * A blank configured string is understood as accept any mode.
     */
    public boolean supportsPresentationMode(String mode) {
        if (mode == null) {
            return false;
        }

        String config = getAttribute(VC_REQUIRES_PRESENTATION_ATTR);
        if (StringUtil.isBlank(config)) {
            return true;
        }

        return Arrays.asList(config.split("[,\\s]+")).contains(mode);
    }

    /**
     * Whether the presentation was performed using the profile enforced by this credential.
     * A blank configured profile rejects every presentation — the safe default.
     */
    public boolean acceptPresentationProfile(String profileId) {
        String configuredProfileId = getPresentationProfileId();
        return configuredProfileId != null && configuredProfileId.equals(profileId);
    }

    /**
     * Encapsulates the validation rules for the presentation-during-issuance attributes of a
     * {@link GuardedCredentialScope}: a gated credential must reference a nonblank presentation
     * profile, and every configured presentation mode must be a supported
     * {@link PresentationDuringIssuanceMode} value.
     */
    private static final class ConfigurationValidator {

        private final String scopeName;
        private final String modesConfig;
        private final String profileId;

        private ConfigurationValidator(GuardedCredentialScope scope) {
            this.scopeName = scope.getName();
            this.modesConfig = scope.getAttribute(VC_REQUIRES_PRESENTATION_ATTR);
            this.profileId = scope.getAttribute(VC_PRESENTATION_PROFILE_ID_ATTR);
        }

        private static void validate(GuardedCredentialScope scope) {
            new ConfigurationValidator(scope).validate();
        }

        private void validate() {
            if (modesConfig == null) {
                return;
            }
            requirePresentationProfileId();
            validateModes();
        }

        private void requirePresentationProfileId() {
            if (!StringUtil.isBlank(profileId)) {
                return;
            }
            throw new IllegalStateException(String.format(
                    "Invalid configuration for OID4VC client scope '%s': '%s' requires presentation during issuance "
                            + "but '%s' is blank or missing. Configure a nonblank presentation profile id.",
                    scopeName, VC_REQUIRES_PRESENTATION_ATTR, VC_PRESENTATION_PROFILE_ID_ATTR));
        }

        private void validateModes() {
            if (StringUtil.isBlank(modesConfig)) {
                return;
            }

            for (String value : modesConfig.split("[,\\s]+")) {
                try {
                    PresentationDuringIssuanceMode.fromValue(value);
                } catch (IllegalArgumentException e) {
                    String supportedValues = Arrays.stream(PresentationDuringIssuanceMode.values())
                            .map(PresentationDuringIssuanceMode::getValue)
                            .collect(Collectors.joining(", "));
                    throw new IllegalStateException(String.format(
                            "Invalid configuration for OID4VC client scope '%s': '%s' contains unsupported value "
                                    + "'%s'. Supported values are [%s].",
                            scopeName, VC_REQUIRES_PRESENTATION_ATTR, value, supportedValues));
                }
            }
        }
    }
}
