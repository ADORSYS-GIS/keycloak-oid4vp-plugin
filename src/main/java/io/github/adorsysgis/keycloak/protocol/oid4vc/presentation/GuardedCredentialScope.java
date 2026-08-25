package io.github.adorsysgis.keycloak.protocol.oid4vc.presentation;

import static org.keycloak.constants.OID4VCIConstants.OID4VC_PROTOCOL;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
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
        return supportsPresentationMode(mode.getValue());
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
}
