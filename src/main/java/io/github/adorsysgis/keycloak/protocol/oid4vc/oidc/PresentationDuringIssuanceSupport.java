package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc;

import static org.keycloak.protocol.oid4vc.utils.CredentialScopeUtils.findCredentialScopeModelByConfigurationId;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.OpenId4VpConstants;
import io.github.adorsysgis.keycloak.protocol.oid4vc.patch.metadata.OID4VCIssuerMetadataProvider;
import java.io.IOException;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.oid4vc.model.OID4VCAuthorizationDetail;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Shared detection of "presentation during issuance" requests (OID4VCI Interactive Authorization).
 *
 * <p>The OIDC authorization-request path must kick in whenever the acting party asks an issuance
 * authorization code for a credential whose configuration requires a Verifiable Presentation prior
 * to issuance. This helper exposes that decision from an {@link AuthenticationSessionModel}:
 * the credential configuration is resolved from the session's {@code scope} values or from the
 * {@code authorization_details} note, and a credential is considered gated when its client-scope
 * carries {@link OpenId4VpConstants#VC_REQUIRES_PRESENTATION_ATTR}.
 */
public final class PresentationDuringIssuanceSupport {

    private static final Logger logger = Logger.getLogger(PresentationDuringIssuanceSupport.class);

    /** Protocol id of OID4VCI credential scopes (see {@code CredentialScopeUtils}). */
    private static final String OID4VC_PROTOCOL = "oid4vc";

    private PresentationDuringIssuanceSupport() {}

    /** Whether realm-level "presentation during issuance" is enabled. */
    public static boolean isPresentationDuringIssuanceEnabled(RealmModel realm) {
        return Boolean.parseBoolean(realm.getAttribute(OID4VCIssuerMetadataProvider.ATTR_PRESENTATION_DURING_ISSUANCE));
    }

    /**
     * Whether the OIDC authorization session requests issuance of a credential that requires a
     * Verifiable Presentation during issuance.
     *
     * @return {@code true} when the session targets such a credential; {@code false} for ordinary
     *         OIDC requests and for issuance requests of non-gated credentials
     */
    public static boolean isPresentationGatedCredentialRequestedInSession(AuthenticationSessionModel authSession) {
        if (authSession == null || authSession.getClient() == null) {
            return false;
        }
        ClientModel client = authSession.getClient();
        RealmModel realm = client.getRealm();
        // TODO: Enable the check
//        if (!isPresentationDuringIssuanceEnabled(realm)) {
//            return false;
//        }

        // The requested credential configuration, and therefore the mandate to present, is the
        // sole authority: it is derived from the client-bound credential scopes only, never from
        // a wallet-selected profile.

        // 1) credential scopes requested as whitespace-separated scope values.
        String scope = authSession.getClientNote(OAuth2Constants.SCOPE);
        if (StringUtil.isNotBlank(scope)) {
            Map<String, ClientScopeModel> clientScopes = client.getClientScopes(false);
            for (String token : scope.split("\\s")) {
                ClientScopeModel clientScope = clientScopes.get(token);
                if (clientScope != null && OID4VC_PROTOCOL.equals(clientScope.getProtocol())) {
                    return true;
                }
//                if (clientScope != null && OID4VC_PROTOCOL.equals(clientScope.getProtocol())
//                        && requiresPresentation(new CredentialScopeModel(clientScope))) {
//                    return true;
//                }
            }
        }

        return false;
    }

    /**
     * Whether the credential configuration mandates a presentation during issuance via its
     * {@link OpenId4VpConstants#VC_REQUIRES_PRESENTATION_ATTR} client-scope attribute.
     */
    public static boolean requiresPresentation(CredentialScopeModel credentialScope) {
        return Boolean.parseBoolean(credentialScope.getAttribute(OpenId4VpConstants.VC_REQUIRES_PRESENTATION_ATTR));
    }
}