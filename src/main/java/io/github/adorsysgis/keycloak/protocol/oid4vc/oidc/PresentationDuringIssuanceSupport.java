package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.HardenedCredentialScope;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.PresentationDuringIssuanceMode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.patch.metadata.OID4VCIssuerMetadataProvider;
import java.util.Map;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

/**
 * Shared detection of "presentation during issuance" requests (OID4VCI Interactive Authorization).
 *
 * <p>The OIDC authorization-request path must kick in whenever the acting party asks an issuance
 * authorization code for a credential whose configuration requires a Verifiable Presentation prior
 * to issuance. This helper exposes that decision from an {@link AuthenticationSessionModel}: the
 * credential configuration is resolved from the session's {@code scope} values, and a credential is
 * considered gated when its client-scope {@code vc.requires_presentation} attribute mandates it.
 */
public final class PresentationDuringIssuanceSupport {

    /** Protocol id of OID4VCI credential scopes (see {@code CredentialScopeUtils}). */
    private static final String OID4VC_PROTOCOL = "oid4vc";

    /**
     * Client-session note set on the OIDC authentication session the first time its redirect is
     * derailed into a same-device OpenID4VP presentation during issuance. It guarantees the
     * {@code buildRedirectUri} interception runs at most once per authorization request: when the
     * presentation completes and the normal OIDC login flow resumes on the <em>same</em>
     * authentication session, the resumed redirect must pass through to the invoking party instead
     * of being derailed a second time (which would otherwise loop).
     */
    public static final String PRESENTATION_TAKEN_OVER_NOTE = "oid4vp.presentation_taken_over";

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
        return resolveRequestedCredentialScope(authSession) != null;
    }

    /**
     * Resolves the OID4VCI credential configuration requested by the OIDC authorization session that
     * additionally requires a Verifiable Presentation during issuance. The credential configuration is
     * derived from the client-bound credential scopes requested as whitespace-separated {@code scope}
     * values. It is the sole authority: the mandate to present is never taken from a wallet-selected
     * profile.
     *
     * @return the gated {@link CredentialScopeModel}, or {@code null} when the session does not request
     *         a presentation-gated credential
     */
    public static CredentialScopeModel resolveRequestedCredentialScope(AuthenticationSessionModel authSession) {
        if (authSession == null || authSession.getClient() == null) {
            return null;
        }
        ClientModel client = authSession.getClient();
        String scope = authSession.getClientNote(OAuth2Constants.SCOPE);
        if (StringUtil.isBlank(scope)) {
            return null;
        }
        Map<String, ClientScopeModel> clientScopes = client.getClientScopes(false);
        for (String token : scope.split("\\s")) {
            ClientScopeModel clientScope = clientScopes.get(token);
            if (clientScope == null || !OID4VC_PROTOCOL.equals(clientScope.getProtocol())) {
                continue;
            }
            CredentialScopeModel credentialScope = new CredentialScopeModel(clientScope);
            HardenedCredentialScope hardened = HardenedCredentialScope.from(credentialScope);
            // This helper backs the nested_oid4vp_flow (browser/IdP-driven) path only. A credential that
            // does not explicitly support that mode must not be derailed here, even if it is
            // presentation-gated via interactive_authorization.
            if (hardened.requiresPresentation()
                    && hardened.supportsPresentationMode(PresentationDuringIssuanceMode.NESTED_OID4VP_FLOW)) {
                return credentialScope;
            }
        }
        return null;
    }

    /**
     * The OpenID4VP authentication profile that MUST be enforced when presenting during issuance of
     * the credential requested by this session, taken from the credential configuration's
     * {@code vc.presentation_profile_id} client-scope attribute.
     *
     * @return the enforced profile id, or {@code null} when the session does not request a gated
     *         credential or its configuration carries no enforced profile
     */
    public static String resolveEnforcedProfileId(AuthenticationSessionModel authSession) {
        CredentialScopeModel credentialScope = resolveRequestedCredentialScope(authSession);
        if (credentialScope == null) {
            return null;
        }
        return HardenedCredentialScope.from(credentialScope).presentationProfileId();
    }

    /** Whether the OIDC authentication session has already been derailed into a presentation. */
    public static boolean isPresentationTakenOver(AuthenticationSessionModel authSession) {
        return authSession != null
                && Boolean.parseBoolean(authSession.getClientNote(PRESENTATION_TAKEN_OVER_NOTE));
    }

    /** Marks the OIDC authentication session as already derailed into a presentation. */
    public static void markPresentationTakenOver(AuthenticationSessionModel authSession) {
        authSession.setClientNote(PRESENTATION_TAKEN_OVER_NOTE, Boolean.TRUE.toString());
    }
}