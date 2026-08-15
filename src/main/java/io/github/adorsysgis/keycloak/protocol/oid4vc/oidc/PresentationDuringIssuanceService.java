package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc;

import static org.keycloak.constants.OID4VCIConstants.OID4VC_PROTOCOL;
import static org.keycloak.protocol.oid4vc.utils.CredentialScopeUtils.findCredentialScopeModelByConfigurationId;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.presentation.GuardedCredentialScope;
import java.io.IOException;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.ClientModel;
import org.keycloak.models.ClientScopeModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.oid4vc.issuance.credentialoffer.CredentialOfferState;
import org.keycloak.protocol.oid4vc.issuance.credentialoffer.CredentialOfferStorage;
import org.keycloak.protocol.oid4vc.model.IssuerState;
import org.keycloak.protocol.oid4vc.model.OID4VCAuthorizationDetail;
import org.keycloak.protocol.oidc.endpoints.AuthorizationEndpoint;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Resolves OID4VCI presentation-during-issuance state for OIDC authorization requests.
 *
 * <p>The requested credential configuration is resolved from {@code authorization_details}, falling
 * back to the scope-only form used by OID4VCI.
 */
public final class PresentationDuringIssuanceService {

    private static final Logger logger = Logger.getLogger(PresentationDuringIssuanceService.class);

    private final KeycloakSession session;

    public PresentationDuringIssuanceService(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Whether the OIDC authorization session requests issuance of a credential that requires a
     * Verifiable Presentation during issuance.
     *
     * @return {@code true} when the session targets such a credential; {@code false} for ordinary
     *         OIDC requests and for issuance requests of non-gated credentials
     */
    public boolean isPresentationGatedCredentialRequestedInSession(AuthenticationSessionModel authSession) {
        return resolveRequestedCredentialScope(authSession) != null;
    }

    /**
     * Resolves the OID4VCI credential configuration requested by the OIDC authorization session that
     * additionally requires a Verifiable Presentation during issuance.
     *
     * <p>{@code authorization_details} are the ultimate ground truth: they are read from the session
     * note and their {@code credential_configuration_id} resolves the credential scope. When no
     * {@code authorization_details} are available, the {@code scope} values are used, mirroring the
     * OID4VCI "scope only" request handling. The credential configuration is the sole authority: the
     * mandate to present is never taken from a wallet-selected profile.
     *
     * @return the gated {@link CredentialScopeModel}, or {@code null} when the session does not request
     *         a presentation-gated credential (or it is gated via the nested OID4VP mode)
     */
    public CredentialScopeModel resolveRequestedCredentialScope(AuthenticationSessionModel authSession) {
        if (authSession == null || authSession.getClient() == null) {
            return null;
        }
        ClientModel client = authSession.getClient();
        RealmModel realm = client.getRealm();

        CredentialScopeModel fromAuthDetails = resolveFromAuthorizationDetails(authSession, client, realm);
        if (fromAuthDetails != null) {
            return fromAuthDetails;
        }
        return resolveFromScope(authSession, client);
    }

    /**
     * Resolves the requested credential scope from the {@code authorization_details} stored on the
     * session, or {@code null} when none are present, they cannot be parsed, or the credential is not
     * gated via the nested OID4VP mode.
     */
    private CredentialScopeModel resolveFromAuthorizationDetails(
            AuthenticationSessionModel authSession, ClientModel client, RealmModel realm) {
        String authorizationDetails = authSession.getClientNote(OAuth2Constants.AUTHORIZATION_DETAILS);
        String credentialConfigurationId = credentialConfigurationIdFromAuthorizationDetails(authorizationDetails);
        if (StringUtil.isBlank(credentialConfigurationId)) {
            return null;
        }
        CredentialScopeModel credentialScope = findCredentialScopeModelByConfigurationId(
                realm, () -> client.getClientScopes(false).values().stream(), credentialConfigurationId);
        return isNestedFlowGated(credentialScope) ? credentialScope : null;
    }

    private String credentialConfigurationIdFromAuthorizationDetails(String authorizationDetails) {
        if (StringUtil.isBlank(authorizationDetails)) {
            return null;
        }
        try {
            OID4VCAuthorizationDetail[] details =
                    JsonSerialization.mapper.readValue(authorizationDetails, OID4VCAuthorizationDetail[].class);
            for (OID4VCAuthorizationDetail detail : details) {
                if (detail != null && StringUtil.isNotBlank(detail.getCredentialConfigurationId())) {
                    return detail.getCredentialConfigurationId();
                }
            }
            return null;
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /**
     * Resolves the requested credential scope from the {@code scope} values (a "scope only" request,
     * mirroring OID4VCI's missing-authorization-details handling).
     */
    private CredentialScopeModel resolveFromScope(AuthenticationSessionModel authSession, ClientModel client) {
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
            if (isNestedFlowGated(new CredentialScopeModel(clientScope))) {
                return new CredentialScopeModel(clientScope);
            }
        }
        return null;
    }

    /**
     * Whether the credential is gated via the {@code nested_oid4vp_flow} mode. This helper backs the
     * nested OID4VP flow (browser/IdP-driven) path only; a credential gated solely via
     * {@code interactive_authorization} must not be derailed here.
     */
    private boolean isNestedFlowGated(CredentialScopeModel credentialScope) {
        if (credentialScope == null) {
            return false;
        }
        GuardedCredentialScope hardened = GuardedCredentialScope.from(credentialScope);
        return hardened.requiresPresentation()
                && hardened.supportsPresentationMode(PresentationDuringIssuanceMode.NESTED_OID4VP_FLOW);
    }

    /**
     * The OpenID4VP authentication profile that MUST be enforced when presenting during issuance of
     * the credential requested by this session, taken from the credential configuration's
     * {@code vc.presentation_profile_id} client-scope attribute.
     *
     * @return the enforced profile id, or {@code null} when the session does not request a gated
     *         credential or its configuration carries no enforced profile
     */
    public String resolveEnforcedProfileId(AuthenticationSessionModel authSession) {
        CredentialScopeModel credentialScope = resolveRequestedCredentialScope(authSession);
        if (credentialScope == null) {
            return null;
        }
        return GuardedCredentialScope.from(credentialScope).getPresentationProfileId();
    }

    public String resolveOfferSubjectUserId(AuthenticationSessionModel authSession) {
        String issuerState = authSession.getClientNote(
                AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + OAuth2Constants.ISSUER_STATE);
        if (StringUtil.isBlank(issuerState)) {
            return null;
        }

        try {
            String offerId = IssuerState.fromEncodedString(issuerState).getCredentialsOfferId();
            if (StringUtil.isBlank(offerId)) {
                return null;
            }
            CredentialOfferState offer =
                    session.getProvider(CredentialOfferStorage.class).getOfferStateById(offerId);
            return offer == null ? null : offer.getTargetUserId();
        } catch (RuntimeException e) {
            logger.debugf(e, "Could not resolve credential offer subject");
            return null;
        }
    }
}
