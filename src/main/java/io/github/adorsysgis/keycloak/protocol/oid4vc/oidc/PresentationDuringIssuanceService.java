package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode.NESTED_OID4VP_FLOW;
import static org.keycloak.OID4VCConstants.OPENID_CREDENTIAL;
import static org.keycloak.constants.OID4VCIConstants.OID4VC_PROTOCOL;
import static org.keycloak.protocol.oid4vc.utils.CredentialScopeUtils.findCredentialScopeModelByConfigurationId;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.github.adorsysgis.keycloak.protocol.oid4vc.patch.metadata.OID4VCIssuerMetadataProvider;
import io.github.adorsysgis.keycloak.protocol.oid4vc.presentation.GuardedCredentialScope;
import jakarta.ws.rs.BadRequestException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
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
 * Detects and resolves presentation-during-issuance state from a running OIDC authentication session.
 *
 * <p>All runtime detection is gated on the realm attribute
 * {@code oid4vci.presentation_during_issuance}: when it is unset or false, no session is treated as
 * requiring nested presentation, so the login flow renders an ordinary login and the issuance gate
 * still refuses gated credentials for want of a verified-presentation marker.
 */
public final class PresentationDuringIssuanceService {

    private static final Logger logger = Logger.getLogger(PresentationDuringIssuanceService.class);

    private static final String ISSUER_STATE_NOTE =
            AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + OAuth2Constants.ISSUER_STATE;

    private final RealmModel realm;
    private final GuardedCredentialScope requestedCredentialScope;
    private final CredentialOfferState requestedCredentialOfferState;

    public PresentationDuringIssuanceService(KeycloakSession session, AuthenticationSessionModel authSession) {
        this.realm = authSession == null ? null : authSession.getRealm();
        this.requestedCredentialOfferState = resolveCredentialOffer(session, authSession);
        this.requestedCredentialScope = resolveRequestedCredential(authSession, requestedCredentialOfferState);
    }

    /**
     * Whether this session requires a nested presentation for credential issuance.
     */
    public boolean requiresNestedPresentationDuringIssuance() {
        return presentationDuringIssuanceEnabled()
                && requestedCredentialScope != null
                && requestedCredentialScope.requiresPresentation()
                && requestedCredentialScope.supportsPresentationMode(NESTED_OID4VP_FLOW);
    }

    private boolean presentationDuringIssuanceEnabled() {
        return realm != null && Boolean.parseBoolean(
                realm.getAttribute(OID4VCIssuerMetadataProvider.ATTR_PRESENTATION_DURING_ISSUANCE));
    }

    /**
     * Resolves the profile enforced by the requested credential configuration.
     */
    public String resolveEnforcedProfileId() {
        return Optional.ofNullable(requestedCredentialScope)
                .map(GuardedCredentialScope::getPresentationProfileId)
                .orElse(null);
    }

    /**
     * Resolves the user targeted by the credential offer referenced by the session, if any.
     */
    public String resolveOfferSubjectUserId() {
        return Optional.ofNullable(requestedCredentialOfferState)
                .map(CredentialOfferState::getTargetUserId)
                .orElse(null);
    }

    /**
     * Resolve credential requested for issuance if any.
     */
    private static GuardedCredentialScope resolveRequestedCredential(
            AuthenticationSessionModel authSession, CredentialOfferState requestedCredentialOfferState) {
        if (authSession == null || authSession.getClient() == null) {
            return null;
        }

        // Credentials can be requested either via issuer state, authorization details, or the scope param
        List<CredentialScopeModel> requestedCredentials = Optional.ofNullable(
                        resolveFromIssuerState(authSession, requestedCredentialOfferState))
                .orElseGet(() -> Optional.ofNullable(resolveFromAuthorizationDetails(authSession))
                        .orElseGet(() -> resolveFromScope(authSession)));

        if (requestedCredentials == null || requestedCredentials.isEmpty()) {
            return null;
        }

        if (requestedCredentials.size() > 1) {
            String errorMessage = "Credential endpoint does not support issuing multiple credential types";
            logger.debugf(
                    "%s (resolved %d credential configurations under request for issuance)",
                    errorMessage, requestedCredentials.size());
            throw new BadRequestException(errorMessage);
        }

        return GuardedCredentialScope.from(requestedCredentials.getFirst());
    }

    /**
     * Resolves the requested credential from the server-side credential offer referenced by issuer_state.
     */
    private static List<CredentialScopeModel> resolveFromIssuerState(
            AuthenticationSessionModel authSession, CredentialOfferState requestedCredentialOfferState) {
        if (requestedCredentialOfferState == null) {
            return null;
        }

        return requestedCredentialOfferState.getAuthorizationDetails().stream()
                .map(OID4VCAuthorizationDetail::getCredentialConfigurationId)
                .filter(Objects::nonNull)
                .map(credentialConfigurationId -> findCredentialScopeModelByConfigurationId(
                        authSession.getClient().getRealm(),
                        () -> authSession.getClient().getClientScopes(false).values().stream(),
                        credentialConfigurationId))
                .filter(Objects::nonNull)
                .toList();
    }

    /**
     * Resolves the requested credential from the session's authorization details.
     */
    private static List<CredentialScopeModel> resolveFromAuthorizationDetails(AuthenticationSessionModel authSession) {
        String authorizationDetails = authSession.getClientNote(OAuth2Constants.AUTHORIZATION_DETAILS);
        if (StringUtil.isBlank(authorizationDetails)) {
            return null;
        }

        var credentialConfigurationIds = findCredentialConfigurationIds(authorizationDetails);
        return credentialConfigurationIds.stream()
                .map(credentialConfigurationId -> findCredentialScopeModelByConfigurationId(
                        authSession.getClient().getRealm(),
                        () -> authSession.getClient().getClientScopes(false).values().stream(),
                        credentialConfigurationId))
                .filter(Objects::nonNull)
                .toList();
    }

    /**
     * Resolves the requested credential from requested scopes.
     */
    private static List<CredentialScopeModel> resolveFromScope(AuthenticationSessionModel authSession) {
        String scopeParam = authSession.getClientNote(OAuth2Constants.SCOPE);
        if (StringUtil.isBlank(scopeParam)) {
            return null;
        }

        Map<String, ClientScopeModel> clientScopes = authSession.getClient().getClientScopes(false);
        return Arrays.stream(scopeParam.split("\\s"))
                .map(clientScopes::get)
                .filter(clientScope -> clientScope != null && OID4VC_PROTOCOL.equals(clientScope.getProtocol()))
                .map(CredentialScopeModel::new)
                .toList();
    }

    /**
     * Resolves the credential offer referenced by an issuer state note. Invalid or unknown issuer
     * states are treated as absent so they cannot turn ordinary login into presentation during issuance.
     */
    public static CredentialOfferState resolveCredentialOffer(
            KeycloakSession session, AuthenticationSessionModel authSession) {
        String issuerState = Optional.ofNullable(authSession)
                .map(s -> s.getClientNote(ISSUER_STATE_NOTE))
                .orElse(null);

        try {
            return resolveCredentialOffer(session, issuerState);
        } catch (IllegalArgumentException e) {
            logger.debugf(e, "Could not resolve credential offer from issuer_state");
            return null;
        }
    }

    /**
     * Resolves a credential offer from an issuer state note.
     *
     * @return resolved offer state or {@code null} if no issuer state provided
     * @throws IllegalArgumentException if invalid issuer_state
     */
    public static CredentialOfferState resolveCredentialOffer(KeycloakSession session, String issuerState) {
        if (StringUtil.isBlank(issuerState)) {
            return null;
        }

        try {
            String offerId = IssuerState.fromEncodedString(issuerState).getCredentialsOfferId();
            if (StringUtil.isBlank(offerId)) {
                throw new IllegalArgumentException("No credentials_offer_id from issuer_state");
            }

            CredentialOfferState offerState =
                    session.getProvider(CredentialOfferStorage.class).getOfferStateById(offerId);
            if (offerState == null) {
                throw new IllegalArgumentException("Unknown or expired issuer_state");
            }

            return offerState;
        } catch (RuntimeException e) {
            logger.debugf(e, "Could not resolve credential offer from issuer_state");
            throw new IllegalArgumentException("Invalid issuer_state", e);
        }
    }

    private static List<String> findCredentialConfigurationIds(String authorizationDetails) {
        try {
            var details = JsonSerialization.mapper.readValue(authorizationDetails, OID4VCAuthorizationDetail[].class);
            return Arrays.stream(details)
                    .filter(d -> d != null && OPENID_CREDENTIAL.equals(d.getType()))
                    .map(OID4VCAuthorizationDetail::getCredentialConfigurationId)
                    .filter(Objects::nonNull)
                    .toList();
        } catch (JsonProcessingException e) {
            logger.debugf("Unable to parse authorization details", e);
            return List.of();
        }
    }
}
