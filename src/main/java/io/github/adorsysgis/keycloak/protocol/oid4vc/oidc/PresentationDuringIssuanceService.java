package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode.NESTED_OID4VP_FLOW;
import static org.keycloak.OID4VCConstants.OPENID_CREDENTIAL;
import static org.keycloak.constants.OID4VCIConstants.OID4VC_PROTOCOL;
import static org.keycloak.protocol.oid4vc.utils.CredentialScopeUtils.findCredentialScopeModelByConfigurationId;

import com.fasterxml.jackson.core.JsonProcessingException;
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
 */
public final class PresentationDuringIssuanceService {

    private static final Logger logger = Logger.getLogger(PresentationDuringIssuanceService.class);

    private static final String ISSUER_STATE_NOTE =
            AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + OAuth2Constants.ISSUER_STATE;

    private final GuardedCredentialScope requestedCredentialScope;
    private final CredentialOfferState requestedCredentialOfferState;

    public PresentationDuringIssuanceService(KeycloakSession session, AuthenticationSessionModel authSession) {
        this.requestedCredentialOfferState = resolveCredentialOfferState(session, authSession);
        this.requestedCredentialScope = resolveRequestedCredential(authSession, requestedCredentialOfferState);
    }

    /**
     * Whether this session requires a nested presentation for credential issuance.
     */
    public boolean requiresNestedPresentationDuringIssuance() {
        return requestedCredentialScope != null
                && requestedCredentialScope.requiresPresentation()
                && requestedCredentialScope.supportsPresentationMode(NESTED_OID4VP_FLOW);
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
            String issuerState = authSession.getClientNote(ISSUER_STATE_NOTE);
            return StringUtil.isBlank(issuerState) ? null : List.of();
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
     * Resolves credential offer state from expected issuer state client note.
     */
    private static CredentialOfferState resolveCredentialOfferState(
            KeycloakSession session, AuthenticationSessionModel authSession) {
        String offerId = Optional.ofNullable(authSession)
                .map(s -> s.getClientNote(ISSUER_STATE_NOTE))
                .filter(StringUtil::isNotBlank)
                .map(IssuerState::fromEncodedString)
                .map(IssuerState::getCredentialsOfferId)
                .orElse(null);

        if (StringUtil.isBlank(offerId)) {
            return null;
        }

        CredentialOfferState offer =
                session.getProvider(CredentialOfferStorage.class).getOfferStateById(offerId);

        if (offer == null) {
            logger.debugf("No credential offer found for attached offerId=%s", offerId);
        }

        return offer;
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
