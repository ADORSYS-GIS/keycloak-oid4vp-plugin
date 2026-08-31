package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode.NESTED_OID4VP_FLOW;

import io.github.adorsysgis.keycloak.protocol.oid4vc.patch.metadata.OID4VCIssuerMetadataProvider;
import io.github.adorsysgis.keycloak.protocol.oid4vc.presentation.GuardedCredentialScope;
import java.util.Optional;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.issuance.credentialoffer.CredentialOfferState;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Detects and resolves presentation-during-issuance state from a running OIDC authentication session.
 *
 * <p>All runtime detection is gated on the realm attribute
 * {@code oid4vci.presentation_during_issuance}: when it is unset or false, no session is treated as
 * requiring nested presentation, so the login flow renders an ordinary login and the issuance gate
 * still refuses gated credentials for want of a verified-presentation marker.
 *
 * <p>Credential request resolution (issuer_state / authorization_details / scope) is delegated to
 * {@link CredentialRequestResolver}, which enforces a single-credential cardinality contract.
 */
public final class PresentationDuringIssuanceService {

    private final RealmModel realm;
    private final GuardedCredentialScope requestedCredentialScope;
    private final CredentialOfferState requestedCredentialOfferState;

    public PresentationDuringIssuanceService(KeycloakSession session, AuthenticationSessionModel authSession) {
        this.realm = authSession == null ? null : authSession.getRealm();
        this.requestedCredentialOfferState = CredentialRequestResolver.resolveCredentialOffer(session, authSession);
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
        return realm != null
                && Boolean.parseBoolean(
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
     * Resolves the credential requested for issuance, if any. Delegates to
     * {@link CredentialRequestResolver} for the shared issuer_state / authorization_details /
     * scope resolution with its single-credential cardinality contract.
     */
    private static GuardedCredentialScope resolveRequestedCredential(
            AuthenticationSessionModel authSession, CredentialOfferState requestedCredentialOfferState) {
        if (authSession == null || authSession.getClient() == null) {
            return null;
        }

        return CredentialRequestResolver.resolveCredentialScope(
                authSession.getClient().getRealm(),
                authSession.getClient(),
                authSession.getClientNote(OAuth2Constants.SCOPE),
                authSession.getClientNote(OAuth2Constants.AUTHORIZATION_DETAILS),
                requestedCredentialOfferState);
    }
}
