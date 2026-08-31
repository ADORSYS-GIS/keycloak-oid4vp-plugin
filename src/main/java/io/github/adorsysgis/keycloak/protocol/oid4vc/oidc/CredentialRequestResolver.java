package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc;

import static org.keycloak.OID4VCConstants.OPENID_CREDENTIAL;
import static org.keycloak.protocol.oid4vc.utils.CredentialScopeUtils.findCredentialScopeModelByConfigurationId;
import static org.keycloak.protocol.oid4vc.utils.CredentialScopeUtils.findCredentialScopeModelByName;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.github.adorsysgis.keycloak.protocol.oid4vc.presentation.GuardedCredentialScope;
import jakarta.ws.rs.BadRequestException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.ClientModel;
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
 * Shared server-side resolver for the credential configuration requested by an OID4VCI
 * authorization request. The resolution follows a strict priority order:
 *
 * <ol>
 *   <li>{@code issuer_state} — the server-side credential offer bound to the issuer state,
 *   <li>{@code authorization_details} — the JSON-encoded OID4VCI authorization details,
 *   <li>{@code scope} — the OAuth 2.0 scope parameter (credential configuration name).
 * </ol>
 *
 * <p><strong>Cardinality contract:</strong> this resolver rejects requests that reference
 * multiple credential configurations. The OID4VCI credential endpoint issues one credential
 * at a time, so multiple configurations in a single request are not supported. Callers
 * relying on this resolver can assume a single credential scope or {@code null}.
 */
public final class CredentialRequestResolver {

    private static final Logger logger = Logger.getLogger(CredentialRequestResolver.class);

    private static final String ISSUER_STATE_NOTE =
            AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + OAuth2Constants.ISSUER_STATE;

    private CredentialRequestResolver() {}

    /**
     * Resolves the requested credential scope from the raw authorization request parameters.
     *
     * <p>The resolution priority is: {@code issuer_state} → {@code authorization_details} →
     * {@code scope}. Returns {@code null} when no credential configuration can be resolved,
     * or throws {@link BadRequestException} when multiple credential configurations are requested.
     *
     * @param realm the realm to search client scopes in
     * @param client the client the request is for
     * @param scope the OAuth 2.0 scope parameter, or {@code null}
     * @param authorizationDetails the OID4VCI authorization_details JSON, or {@code null}
     * @param offerState the resolved credential offer state (from issuer_state), or {@code null}
     * @return the resolved guarded credential scope, or {@code null} when no credential is requested
     * @throws BadRequestException when multiple credential configurations are requested
     */
    public static GuardedCredentialScope resolveCredentialScope(
            RealmModel realm,
            ClientModel client,
            String scope,
            String authorizationDetails,
            CredentialOfferState offerState) {

        if (client == null) {
            return null;
        }

        // Credentials can be requested either via issuer state, authorization details, or the scope param
        List<CredentialScopeModel> candidates = Optional.ofNullable(resolveFromIssuerState(realm, client, offerState))
                .orElseGet(
                        () -> Optional.ofNullable(resolveFromAuthorizationDetails(realm, client, authorizationDetails))
                                .orElseGet(() -> resolveFromScope(realm, client, scope)));

        if (candidates == null || candidates.isEmpty()) {
            return null;
        }

        if (candidates.size() > 1) {
            String errorMessage = "Credential endpoint does not support issuing multiple credential types";
            logger.debugf(
                    "%s (resolved %d credential configurations under request for issuance)",
                    errorMessage, candidates.size());
            throw new BadRequestException(errorMessage);
        }

        return GuardedCredentialScope.from(candidates.getFirst());
    }

    /**
     * Resolves a credential offer from an encoded issuer state string.
     *
     * @return resolved offer state or {@code null} if no issuer state provided
     * @throws IllegalArgumentException if the issuer state is invalid or references an unknown offer
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

    /**
     * Resolves the credential offer referenced by an issuer state note stored on the
     * authentication session. Invalid or unknown issuer states are treated as absent so
     * they cannot turn ordinary login into presentation during issuance.
     *
     * @return resolved offer state or {@code null} if no issuer state or invalid
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
     * Resolves the requested credential from the server-side credential offer referenced by issuer_state.
     */
    private static List<CredentialScopeModel> resolveFromIssuerState(
            RealmModel realm, ClientModel client, CredentialOfferState offerState) {
        if (offerState == null) {
            return null;
        }

        return offerState.getAuthorizationDetails().stream()
                .map(OID4VCAuthorizationDetail::getCredentialConfigurationId)
                .filter(Objects::nonNull)
                .map(credentialConfigurationId -> findCredentialScopeModelByConfigurationId(
                        realm, () -> client.getClientScopes(false).values().stream(), credentialConfigurationId))
                .filter(Objects::nonNull)
                .toList();
    }

    /**
     * Resolves the requested credential from the OID4VCI authorization_details JSON parameter.
     */
    private static List<CredentialScopeModel> resolveFromAuthorizationDetails(
            RealmModel realm, ClientModel client, String authorizationDetails) {
        if (StringUtil.isBlank(authorizationDetails)) {
            return null;
        }

        var credentialConfigurationIds = parseCredentialConfigurationIds(authorizationDetails);
        return credentialConfigurationIds.stream()
                .map(credentialConfigurationId -> findCredentialScopeModelByConfigurationId(
                        realm, () -> client.getClientScopes(false).values().stream(), credentialConfigurationId))
                .filter(Objects::nonNull)
                .toList();
    }

    /**
     * Resolves the requested credential from the OAuth 2.0 scope parameter.
     * The scope parameter may contain multiple space-separated values; each is looked up
     * by name against the client's OID4VC client scopes.
     */
    private static List<CredentialScopeModel> resolveFromScope(RealmModel realm, ClientModel client, String scope) {
        if (StringUtil.isBlank(scope)) {
            return null;
        }

        return Arrays.stream(scope.split("\\s"))
                .map(name -> findCredentialScopeModelByName(
                        realm, () -> client.getClientScopes(false).values().stream(), name))
                .filter(Objects::nonNull)
                .toList();
    }

    /**
     * Parses the OID4VCI authorization_details JSON and extracts credential configuration IDs
     * for entries with type {@code openid_credential}.
     */
    private static List<String> parseCredentialConfigurationIds(String authorizationDetails) {
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
