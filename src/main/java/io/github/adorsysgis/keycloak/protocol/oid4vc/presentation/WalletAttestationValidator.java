package io.github.adorsysgis.keycloak.protocol.oid4vc.presentation;

import static org.keycloak.authentication.authenticators.client.AttestationBasedClientAuthenticator.OAUTH_CLIENT_ATTESTATION_HEADER;
import static org.keycloak.authentication.authenticators.client.AttestationBasedClientAuthenticator.OAUTH_CLIENT_ATTESTATION_POP_HEADER;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.CorsService;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.utils.StringUtil;

/**
 * Validates the OAuth 2.0 Attestation-Based Client Authentication material (a Wallet Attestation)
 * that a wallet includes on an Authorization Challenge Request when the Authorization Server
 * requires it (OID4VCI §6.1, Note; draft-ietf-oauth-attestation-based-client-auth).
 *
 * <p>Keycloak's {@code AttestationBasedClientAuthenticator} performs the JWT validation through the
 * realm's client-authentication flow. This adapter invokes that supported flow for the public
 * Authorization Challenge Endpoint while preserving the endpoint's missing-header response.
 */
public final class WalletAttestationValidator {

    private WalletAttestationValidator() {}

    /**
     * Validates the wallet attestation headers of the current request through Keycloak's
     * client-authentication flow.
     *
     * @throws WebApplicationException if the attestation is missing or invalid
     */
    public static void validate(KeycloakSession session, EventBuilder event) {
        HttpHeaders headers = session.getContext().getHttpRequest().getHttpHeaders();
        String attestationValue = headers.getHeaderString(OAUTH_CLIENT_ATTESTATION_HEADER);
        String attestationPoPValue = headers.getHeaderString(OAUTH_CLIENT_ATTESTATION_POP_HEADER);

        if (StringUtil.isBlank(attestationValue) || StringUtil.isBlank(attestationPoPValue)) {
            throw invalidAttestation(String.format(
                    "A wallet attestation is required: both %s and %s headers must be present",
                    OAUTH_CLIENT_ATTESTATION_HEADER, OAUTH_CLIENT_ATTESTATION_POP_HEADER));
        }

        AuthenticationFlowModel clientAuthenticationFlow =
                session.getContext().getRealm().getClientAuthenticationFlow();
        if (clientAuthenticationFlow == null) {
            throw invalidAttestation("No client authentication flow is configured");
        }

        Response response = new AuthenticationProcessor()
                .setRealm(session.getContext().getRealm())
                .setSession(session)
                .setRequest(session.getContext().getHttpRequest())
                .setConnection(session.getContext().getConnection())
                .setUriInfo(session.getContext().getUri())
                .setEventBuilder(event.clone().event(EventType.CLIENT_LOGIN))
                .setFlowId(clientAuthenticationFlow.getId())
                .authenticateClient();
        if (response != null) {
            throw new WebApplicationException(response);
        }
    }

    private static BadRequestException invalidAttestation(String description) {
        var error = new OAuth2ErrorRepresentation(OAuthErrorException.INVALID_CLIENT_ATTESTATION, description);
        return new BadRequestException(CorsService.open()
                .add(Response.status(Response.Status.BAD_REQUEST).entity(error).type(MediaType.APPLICATION_JSON)));
    }
}
