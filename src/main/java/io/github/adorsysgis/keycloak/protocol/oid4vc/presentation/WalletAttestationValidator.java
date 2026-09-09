package io.github.adorsysgis.keycloak.protocol.oid4vc.presentation;

import static org.keycloak.authentication.authenticators.client.AttestationBasedClientAuthenticator.OAUTH_CLIENT_ATTESTATION_HEADER;
import static org.keycloak.authentication.authenticators.client.AttestationBasedClientAuthenticator.OAUTH_CLIENT_ATTESTATION_POP_HEADER;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.CorsService;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.authentication.ClientAuthenticator;
import org.keycloak.authentication.ClientAuthenticatorFactory;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.authentication.authenticators.client.AttestationBasedClientAuthenticator;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;

/**
 * Validates the OAuth 2.0 Attestation-Based Client Authentication material (a Wallet Attestation)
 * that a wallet includes on an Authorization Challenge Request when the Authorization Server
 * requires it (OID4VCI §6.1, Note; draft-ietf-oauth-attestation-based-client-auth).
 *
 * <p>Keycloak's {@code AttestationBasedClientAuthenticator} performs the JWT validation. This adapter
 * invokes that provider through a client-authentication context containing only the attestation
 * execution, so validation does not depend on the realm's other client-authentication methods.
 */
public final class WalletAttestationValidator {

    static final String AUTHORIZATION_CHALLENGE_EVENT_CONTEXT = "oid4vci-authorization-challenge";

    private WalletAttestationValidator() {}

    /**
     * Validates the wallet attestation headers of the current request through Keycloak's
     * client-authentication flow.
     *
     * @throws WebApplicationException if the attestation is missing or invalid
     */
    public static void validate(KeycloakSession session, EventBuilder event) {
        AuthenticationProcessor processor = new AuthenticationProcessor()
                .setRealm(session.getContext().getRealm())
                .setSession(session)
                .setRequest(session.getContext().getHttpRequest())
                .setConnection(session.getContext().getConnection())
                .setUriInfo(session.getContext().getUri())
                .setEventBuilder(event.clone()
                        .event(EventType.CLIENT_LOGIN)
                        .detail(Details.CONTEXT, AUTHORIZATION_CHALLENGE_EVENT_CONTEXT));

        ProviderFactory providerFactory = session.getKeycloakSessionFactory()
                .getProviderFactory(ClientAuthenticator.class, AttestationBasedClientAuthenticator.PROVIDER_ID);
        if (!(providerFactory instanceof ClientAuthenticatorFactory factory)) {
            throw invalidAttestation("Keycloak's attestation-based client authenticator is unavailable");
        }

        ClientAuthenticator authenticator = factory.create();
        AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
        execution.setAuthenticator(factory.getId());
        execution.setRequirement(AuthenticationExecutionModel.Requirement.REQUIRED);

        AuthenticationProcessor.Result context =
                processor.createClientAuthenticatorContext(execution, authenticator, List.of(execution));
        try {
            authenticator.authenticateClient(context);
        } catch (RuntimeException e) {
            String description = e.getMessage() == null ? "Wallet attestation validation failed" : e.getMessage();
            throw invalidAttestation(description);
        }

        if (FlowStatus.SUCCESS.equals(context.getStatus()) && context.getClient() != null) {
            return;
        }

        if (context.getChallenge() != null) {
            throw new WebApplicationException(CorsService.open().add(Response.fromResponse(context.getChallenge())));
        }

        throw invalidAttestation(String.format(
                "A wallet attestation is required: both %s and %s headers must be present",
                OAUTH_CLIENT_ATTESTATION_HEADER, OAUTH_CLIENT_ATTESTATION_POP_HEADER));
    }

    private static BadRequestException invalidAttestation(String description) {
        var error = new OAuth2ErrorRepresentation(OAuthErrorException.INVALID_CLIENT_ATTESTATION, description);
        return new BadRequestException(CorsService.open()
                .add(Response.status(Response.Status.BAD_REQUEST).entity(error).type(MediaType.APPLICATION_JSON)));
    }
}
