package io.github.adorsysgis.keycloak.protocol.oid4vc.presentation;

import static org.keycloak.authentication.authenticators.client.AttestationBasedClientAuthenticator.OAUTH_CLIENT_ATTESTATION_CONFIG_TRUST_IDPS;
import static org.keycloak.authentication.authenticators.client.AttestationBasedClientAuthenticator.OAUTH_CLIENT_ATTESTATION_HEADER;
import static org.keycloak.authentication.authenticators.client.AttestationBasedClientAuthenticator.OAUTH_CLIENT_ATTESTATION_JWT_TYPE;
import static org.keycloak.authentication.authenticators.client.AttestationBasedClientAuthenticator.OAUTH_CLIENT_ATTESTATION_POP_HEADER;
import static org.keycloak.authentication.authenticators.client.AttestationBasedClientAuthenticator.OAUTH_CLIENT_ATTESTATION_POP_JWT_TYPE;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.CorsService;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.OAuthErrorException;
import org.keycloak.TokenVerifier;
import org.keycloak.authentication.authenticators.client.AttestationBasedClientAuthenticator.ClientAttestationJwt;
import org.keycloak.authentication.authenticators.client.AttestationBasedClientAuthenticator.ClientAttestationPoPJwt;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.broker.provider.TrustMaterialResolver;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCWellKnownProviderFactory;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.utils.StringUtil;
import org.keycloak.wellknown.WellKnownProvider;

/**
 * Validates the OAuth 2.0 Attestation-Based Client Authentication material (a Wallet Attestation)
 * that a wallet includes on an Authorization Challenge Request when the Authorization Server
 * requires it (OID4VCI §6.1, Note; draft-ietf-oauth-attestation-based-client-auth).
 *
 * <p>The checks mirror {@code AttestationBasedClientAuthenticator} but run outside the client
 * authentication flow, since the Authorization Challenge Endpoint is a public {@code RealmResource}.
 * The Client Attestation JWT signature is verified against a trusted attester key (resolved from the
 * client's {@code attester_trust_idps} configuration), and the Client Attestation PoP JWT is verified
 * against the key confirmed in the attestation's {@code cnf} claim and bound to this Authorization
 * Server via its {@code aud} claim.
 */
public final class WalletAttestationValidator {

    // TODO: Investigate reusing Keycloak's wallet/client-attestation validation from this
    // RealmResource endpoint instead of mirroring the implementation here.
    private static final Logger logger = Logger.getLogger(WalletAttestationValidator.class);

    private WalletAttestationValidator() {}

    /**
     * Validates the wallet attestation headers of the current request for the given client.
     *
     * @throws BadRequestException if the attestation is missing or invalid
     */
    public static void validate(KeycloakSession session, String clientId) {
        HttpHeaders headers = session.getContext().getHttpRequest().getHttpHeaders();
        String attestationValue = headers.getHeaderString(OAUTH_CLIENT_ATTESTATION_HEADER);
        String attestationPoPValue = headers.getHeaderString(OAUTH_CLIENT_ATTESTATION_POP_HEADER);

        if (StringUtil.isBlank(attestationValue) || StringUtil.isBlank(attestationPoPValue)) {
            throw invalidAttestation(String.format(
                    "A wallet attestation is required: both %s and %s headers must be present",
                    OAUTH_CLIENT_ATTESTATION_HEADER, OAUTH_CLIENT_ATTESTATION_POP_HEADER));
        }

        try {
            ClientAttestationJwt attestationJwt = validateAttestationJwt(session, attestationValue, clientId);
            validateAttestationPoPJwt(session, attestationPoPValue, attestationJwt);
        } catch (BadRequestException e) {
            throw e;
        } catch (Exception e) {
            logger.debugf(e, "Wallet attestation validation failed");
            throw invalidAttestation(e.getMessage());
        }
    }

    private static ClientAttestationJwt validateAttestationJwt(
            KeycloakSession session, String headerValue, String clientId) throws Exception {
        JWSInput jws = new JWSInput(headerValue);
        String jwsType = jws.getHeader().getType();
        if (!OAUTH_CLIENT_ATTESTATION_JWT_TYPE.equals(jwsType)) {
            throw invalidAttestation("The Client Attestation JWS type MUST be " + OAUTH_CLIENT_ATTESTATION_JWT_TYPE);
        }

        ClientAttestationJwt attestationJwt = jws.readJsonContent(ClientAttestationJwt.class);

        if (StringUtil.isNotBlank(clientId) && !clientId.equals(attestationJwt.getSubject())) {
            throw invalidAttestation("The sub claim of the Client Attestation MUST match the client_id");
        }
        if (StringUtil.isBlank(attestationJwt.getIssuer())) {
            throw invalidAttestation("The Client Attestation MUST contain an iss (issuer) claim");
        }
        if (attestationJwt.getConfirmation() == null
                || attestationJwt.getConfirmation().getJwk() == null) {
            throw invalidAttestation("The Client Attestation MUST contain a cnf (confirmation) key");
        }

        TokenVerifier.createWithoutSignature(attestationJwt)
                .withChecks(TokenVerifier.IS_ACTIVE)
                .verify();

        KeyWrapper attesterKey = resolveAttesterKey(
                session,
                attestationJwt.getSubject(),
                jws.getHeader().getKeyId(),
                jws.getHeader().getRawAlgorithm(),
                attestationJwt.getIssuer());
        verifySignature(session, jws, attesterKey, "Client Attestation");

        return attestationJwt;
    }

    private static void validateAttestationPoPJwt(
            KeycloakSession session, String headerValue, ClientAttestationJwt attestationJwt) throws Exception {
        JWSInput jws = new JWSInput(headerValue);
        String jwsType = jws.getHeader().getType();
        if (!OAUTH_CLIENT_ATTESTATION_POP_JWT_TYPE.equals(jwsType)) {
            throw invalidAttestation(
                    "The Client Attestation PoP JWS type MUST be " + OAUTH_CLIENT_ATTESTATION_POP_JWT_TYPE);
        }

        ClientAttestationPoPJwt popJwt = jws.readJsonContent(ClientAttestationPoPJwt.class);

        TokenVerifier.Predicate<JsonWebToken> jtiCheck = t -> {
            if (StringUtil.isBlank(t.getId())) {
                throw new IllegalArgumentException("The Client Attestation PoP MUST contain a jti claim");
            }
            return true;
        };
        TokenVerifier.Predicate<JsonWebToken> iatCheck = t -> {
            if (t.getIat() == null || t.getIat() == 0) {
                throw new IllegalArgumentException("The Client Attestation PoP MUST contain an iat claim");
            }
            return true;
        };
        TokenVerifier.Predicate<JsonWebToken> issCheck = t -> {
            if (StringUtil.isBlank(t.getIssuer()) || !t.getIssuer().equals(attestationJwt.getSubject())) {
                throw new IllegalArgumentException(
                        "The iss claim of the Client Attestation PoP MUST match the sub of the Client Attestation");
            }
            return true;
        };
        TokenVerifier.Predicate<JsonWebToken> audCheck = t -> {
            String issuer = authorizationServerIssuer(session);
            List<String> audiences =
                    Optional.ofNullable(t.getAudience()).map(Arrays::asList).orElse(List.of());
            if (!audiences.contains(issuer)) {
                throw new IllegalArgumentException(
                        "The aud claim of the Client Attestation PoP MUST identify this Authorization Server");
            }
            return true;
        };

        TokenVerifier.createWithoutSignature(popJwt)
                .withChecks(jtiCheck, iatCheck, issCheck, audCheck, TokenVerifier.IS_ACTIVE)
                .verify();

        KeyWrapper clientKey =
                toPublicKeyWrapper(attestationJwt.getConfirmation().getJwk());
        verifySignature(session, jws, clientKey, "Client Attestation PoP");
    }

    private static KeyWrapper resolveAttesterKey(
            KeycloakSession session, String clientId, String kid, String algorithm, String issuer) {
        if (StringUtil.isBlank(kid)) {
            throw invalidAttestation("The Client Attestation MUST reference the attester key via a kid header");
        }

        String trustIdps = Optional.ofNullable(clientId)
                .map(id -> session.getContext().getRealm().getClientByClientId(id))
                .map(client -> client.getAttribute(OAUTH_CLIENT_ATTESTATION_CONFIG_TRUST_IDPS))
                .orElse(null);
        if (StringUtil.isBlank(trustIdps)) {
            throw invalidAttestation("No trusted attester configured for the client ("
                    + OAUTH_CLIENT_ATTESTATION_CONFIG_TRUST_IDPS + ")");
        }

        TrustMaterialRequest request = TrustMaterialRequest.builder()
                .kid(kid)
                .algorithm(algorithm)
                .issuer(issuer)
                .build();
        JWK jwk = new TrustMaterialResolver()
                .resolveKey(session, trustIdps, request)
                .orElseThrow(() -> invalidAttestation("No trusted attester key found for kid: " + kid));

        return toPublicKeyWrapper(jwk);
    }

    private static void verifySignature(KeycloakSession session, JWSInput jws, KeyWrapper key, String label)
            throws Exception {
        String algorithm = jws.getHeader().getRawAlgorithm();
        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, algorithm);
        if (signatureProvider == null) {
            throw invalidAttestation("Signature provider not found for algorithm: " + algorithm);
        }
        byte[] data = jws.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8);
        if (!signatureProvider.verifier(key).verify(data, jws.getSignature())) {
            throw invalidAttestation("Invalid " + label + " signature");
        }
    }

    private static KeyWrapper toPublicKeyWrapper(JWK jwk) {
        PublicKey publicKey = new JWKParser(jwk).toPublicKey();
        KeyWrapper kw = new KeyWrapper();
        kw.setPublicKey(publicKey);
        kw.setUse(KeyUse.SIG);
        kw.setType(jwk.getKeyType());
        kw.setAlgorithm(jwk.getAlgorithm());
        return kw;
    }

    private static String authorizationServerIssuer(KeycloakSession session) {
        WellKnownProvider oidcProvider =
                session.getProvider(WellKnownProvider.class, OIDCWellKnownProviderFactory.PROVIDER_ID);
        OIDCConfigurationRepresentation oidcConfig = (OIDCConfigurationRepresentation) oidcProvider.getConfig();
        return oidcConfig.getIssuer();
    }

    private static BadRequestException invalidAttestation(String description) {
        var error = new OAuth2ErrorRepresentation(OAuthErrorException.INVALID_CLIENT_ATTESTATION, description);
        return new BadRequestException(CorsService.open()
                .add(Response.status(Response.Status.BAD_REQUEST).entity(error).type(MediaType.APPLICATION_JSON)));
    }
}
