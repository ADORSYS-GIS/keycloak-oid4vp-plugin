package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.VerificationException;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.sdjwt.SdJwtUtils;
import org.keycloak.sdjwt.consumer.SdJwtPresentationConsumer;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

/**
 * Authenticate by presenting a valid SD-JWT credential.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(SdJwtAuthenticator.class);

    private final SdJwtPresentationConsumer consumer;
    private final ReferencedTokenValidator tokenStatusValidator;

    /**
     * The authenticating party is challenged to produce a presentation with a nonce.
     */
    public static final String CHALLENGE_NONCE_KEY = "nonce";

    /**
     * The authenticating party presents a non-replayable SD-JWT token for authentication.
     */
    public static final String SDJWT_TOKEN_KEY = "sdjwt_token";

    public SdJwtAuthenticator(StatusListJwtFetcher statusListJwtFetcher) {
        this.consumer = new SdJwtPresentationConsumer();
        this.tokenStatusValidator = new ReferencedTokenValidator(statusListJwtFetcher);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        logger.info("Authenticating with SdJwtAuthenticator");

        SdJwtAuthRequirements authReqs = getAuthenticationRequirements(context);
        String nonce = authSession.getAuthNote(CHALLENGE_NONCE_KEY);
        SdJwtVP sdJwt = SdJwtVP.of(authSession.getAuthNote(SDJWT_TOKEN_KEY));

        try {
            consumer.verifySdJwtPresentation(
                    sdJwt,
                    authReqs.getPresentationDefinition(),
                    List.of(new SelfTrustedSdJwtIssuer(context)),
                    authReqs.getIssuerSignedJwtVerificationOpts(),
                    authReqs.getKeyBindingJwtVerificationOpts(nonce));
        } catch (VerificationException e) {
            logger.errorf(e, "Token verification failed");
            failRejectingPresentedSdJwtToken(context, e.getMessage());
            return;
        }

        // Validate token status if enforced
        if (authReqs.shouldEnforceRevocationStatus()) {
            try {
                tokenStatusValidator.validate(sdJwt.getIssuerSignedJWT().getPayload());
            } catch (ReferencedTokenValidationException e) {
                logger.errorf(e, "Token status verification failed");
                failRejectingPresentedSdJwtToken(context, "Token status verification failed");
                return;
            }
        }

        UserModel user = recoverAuthenticatingUser(context, sdJwt);
        if (user == null) {
            return;
        }

        context.setUser(user);
        context.success(); // Mark authentication as successful
        logger.debugf("User '%s' successfully authenticated", user.getUsername());
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // No form action is relevant for this authenticator
    }

    private SdJwtAuthRequirements getAuthenticationRequirements(AuthenticationFlowContext context) {
        return new SdJwtAuthRequirements(context.getSession().getContext(), context.getAuthenticatorConfig());
    }

    private UserModel recoverAuthenticatingUser(AuthenticationFlowContext context, SdJwtVP sdJwt) {
        logger.info("Recovering authenticating user");

        String subject = readSubjectFromCredential(sdJwt);
        if (StringUtil.isBlank(subject)) {
            logger.warn("Presented SD-JWT is missing required subject claim");
            failRejectingPresentedSdJwtToken(context, "Missing subject claim");
            return null;
        }
        logger.debugf("Presented subject: %s", subject);

        UserModel user = context.getSession().users().getUserById(context.getRealm(), subject);
        if (user == null) {
            logger.debugf("Authentication passed but authenticating user is unknown");
            failDenyingAuthenticatingUser(context);
            return null;
        }
        logger.debugf("Resolved user id: %s", user.getId());

        String presentedUsername = readUsernameFromCredential(sdJwt);
        if (StringUtil.isBlank(presentedUsername)) {
            logger.warn("Presented SD-JWT is missing required username claim");
            failRejectingPresentedSdJwtToken(context, "Missing username claim");
            return null;
        }

        if (!presentedUsername.equals(user.getUsername())) {
            logger.warnf(
                    "Username mismatch for subject '%s': credential='%s', user='%s'",
                    subject, presentedUsername, user.getUsername());
            failRejectingPresentedSdJwtToken(context, "Username mismatch");
            return null;
        }

        return user;
    }

    private String readSubjectFromCredential(SdJwtVP sdJwt) {
        return readClaimFromCredential(sdJwt, JsonWebToken.SUBJECT);
    }

    private String readUsernameFromCredential(SdJwtVP sdJwt) {
        return readClaimFromCredential(sdJwt, OAuth2Constants.USERNAME);
    }

    private String readClaimFromCredential(SdJwtVP sdJwt, String claimName) {
        JsonNode issuerSignedJwtPayload = sdJwt.getIssuerSignedJWT().getPayload();
        JsonNode claim = issuerSignedJwtPayload.get(claimName);

        if (claim == null) {
            claim = readSelectivelyDisclosedClaim(sdJwt, claimName);
        }

        return claim != null ? claim.asText() : null;
    }

    private JsonNode readSelectivelyDisclosedClaim(SdJwtVP sdJwt, String claimName) {
        for (String disclosure : sdJwt.getDisclosuresString()) {
            try {
                ArrayNode arrayNode = SdJwtUtils.decodeDisclosureString(disclosure);
                if (arrayNode.size() == 3 && arrayNode.get(1).asText().equals(claimName)) {
                    return arrayNode.get(2);
                }
            } catch (VerificationException e) {
                logger.warnf(e, "Failed to decode disclosure string");
            }
        }

        return null;
    }

    private void failRejectingPresentedSdJwtToken(AuthenticationFlowContext context, String reason) {
        logger.info("Presented SD-JWT will be rejected as invalid");

        var errorRep = new OAuth2ErrorRepresentation(
                Errors.INVALID_USER_CREDENTIALS, String.format("Invalid SD-JWT presentation (%s)", reason));

        context.failure(
                AuthenticationFlowError.INVALID_CREDENTIALS,
                Response.status(Response.Status.UNAUTHORIZED.getStatusCode())
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .entity(errorRep)
                        .build());
    }

    private void failDenyingAuthenticatingUser(AuthenticationFlowContext context) {
        logger.info("Presented SD-JWT will be rejected for associated user is unknown");

        var errorRep = new OAuth2ErrorRepresentation(Errors.USER_NOT_FOUND, "User with presented SD-JWT is unknown");

        context.failure(
                AuthenticationFlowError.UNKNOWN_USER,
                Response.status(Response.Status.UNAUTHORIZED.getStatusCode())
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .entity(errorRep)
                        .build());
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

    @Override
    public void close() {}
}
