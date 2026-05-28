package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ErrorResponseSanitizer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.TransactionDataValidator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Optional;
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
import org.keycloak.sdjwt.vp.KeyBindingJWT;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Authenticate by presenting a valid SD-JWT credential.
 *
 * <p>Presentation validation is performed upstream by
 * {@link io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation.VpTokenValidationPipeline}
 * before this authenticator runs. This authenticator only resolves the presenting user.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(SdJwtAuthenticator.class);

    /**
     * The authenticating party presents a non-replayable SD-JWT token for authentication.
     */
    public static final String SDJWT_TOKEN_KEY = "sdjwt_token";

    /**
     * Required for the OpenID4VP authorization-response flow. Set by
     * {@link io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationResponseService}
     * after {@link io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation.VpTokenValidationPipeline}
     * validates the presentation.
     */
    public static final String VP_TOKEN_VALIDATED_KEY = "vp_token_validated";

    public static final String REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING_KEY = "require_cryptographic_holder_binding";

    public static final String TRANSACTION_DATA_WIRE_KEY = "transaction_data_wire";

    public SdJwtAuthenticator() {}

    public SdJwtAuthenticator(StatusListJwtFetcher statusListJwtFetcher) {
        this();
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        logger.info("Authenticating with SdJwtAuthenticator");

        String sdJwtToken = authSession.getAuthNote(SDJWT_TOKEN_KEY);
        if (StringUtil.isBlank(sdJwtToken)) {
            logger.errorf("Missing SD-JWT VP token (authSession = %s)", correlationId(context));
            failRejectingPresentedSdJwtToken(context, "Missing SD-JWT VP token");
            return;
        }

        if (!"true".equals(authSession.getAuthNote(VP_TOKEN_VALIDATED_KEY))) {
            logger.errorf(
                    "VP token reached authenticator without prior pipeline validation (authSession = %s)",
                    correlationId(context));
            failRejectingPresentedSdJwtToken(context, "VP token was not validated by the verifier pipeline");
            return;
        }

        SdJwtVP sdJwt = SdJwtVP.of(sdJwtToken);
        logger.debug("Resolving user from pipeline-validated SD-JWT presentation");

        try {
            validateTransactionData(authSession, sdJwt);
        } catch (IllegalArgumentException e) {
            logger.errorf(e, "Transaction data validation failed (authSession = %s)", correlationId(context));
            failRejectingPresentedSdJwtToken(context, e.getMessage());
            return;
        }

        UserModel user = recoverAuthenticatingUser(context, sdJwt);
        if (user == null) {
            return;
        }

        if (!user.isEnabled()) {
            logger.debugf("Rejecting authentication for disabled user '%s'", user.getUsername());
            failDenyingDisabledUser(context);
            return;
        }

        context.setUser(user);
        context.success();
        logger.debugf("User '%s' successfully authenticated", user.getUsername());
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // No form action is relevant for this authenticator
    }

    void validateTransactionData(AuthenticationSessionModel authSession, SdJwtVP sdJwt) {
        String wireJson = authSession.getAuthNote(TRANSACTION_DATA_WIRE_KEY);
        if (StringUtil.isBlank(wireJson)) {
            return;
        }

        List<String> transactionDataWire;
        try {
            transactionDataWire = JsonSerialization.readValue(wireJson, new TypeReference<List<String>>() {});
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid transaction_data session state", e);
        }

        Optional<KeyBindingJWT> keyBindingJwt = sdJwt.getKeyBindingJWT();
        if (keyBindingJwt.isEmpty()) {
            throw new IllegalArgumentException("Key Binding JWT required when transaction_data is requested");
        }

        ObjectNode kbPayload = keyBindingJwt.get().getPayload();
        TransactionDataValidator.validate(transactionDataWire, kbPayload);
    }

    private UserModel recoverAuthenticatingUser(AuthenticationFlowContext context, SdJwtVP sdJwt) {
        logger.info("Recovering authenticating user");

        String subject = readSubjectFromCredential(sdJwt);
        if (StringUtil.isBlank(subject)) {
            logger.warn("Presented SD-JWT is missing subject claim");
        } else {
            logger.debugf("Presented subject: %s", subject);
        }

        String presentedUsername = readUsernameFromCredential(sdJwt);
        if (StringUtil.isBlank(presentedUsername)) {
            logger.warn("Presented SD-JWT is missing required username claim");
            failRejectingPresentedSdJwtToken(context, "Missing username claim");
            return null;
        }

        UserModel user = null;
        if (!StringUtil.isBlank(subject)) {
            user = context.getSession().users().getUserById(context.getRealm(), subject);
            if (user != null) {
                logger.debugf("Resolved user id: %s", user.getId());
            }
        }

        if (user == null) {
            // TODO: Remove username-only fallback once SubjectID mapper is fixed and stable.
            logger.warn("Subject did not resolve to a user. Falling back to username lookup.");
            user = context.getSession().users().getUserByUsername(context.getRealm(), presentedUsername);
        }

        if (user == null) {
            logger.debugf("Authentication passed but authenticating user is unknown");
            failDenyingAuthenticatingUser(context);
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

    private static String correlationId(AuthenticationFlowContext context) {
        return ErrorResponseSanitizer.correlationIdFromAuthSession(context.getAuthenticationSession());
    }

    private void failRejectingPresentedSdJwtToken(AuthenticationFlowContext context, String reason) {
        String correlationId = ErrorResponseSanitizer.correlationIdFromAuthSession(context.getAuthenticationSession());
        logger.errorf("Presented SD-JWT rejected (authSession = %s): %s", correlationId, reason);

        String description = String.format("Invalid SD-JWT presentation (%s)", reason);
        var errorRep = new OAuth2ErrorRepresentation(Errors.INVALID_USER_CREDENTIALS, description);

        context.failure(
                AuthenticationFlowError.INVALID_CREDENTIALS,
                Response.status(Response.Status.UNAUTHORIZED.getStatusCode())
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .entity(errorRep)
                        .build());
    }

    private void failDenyingAuthenticatingUser(AuthenticationFlowContext context) {
        logger.info("Presented SD-JWT will be rejected for associated user is unknown");

        String correlationId = ErrorResponseSanitizer.correlationIdFromAuthSession(context.getAuthenticationSession());
        logger.errorf("User with presented SD-JWT is unknown (authSession = %s)", correlationId);

        String description = "User with presented SD-JWT is unknown";

        var errorRep = new OAuth2ErrorRepresentation(Errors.USER_NOT_FOUND, description);

        context.failure(
                AuthenticationFlowError.UNKNOWN_USER,
                Response.status(Response.Status.UNAUTHORIZED.getStatusCode())
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .entity(errorRep)
                        .build());
    }

    private void failDenyingDisabledUser(AuthenticationFlowContext context) {
        var errorRep = new OAuth2ErrorRepresentation(Errors.USER_DISABLED, "User with presented SD-JWT is disabled");

        context.failure(
                AuthenticationFlowError.USER_DISABLED,
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
