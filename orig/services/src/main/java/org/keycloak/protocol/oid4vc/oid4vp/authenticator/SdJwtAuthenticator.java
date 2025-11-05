/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.protocol.oid4vc.oid4vp.authenticator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
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
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator;
import org.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.sdjwt.SdJwtUtils;
import org.keycloak.sdjwt.consumer.SdJwtPresentationConsumer;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.List;
import java.util.Objects;

import static org.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;

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
                    authReqs.getKeyBindingJwtVerificationOpts(nonce)
            );
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
            logger.debugf("Authentication passed but authenticating user is unknown");
            failDenyingAuthenticatingUser(context);
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
        return new SdJwtAuthRequirements(
                context.getSession().getContext(),
                context.getAuthenticatorConfig()
        );
    }

    private UserModel recoverAuthenticatingUser(AuthenticationFlowContext context, SdJwtVP sdJwt) {
        logger.info("Recovering (or importing) authenticating user");
        String username = readUsernameFromCredential(sdJwt);

        // Recover authenticating user
        UserModel user = KeycloakModelUtils.findUserByNameOrEmail(
                context.getSession(),
                context.getRealm(),
                username
        );

        // Import user if not found
        if (user == null) {
            // TODO: Improve user import strategy. Extend AbstractIdpAuthenticator?
            user = context.getSession().users().addUser(context.getRealm(), username);

            if (user != null) {
                user.setEnabled(true);
                logger.infof("Imported user '%s' from SD-JWT credential", username);
            } else {
                logger.errorf("Failed to import user '%s' from SD-JWT credential into Keycloak", username);
            }
        }

        return user;
    }

    private String readUsernameFromCredential(SdJwtVP sdJwt) {
        // Read username from SD-JWT
        JsonNode issuerSignedJwtPayload = sdJwt.getIssuerSignedJWT().getPayload();
        JsonNode username = issuerSignedJwtPayload.get(OAuth2Constants.USERNAME);

        // Attempt to read from disclosures
        if (username == null) {
            username = readSelectivelyDisclosedUsername(sdJwt);
            Objects.requireNonNull(username, "Disclosing a username is a presentation requirement");
        }

        return username.asText();
    }

    private JsonNode readSelectivelyDisclosedUsername(SdJwtVP sdJwt) {
        for (String disclosure : sdJwt.getDisclosuresString()) {
            try {
                ArrayNode arrayNode = SdJwtUtils.decodeDisclosureString(disclosure);
                if (arrayNode.size() == 3 && arrayNode.get(1).asText().equals(OAuth2Constants.USERNAME)) {
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
                Errors.INVALID_USER_CREDENTIALS,
                String.format("Invalid SD-JWT presentation (%s)", reason)
        );

        context.failure(
                AuthenticationFlowError.INVALID_CREDENTIALS,
                Response.status(Response.Status.UNAUTHORIZED.getStatusCode())
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .entity(errorRep)
                        .build()
        );
    }

    private void failDenyingAuthenticatingUser(AuthenticationFlowContext context) {
        logger.info("Presented SD-JWT will be rejected for associated user is unknown and could not be imported");

        var errorRep = new OAuth2ErrorRepresentation(
                Errors.USER_NOT_FOUND,
                "User with presented SD-JWT unknown and could not be imported"
        );

        context.failure(
                AuthenticationFlowError.UNKNOWN_USER,
                Response.status(Response.Status.UNAUTHORIZED.getStatusCode())
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .entity(errorRep)
                        .build()
        );
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
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
