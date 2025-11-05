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

package org.keycloak.protocol.oid4vc.oid4vp.service;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.common.util.Time;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticator;
import org.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import org.keycloak.protocol.oid4vc.oid4vp.model.prex.Descriptor;
import org.keycloak.protocol.oidc.utils.OAuth2Code;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.MediaType;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Dedicated service for processing OpenID4VP authorization responses for user authentication.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class AuthorizationResponseService {

    private static final Logger logger = Logger.getLogger(AuthorizationResponseService.class);

    public static final String JSON_PATH_ROOT = "$";

    private final KeycloakSession session;

    public AuthorizationResponseService(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Processes authorization response for user authentication.
     */
    public void processAuthorizationResponse(
            ResponseObject responseObject,
            AuthorizationContext authContext,
            AuthenticationSessionModel authSession,
            AuthenticationProcessor authProcessor
    ) {
        logger.debug("Processing authorization response for user authentication...");
        AuthenticationSessionStore store = new AuthenticationSessionStore(authSession);

        // Validate that authorization context is not yet closed
        if (authContext.getStatus().equals(AuthorizationContextStatus.SUCCESS)) {
            throw failWithHttpException(
                    ProcessingError.AUTH_CONTEXT_CLOSED,
                    "Authorization context is already closed. Cannot process further responses",
                    Response.Status.BAD_REQUEST, authContext, store
            );
        }

        // Extract SD-JWT VP token from the response object
        String sdJwtVp = extractSdJwtVpToken(responseObject, authContext, store);

        // Formally, we should then check that the VP token satisfies the constraints of
        // the OpenID4VP presentation definition. Equivalently, we offload this task to
        // the SD-JWT authenticator in the authentication flow.
        logger.debugf("Initializing authentication with extracted SD-JWT VP token");
        var processorSession = authProcessor.getAuthenticationSession();
        String nonce = authContext.getRequestObject().getNonce();
        processorSession.setAuthNote(SdJwtAuthenticator.SDJWT_TOKEN_KEY, sdJwtVp);
        processorSession.setAuthNote(SdJwtAuthenticator.CHALLENGE_NONCE_KEY, nonce);

        // Run authentication processor to validate the SD-JWT VP token
        logger.debug("Running authentication processor to validate SD-JWT VP token...");
        try (Response response = authProcessor.authenticateOnly()) {
            if (response != null) {
                String message = getAuthenticatorErrorMessage(response);
                logger.errorf("Authentication processor failed. [%s] %s", response.getStatus(), message);

                throw failWithHttpException(
                        ProcessingError.VP_TOKEN_AUTH_ERROR, message,
                        Response.Status.fromStatusCode(response.getStatus()),
                        authContext, store
                );
            }
        }

        // Log authentication success and retrieve authenticated session
        logger.debug("Authentication processor succeeded, retrieving user session...");
        AuthenticatedClientSessionModel clientSession = authProcessor.attachSession().getClientSession();
        logger.infof("Client session id: %s", clientSession.getId());

        // Produce an authorization code for the authenticated user
        String authorizationCode = produceAuthorizationCode(clientSession);
        authContext.setStatus(AuthorizationContextStatus.SUCCESS);
        authContext.setAuthorizationCode(authorizationCode);

        // Persist authorization context
        store.storeAuthorizationContext(authContext);
    }

    private static String getAuthenticatorErrorMessage(Response response) {
        Object responseEntity = response.getEntity();
        if (!(responseEntity instanceof OAuth2ErrorRepresentation errorResponse)) {
            throw new IllegalStateException(String.format(
                    "Unexpected error response type from authenticator: %s",
                    responseEntity.getClass().getName()
            ));
        }

        return String.format("%s: %s", errorResponse.getError().toUpperCase(), errorResponse.getErrorDescription());
    }

    /**
     * Extract SD-JWT VP token from response object
     */
    private String extractSdJwtVpToken(
            ResponseObject responseObject,
            AuthorizationContext authContext,
            AuthenticationSessionStore store
    ) {
        // Ensure that the presentation submission matches the expected presentation definition
        var definition = authContext.getRequestObject().getPresentationDefinition();
        var submission = responseObject.getPresentationSubmission();
        if (!definition.getId().equals(submission.getDefinitionId())
                || definition.getInputDescriptors().size() != submission.getDescriptorMap().size()) {
            throw failWithHttpException(
                    ProcessingError.INVALID_PRESENTATION_SUBMISSION,
                    "Presentation submission does not match the expected presentation definition",
                    Response.Status.BAD_REQUEST, authContext, store
            );
        }

        // Check that the submission's descriptor is of SD-JWT VP format
        var descriptor = submission.getDescriptorMap().get(0);
        if (!List.of(Format.SD_JWT_VC, Descriptor.Format.VC_SD_JWT.value())
                .contains(descriptor.getFormat().value())) {
            throw failWithHttpException(
                    ProcessingError.INVALID_PRESENTATION_SUBMISSION,
                    "SD-JWT VP token expected, but received: " + descriptor.getFormat().value(),
                    Response.Status.BAD_REQUEST, authContext, store
            );
        }

        // Minimalistic JSON path parse. We should normally follow the JSON path provided to
        // extract the SD-JWT VP token as decided by the wallet. However, in this situation,
        // most implementations will simply use the root path "$", enabling us to avoid full
        // JSON path parsing and to bring in a dependency on a JSON path library.
        if (!JSON_PATH_ROOT.equals(descriptor.getPath()) || descriptor.getPathNested() != null) {
            throw failWithHttpException(
                    ProcessingError.INVALID_PRESENTATION_SUBMISSION,
                    String.format("Invalid path in presentation submission descriptor: %s. Only '%s' without `path_nested` is supported",
                            descriptor.getPath(), JSON_PATH_ROOT),
                    Response.Status.BAD_REQUEST, authContext, store
            );
        }

        // Check that a vp_token was submitted
        if (responseObject.getVpToken() == null || responseObject.getVpToken().isEmpty()) {
            throw failWithHttpException(
                    ProcessingError.INVALID_PRESENTATION_SUBMISSION,
                    "Could not parse submission in search for SD-JWT VP token",
                    Response.Status.BAD_REQUEST, authContext, store
            );
        }

        try {
            String vpToken = decodeIfBase64Url(responseObject.getVpToken());
            SdJwtVP.of(vpToken);
            return vpToken;
        } catch (IllegalArgumentException e) {
            logger.errorf(e, "Failed to parse SD-JWT VP token");
            throw failWithHttpException(
                    ProcessingError.INVALID_VP_TOKEN,
                    "Could not parse `vp_token` as an SD-JWT VP token",
                    Response.Status.BAD_REQUEST, authContext, store
            );
        }
    }

    /**
     * Issues an authorization code provided successful authentication.
     */
    private String produceAuthorizationCode(AuthenticatedClientSessionModel clientSession) {
        String code = UUID.randomUUID().toString();
        String nonce = SecretGenerator.getInstance().randomString();
        int expiration = Time.currentTime() + clientSession.getRealm().getAccessCodeLifespan();

        OAuth2Code codeData = new OAuth2Code(
                code,
                expiration,
                nonce,
                OAuth2Constants.SCOPE_OPENID,
                null,
                null,
                null,
                null,
                clientSession.getUserSession().getId()
        );

        return OAuth2CodeParser.persistCode(session, clientSession, codeData);
    }

    /**
     * Helper method for issuing exceptions while keeping a record in the authorization context.
     */
    private WebApplicationException failWithHttpException(
            ProcessingError error,
            String message,
            Response.Status status,
            AuthorizationContext authorizationContext,
            AuthenticationSessionStore store
    ) {
        logger.errorf("%s: %s", error, message);

        var errorResponse = new OAuth2ErrorRepresentation(error.getErrorString(), message);
        var httpErrorResponse = Response
                .status(status)
                .entity(errorResponse)
                .type(MediaType.APPLICATION_JSON);

        WebApplicationException exception = new WebApplicationException(
                CorsService.forWebOrigins(store.authenticationSession())
                        .add(httpErrorResponse)
        );

        // Update the authorization context with error details
        if (!error.equals(ProcessingError.AUTH_CONTEXT_CLOSED)) {
            authorizationContext
                    .setStatus(AuthorizationContextStatus.ERROR)
                    .setError(error)
                    .setErrorDescription(message);
            store.storeAuthorizationContext(authorizationContext);
        }

        return exception;
    }

    /**
     * Helper method to decode Base64URL encoded strings if applicable.
     * If the input is not Base64URL encoded, it returns the input as is.
     */
    private static String decodeIfBase64Url(String input) {
        try {
            // Try to decode as Base64URL
            byte[] decoded = Base64.getUrlDecoder().decode(input);
            return new String(decoded, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            // Not valid Base64URL, return as is
            return input;
        }
    }
}
