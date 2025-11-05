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

import org.jboss.logging.Logger;
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.Objects;

/**
 * Dedicated service for persisting authorization contexts to authentication sessions.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public record AuthenticationSessionStore(AuthenticationSessionModel authenticationSession) {

    private static final Logger logger = Logger.getLogger(AuthenticationSessionStore.class);

    private static final String AUTH_CONTEXT_SESSION_KEY = "oid4vp-auth-context";

    /**
     * Stores the given authorization context in the authentication session.
     */
    public void storeAuthorizationContext(AuthorizationContext authorizationContext) {
        String authContextJson;

        try {
            authContextJson = JsonSerialization.writeValueAsString(authorizationContext);
        } catch (IOException e) {
            throw new RuntimeException("Failed to serialize authorization context", e);
        }

        authenticationSession.setAuthNote(AUTH_CONTEXT_SESSION_KEY, authContextJson);
        logger.debugf("Stored authorization context in authentication session: requestId=%s",
                authorizationContext.getRequestId());
    }

    /**
     * Retrieves authorization context by request ID from the authentication session.
     */
    public AuthorizationContext getAuthorizationContextByRequestId(String requestId) {
        AuthorizationContext authContext = getAuthorizationContext();
        if (!Objects.equals(authContext.getRequestId(), requestId)) {
            logger.warnf("Authorization context does not match the provided request ID: "
                    + "Expected=%s, Actual=%s", authContext.getRequestId(), requestId);
            throw new IllegalArgumentException("Authorization context does not match the provided request ID: "
                    + requestId);
        }

        return authContext;
    }

    /**
     * Retrieves authorization context by transaction ID from the authentication session.
     */
    public AuthorizationContext getAuthorizationContextByTransactionId(String transactionId) {
        AuthorizationContext authContext = getAuthorizationContext();
        if (!Objects.equals(authContext.getTransactionId(), transactionId)) {
            logger.warnf("Authorization context does not match the provided transaction ID: "
                    + "Expected=%s, Actual=%s", authContext.getTransactionId(), transactionId);
            throw new IllegalArgumentException("Authorization context does not match the provided transaction ID: "
                    + transactionId);
        }

        return authContext;
    }

    /**
     * Retrieves authorization context from the authentication session.
     */
    private AuthorizationContext getAuthorizationContext() {
        String authContextJson = authenticationSession.getAuthNote(AUTH_CONTEXT_SESSION_KEY);
        if (authContextJson == null) {
            throw new IllegalArgumentException("No authorization context found in authentication session");
        }

        try {
            return JsonSerialization.readValue(authContextJson, AuthorizationContext.class);
        } catch (IOException e) {
            throw new RuntimeException("Failed to deserialize authorization context", e);
        }
    }
}
