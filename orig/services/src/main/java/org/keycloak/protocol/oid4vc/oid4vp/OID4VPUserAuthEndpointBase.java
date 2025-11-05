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

package org.keycloak.protocol.oid4vc.oid4vp;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.AuthorizationEndpointBase;
import org.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

import static org.keycloak.models.utils.DefaultAuthenticationFlows.OID4VP_AUTH_FLOW;

/**
 * Base endpoint class handling common routines needed by OpenID4VP routes.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class OID4VPUserAuthEndpointBase extends AuthorizationEndpointBase {

    private static final Logger logger = Logger.getLogger(OID4VPUserAuthEndpointBase.class);

    public static final String AUTH_SESSION_DELIMITER = ".";
    public static final String AUTH_SESSION_EOL_MARKER = "::";

    public OID4VPUserAuthEndpointBase(KeycloakSession session, EventBuilder event) {
        super(session, event);
    }

    /**
     * Returns the OpenID4VP authentication flow model.
     */
    protected AuthenticationFlowModel getOid4vpAuthFlow() {
        AuthenticationFlowModel flow = realm.getFlowByAlias(OID4VP_AUTH_FLOW);
        if (flow == null) {
            throw new IllegalStateException(String.format(
                    "Authentication flow '%s' not found. Such is supposed to be built-in",
                    OID4VP_AUTH_FLOW
            ));
        }

        return flow;
    }

    /**
     * Returns the SD-JWT authenticator configuration as part of the OpenID4VP authentication flow.
     */
    protected AuthenticatorConfigModel getSdjwtAuthenticatorConfig() {
        AuthenticationFlowModel flow = getOid4vpAuthFlow();
        return realm.getAuthenticationExecutionsStream(flow.getId())
                .filter(execution -> execution.getAuthenticator().equals(SdJwtAuthenticatorFactory.PROVIDER_ID))
                .findFirst()
                .map(AuthenticationExecutionModel::getAuthenticatorConfig)
                .map(realm::getAuthenticatorConfigById)
                .orElse(new AuthenticatorConfigModel());
    }

    /**
     * Derives authenticator processor from authentication flow.
     */
    protected AuthenticationProcessor getAuthenticationProcessor() {
        KeycloakContext context = session.getContext();
        AuthenticationFlowModel flow = getOid4vpAuthFlow();

        // Creates an ephemeral authentication session tab. Authentication sessions tabs
        // are automatically removed after successful authentication, which is problematic
        // for this OpenID4VP flow, as we need to keep session data for some time to enable
        // polling the authentication status by an entity other than the wallet. Thus, we
        // create an ephemeral separate authentication session tab just for processors.
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        AuthenticationSessionModel ephemeralAuthSession = authSession.getParentSession()
                .createAuthenticationSession(authSession.getClient());

        return new AuthenticationProcessor()
                .setAuthenticationSession(ephemeralAuthSession)
                .setFlowId(flow.getId())
                .setFlowPath(null)
                .setConnection(clientConnection)
                .setEventBuilder(event)
                .setRealm(realm)
                .setSession(session)
                .setUriInfo(context.getUri())
                .setRequest(httpRequest);
    }

    /**
     * Recovers session from `authSessionId`.
     */
    protected Optional<AuthenticationSessionModel> getAuthSession(String authSessionId) {
        if (authSessionId == null || !authSessionId.contains(AUTH_SESSION_DELIMITER)) {
            logger.debugf("Invalid authSessionId format: %s. Delimiter '%s' expected",
                    authSessionId, AUTH_SESSION_DELIMITER);
            return Optional.empty();
        }

        String[] authSessionIdParts = authSessionId
                .split(Pattern.quote(AUTH_SESSION_DELIMITER));

        String rootAuthSessionId = authSessionIdParts[0];
        String tabSessionId = authSessionIdParts[1];

        RootAuthenticationSessionModel rootAuthSession = session.authenticationSessions()
                .getRootAuthenticationSession(realm, rootAuthSessionId);

        if (rootAuthSession == null) {
            logger.tracef("Root authentication session not found for ID: %s", authSessionId);
            return Optional.empty();
        }

        AuthenticationSessionModel authSession = rootAuthSession
                .getAuthenticationSessions()
                .get(tabSessionId);

        if (authSession == null) {
            logger.tracef("Authentication session not found for ID: %s", authSessionId);
            return Optional.empty();
        }

        return Optional.of(authSession);
    }

    /**
     * Creates new authentication session.
     */
    protected AuthenticationSessionModel createAuthSession(ClientModel client) {
        AuthenticationSessionModel authSession = new AuthenticationSessionManager(session)
                .createAuthenticationSession(realm, false)
                .createAuthenticationSession(client);

        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authSession.setAction(AuthenticatedClientSessionModel.Action.AUTHENTICATE.name());

        return authSession;
    }

    /**
     * Extracts the unique identifier to recover authentication sessions.
     * <p></p>
     * This method prunes any additional information appended to the auth session ID
     * based on the EOL marker. This is to done to allow application code to append
     * additional information to the auth session ID, such as a request or transaction ID,
     * without affecting this session recovery.
     */
    public static String pruneAuthSessionId(String authSessionId) {
        if (StringUtil.isBlank(authSessionId)) {
            throw new IllegalArgumentException("Authentication session ID cannot be null or empty");
        }

        // Strip all characters from the EOL marker onward.
        int markerIndex = authSessionId.indexOf(AUTH_SESSION_EOL_MARKER);
        if (markerIndex != -1) {
            return authSessionId.substring(0, markerIndex);
        }

        return authSessionId; // Return as is if no EOL marker found
    }

    /**
     * Returns a unique identifier to recover the authentication session.
     */
    public static String getAuthSessionId(AuthenticationSessionModel authSession) {
        Objects.requireNonNull(authSession);
        Objects.requireNonNull(authSession.getParentSession());

        String rootAuthSessionId = authSession.getParentSession().getId();
        String tabSessionId = authSession.getTabId();

        return rootAuthSessionId + AUTH_SESSION_DELIMITER + tabSessionId;
    }
}
