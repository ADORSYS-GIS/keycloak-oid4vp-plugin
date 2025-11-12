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

package de.adorsys.gis.keycloak.services.protocol.oid4vc.oid4vp;

import de.adorsys.gis.keycloak.services.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlow;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

import static de.adorsys.gis.keycloak.services.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW;

/**
 * Factory for user authentication over OpenID4VP.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class OID4VPUserAuthEndpointFactory
        implements RealmResourceProviderFactory, OID4VPEnvironmentProviderFactory {

    private static final Logger logger = Logger.getLogger(OID4VPUserAuthEndpointFactory.class);

    public static final String PROVIDER_ID = "oid4vp-auth";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        KeycloakContext context = session.getContext();
        RealmModel realm = context.getRealm();
        EventBuilder event = new EventBuilder(realm, session, context.getConnection());
        migrateRealmIfNecessary(realm);
        return new OID4VPUserAuthEndpoint(session, event);
    }

    private void migrateRealmIfNecessary(RealmModel realm) {
        if (realm.getFlowByAlias(OID4VP_AUTH_FLOW) == null) {
            logger.infof("Creating default OpenID4VP user auth flow for realm '%s'", realm.getName());
            oid4vpAuthenticationFlow(realm);
        } else {
            logger.debugf("OpenID4VP user auth flow already exists for realm '%s'", realm.getName());
        }
    }

    private void oid4vpAuthenticationFlow(final RealmModel realm) {
        AuthenticationFlowModel oid4vpAuthFlow = new AuthenticationFlowModel();

        oid4vpAuthFlow.setAlias(OID4VP_AUTH_FLOW);
        oid4vpAuthFlow.setDescription("Authenticate via OpenID4VP presentations of self-issued identity credentials");
        oid4vpAuthFlow.setProviderId(AuthenticationFlow.BASIC_FLOW);
        oid4vpAuthFlow.setTopLevel(true);
        oid4vpAuthFlow.setBuiltIn(true);
        oid4vpAuthFlow = realm.addAuthenticationFlow(oid4vpAuthFlow);

        AuthenticationExecutionModel execution = new AuthenticationExecutionModel();

        execution.setParentFlow(oid4vpAuthFlow.getId());
        execution.setRequirement(AuthenticationExecutionModel.Requirement.REQUIRED);
        execution.setAuthenticator(SdJwtAuthenticatorFactory.PROVIDER_ID);
        execution.setPriority(10);
        execution.setAuthenticatorFlow(false);

        realm.addAuthenticatorExecution(execution);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
