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

package org.keycloak.testsuite.oid4vc.oid4vp;

import jakarta.ws.rs.core.UriBuilder;
import org.jboss.resteasy.mock.MockHttpRequest;
import org.jboss.resteasy.specimpl.ResteasyUriInfo;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.Profile;
import org.keycloak.forms.login.freemarker.model.OID4VPUserAuthBean;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resteasy.HttpRequestImpl;
import org.keycloak.testsuite.arquillian.annotation.EnableFeature;
import org.keycloak.testsuite.oid4vc.issuance.signing.OID4VCIssuerEndpointTest;

import java.net.URI;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.keycloak.forms.login.freemarker.model.OID4VPUserAuthBean.LOGIN_METHOD_OID4VP;
import static org.keycloak.forms.login.freemarker.model.OID4VPUserAuthBean.PARAM_LOGIN_METHOD;
import static org.keycloak.testsuite.oid4vc.oid4vp.OID4VPUserAuthEndpointTest.TEST_CLIENT_ID;

/**
 * Test that view data are properly constructed in OID4VPUserAuthBean.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
@EnableFeature(value = Profile.Feature.OID4VC_VPAUTH, skipRestart = true)
public class OID4VPUserAuthBeanTest extends OID4VCIssuerEndpointTest {

    @Test
    public void shouldSuccessfullyBuildBean() {
        testingClient.server(TEST_REALM_NAME).run(session -> {
            OID4VPUserAuthBean bean = createBeanHelper(session);

            // Login URL should contain login_method=oid4vp
            URI loginUrl = URI.create(bean.getLoginUrl());
            ResteasyUriInfo uriInfo = new ResteasyUriInfo(loginUrl);
            String loginMethod = uriInfo.getQueryParameters().getFirst(PARAM_LOGIN_METHOD);
            assertEquals(LOGIN_METHOD_OID4VP, loginMethod);

            // Login Action URL
            assertNotNull(bean.getLoginActionUrl());

            // Auth Context should be created
            var authContext = bean.getAuthContext();
            assertTrue(authContext.getAuthReqQrCode().startsWith("data:image/png;base64,"));
            assertNotNull(authContext.getAuthStatusUrl());
        });
    }

    @Test
    public void shouldNotInjectLoginUrlIfInvalidClient() {
        testingClient.server(TEST_REALM_NAME).run(session -> {
            OID4VPUserAuthBean bean = createBeanHelper(session, "unknown-client", true);
            assertNull(bean.getLoginUrl());  // Null because clientId is invalid
        });
    }

    @Test
    public void shouldNotInjectAuthContextIfLoginMethodNotExplicit() {
        testingClient.server(TEST_REALM_NAME).run(session -> {
            OID4VPUserAuthBean bean = createBeanHelper(session, TEST_CLIENT_ID, false);
            assertNull(bean.getAuthContext()); // Null because no login_method param
        });
    }

    @Test
    public void shouldNotRecreateAuthContextInSameParsingSession() {
        testingClient.server(TEST_REALM_NAME).run(session -> {
            OID4VPUserAuthBean bean = createBeanHelper(session);

            var authContext1 = bean.getAuthContext();
            assertNotNull(authContext1);

            var authContext2 = bean.getAuthContext();
            assertEquals(authContext1, authContext2);
        });
    }

    private static OID4VPUserAuthBean createBeanHelper(KeycloakSession session) {
        return createBeanHelper(session, TEST_CLIENT_ID, true);
    }

    private static OID4VPUserAuthBean createBeanHelper(
            KeycloakSession session,
            String clientId,
            boolean withLoginMethod
    ) {
        UriBuilder uriBuilder = UriBuilder.fromUri("https://keycloak.org/")
                .queryParam(OAuth2Constants.CLIENT_ID, clientId);

        if (withLoginMethod) {
            uriBuilder.queryParam(PARAM_LOGIN_METHOD, LOGIN_METHOD_OID4VP);
        }

        URI uri = uriBuilder.build();
        HttpRequest httpRequest = new HttpRequestImpl(MockHttpRequest.create("GET", uri, uri));
        session.getContext().setHttpRequest(httpRequest);

        RealmModel realm = session.getContext().getRealm();
        return new OID4VPUserAuthBean(session, realm, uri);
    }
}
