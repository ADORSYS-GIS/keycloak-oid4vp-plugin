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

import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.keys.Attributes;
import org.keycloak.protocol.oid4vc.oid4vp.service.VerifierDiscoveryService;
import org.keycloak.representations.idm.ComponentExportRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.oid4vc.issuance.signing.OID4VCTest;

import static org.junit.Assert.assertEquals;

/**
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
@RunWith(Enclosed.class)
public class VerifierDiscoveryServiceTest {

    public static class TestPreferECKey extends OID4VCTest {

        @Override
        public void configureTestRealm(RealmRepresentation testRealm) {
            ComponentExportRepresentation ecKeyProvider = getEcKeyProvider();
            ecKeyProvider.getConfig().add(Attributes.EC_GENERATE_CERTIFICATE_KEY, "true");

            registerKeyProvider(testRealm, ecKeyProvider);
            registerKeyProvider(testRealm, getRsaKeyProvider(RSA_KEY));
        }

        @Test
        public void shoudPreferECKey() {
            testingClient.server(TEST_REALM_NAME).run(session -> {
                VerifierDiscoveryService service = new VerifierDiscoveryService(session);
                KeyWrapper key = service.getSigningKey();
                assertEquals(KeyType.EC, key.getType());
            });
        }
    }

    public static class TestDefaultToRSAKey extends OID4VCTest {

        @Override
        public void configureTestRealm(RealmRepresentation testRealm) {
            registerKeyProvider(testRealm, getEcKeyProvider());
            registerKeyProvider(testRealm, getRsaKeyProvider(RSA_KEY));
        }

        @Test
        public void shoudDefaultToRSAKeyIfNoECKeyWithCertificate() {
            testingClient.server(TEST_REALM_NAME).run(session -> {
                VerifierDiscoveryService service = new VerifierDiscoveryService(session);
                KeyWrapper key = service.getSigningKey();
                assertEquals(KeyType.RSA, key.getType());
            });
        }
    }

    static void registerKeyProvider(RealmRepresentation testRealm, ComponentExportRepresentation keyProvider) {
        if (testRealm.getComponents() == null) {
            testRealm.setComponents(new MultivaluedHashMap<>());
        }

        testRealm.getComponents().add("org.keycloak.keys.KeyProvider", keyProvider);
    }
}
