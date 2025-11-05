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

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.consumer.TrustedSdJwtIssuer;

import java.util.List;
import java.util.stream.Stream;

/**
 * Trust anchor enforcing Keycloak only trusts SD-JWTs that it issued can verify itself.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SelfTrustedSdJwtIssuer implements TrustedSdJwtIssuer {

    private static final Logger logger = Logger.getLogger(SelfTrustedSdJwtIssuer.class);

    private final KeycloakSession session;

    public SelfTrustedSdJwtIssuer(AuthenticationFlowContext context) {
        this.session = context.getSession();
    }

    @Override
    public List<SignatureVerifierContext> resolveIssuerVerifyingKeys(IssuerSignedJWT issuerSignedJWT) {
        logger.debugf("Gathering potential verifying keys for FiPA-based SDJWT authentication");

        RealmModel realm = session.getContext().getRealm();
        KeyManager keyManager = session.keys();
        Stream<KeyWrapper> keyStream = keyManager.getKeysStream(realm)
                .filter(key -> KeyUse.SIG.equals(key.getUse()));

        String signingKeyId = issuerSignedJWT.getHeader().getKeyId();
        if (signingKeyId != null) {
            keyStream = keyStream.filter(key -> signingKeyId.equals(key.getKid()));
        }

        return keyStream
                .map(key -> {
                    SignatureProvider signatureProvider = session
                            .getProvider(SignatureProvider.class, key.getAlgorithmOrDefault());
                    try {
                        return signatureProvider.verifier(key);
                    } catch (VerificationException e) {
                        throw new RuntimeException(e);
                    }
                })
                .toList();
    }
}
