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

package org.keycloak.testsuite.oid4vc.oid4vp.utils;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.ECDSASignatureSignerContext;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory;
import org.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.sdjwt.DisclosureSpec;
import org.keycloak.sdjwt.SdJwt;
import org.keycloak.sdjwt.vp.KeyBindingJWT;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.services.Urls;
import org.keycloak.testsuite.client.KeycloakTestingClient;
import org.keycloak.testsuite.runonserver.FetchOnServer;
import org.keycloak.urls.UrlType;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Objects;

import static org.keycloak.protocol.oid4vc.issuance.credentialbuilder.SdJwtCredentialBody.CNF_CLAIM;
import static org.keycloak.protocol.oid4vc.issuance.credentialbuilder.SdJwtCredentialBody.JWK_CLAIM;
import static org.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.STATUS_FIELD;
import static org.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.STATUS_LIST_FIELD;
import static org.keycloak.testsuite.AbstractTestRealmKeycloakTest.TEST_REALM_NAME;

/**
 * Test helper for crafting SD-JWT verifiable presentations.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtVPTestUtils {

    public static final int ISSUER_SIGNED_JWT_LIFESPAN_SECS = 300;
    public static final int KB_JWT_LIFESPAN_SECS = 60;
    public static final String EXP_CLAIM_KEY = "exp";

    private final KeycloakTestingClient testingClient;

    public SdJwtVPTestUtils(KeycloakTestingClient testingClient) {
        this.testingClient = testingClient;
    }

    /**
     * Requests that Keycloak issue an SD-JWT credential.
     */
    public String requestSdJwtCredential(String vct, String username) {
        return requestSdJwtCredential(vct, username, true, true);
    }

    /**
     * Requests that Keycloak issue an SD-JWT credential.
     *
     * @param vct            The verifiable credential type
     * @param username       The username of the user whom the credential is issued for
     * @param setKid         Specifies if the ID of the key used by Keycloak for issuing the credential
     *                       should be set to the `kid` header of the SD-JWT
     * @param setStatusClaim Specifies whether to include a status claim in the issued credential
     */
    public String requestSdJwtCredential(String vct, String username, boolean setKid, boolean setStatusClaim) {
        FetchOnServer sdJwtFetcher = (session) -> {
            RealmModel realm = session.realms().getRealmByName(TEST_REALM_NAME);
            KeyWrapper signingKey = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.ES256);

            if (!setKid) {
                signingKey.setKid(null);
            }

            SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, Algorithm.ES256);
            SignatureSignerContext signer = signatureProvider.signer(signingKey);

            String keycloakIssuerURI = Urls.realmIssuer(
                    session.getContext().getUri(UrlType.FRONTEND).getBaseUri(),
                    TEST_REALM_NAME
            );

            SdJwt sdJwt = exampleSdJwtCredential(keycloakIssuerURI, vct, username, setStatusClaim)
                    .withSigner(signer)
                    .build();

            return sdJwt.toSdJwtString();
        };

        return testingClient.server().fetch(sdJwtFetcher, String.class);
    }

    /**
     * Scaffold an SD-JWT identity credential that can clear authentication.
     */
    private static SdJwt.Builder exampleSdJwtCredential(
            String iss, String vct, String username, boolean setStatusClaim
    ) {
        Objects.requireNonNull(iss);
        Objects.requireNonNull(vct);

        ObjectNode claimSet = JsonSerialization.mapper.createObjectNode();
        claimSet.put(OAuth2Constants.ISSUER, iss);
        claimSet.put(SdJwtAuthenticatorFactory.VCT_CONFIG, vct);
        claimSet.put(EXP_CLAIM_KEY, Time.currentTime() + ISSUER_SIGNED_JWT_LIFESPAN_SECS);

        // Add status list claim (Token Status List)
        if (setStatusClaim) {
            claimSet.set(STATUS_FIELD, JsonSerialization.mapper.valueToTree(
                    Map.of(STATUS_LIST_FIELD, new ReferencedTokenValidator.StatusInfo(
                            0, "https://example.com/status-list-jwt"
                    ))
            ));
        }

        DisclosureSpec.Builder disclosure = DisclosureSpec.builder()
                .withDecoyClaim("G02NSrQfjFXQ7Io09syajA");

        // Bind credential to user
        JWK jwk = ECTestUtils.getECPublicJwk(getUserJwk());
        ObjectNode cnf = JsonSerialization.mapper.createObjectNode();
        cnf.set(JWK_CLAIM, JsonSerialization.mapper.valueToTree(jwk));
        claimSet.set(CNF_CLAIM, cnf);

        if (username != null) {
            claimSet.put(OAuth2Constants.USERNAME, username);
            disclosure = disclosure.withUndisclosedClaim(OAuth2Constants.USERNAME, "eI8ZWm9QnKPpNPeNenHdhQ");
        }

        return SdJwt.builder()
                .withDisclosureSpec(disclosure.build())
                .withClaimSet(claimSet);
    }

    /**
     * Creates an SD-JWT verifiable presentation of an SD-JWT credential.
     */
    public String presentSdJwt(String sdjwt, String nonce, String aud, JWK holderKey)
            throws Exception {
        return presentSdJwt(sdjwt, nonce, aud, holderKey, KB_JWT_LIFESPAN_SECS);
    }

    /**
     * Creates an SD-JWT verifiable presentation of an SD-JWT credential.
     *
     * @param sdjwt         The SD-JWT credential (without key-binding JWT)
     * @param nonce         A nonce value for replay protection
     * @param aud           An audience for replay protection
     * @param holderKey     The holder's private key
     * @param kbJwtLifespan The validity of the key-binding JWT in seconds
     */
    public String presentSdJwt(String sdjwt, String nonce, String aud, JWK holderKey, long kbJwtLifespan)
            throws Exception {
        JsonWebToken kbJwtClaims = new JsonWebToken();

        long currentTime = Time.currentTime();
        kbJwtClaims.iat(currentTime);
        kbJwtClaims.exp(currentTime + kbJwtLifespan);

        kbJwtClaims.getOtherClaims().put(IDToken.NONCE, nonce);
        kbJwtClaims.getOtherClaims().put(IDToken.AUD, aud);

        KeyWrapper keyWrapper = ECTestUtils.getEcKeyWrapper(holderKey);
        SignatureSignerContext signer = new ECDSASignatureSignerContext(keyWrapper);

        SdJwtVP sdJwtVP = SdJwtVP.of(sdjwt);
        return sdJwtVP.present(
                null,
                JsonSerialization.mapper.valueToTree(kbJwtClaims),
                signer,
                KeyBindingJWT.TYP
        );
    }

    public static JWK getUserJwk() {
        return testJwkResource("/oid4vc/oid4vp/user-wallet-key.json");
    }

    public static JWK getStrayJwk() {
        return testJwkResource("/oid4vc/oid4vp/stray-key.json");
    }

    /**
     * Load a test resource file, assuming it is a JWK.
     */
    private static JWK testJwkResource(String filename) {
        try (InputStream stream = SdJwtVPTestUtils.class.getResourceAsStream(filename)) {
            return JsonSerialization.readValue(stream, JWK.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
