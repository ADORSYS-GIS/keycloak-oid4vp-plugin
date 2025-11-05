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

package org.keycloak.protocol.oid4vc.tokenstatus.http;

import org.keycloak.common.VerificationException;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import static org.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;

/**
 * Status list JWT data fetcher with trust enforcement.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class TrustedStatusListJwtFetcher extends SimpleStatusListJwtFetcher {

    public TrustedStatusListJwtFetcher(KeycloakSession session) {
        super(session);
    }

    @Override
    public String fetchStatusListJwt(String uri) throws ReferencedTokenValidationException {
        // Enforce HTTPS
        if (!uri.startsWith("https://")) {
            throw new ReferencedTokenValidationException("Status list JWT URI must use HTTPS: " + uri);
        }

        // Retrieve status list JWT
        String statusListJwt = _fetchStatusListJwt(uri);
        JWSInput jws = parseStatusListJwt(statusListJwt);

        // Extract verifying key from X5C cert chain
        // TODO: Enforce trust in X5C chain
        SignatureVerifierContext verifier = getVerifierFromX5C(jws);

        // Verify signature
        validateJwsSignature(jws, verifier);

        return statusListJwt;
    }

    protected String _fetchStatusListJwt(String uri) throws ReferencedTokenValidationException {
        return super.fetchStatusListJwt(uri);
    }

    private JWSInput parseStatusListJwt(String statusListJwt) throws ReferencedTokenValidationException {
        try {
            return new JWSInput(statusListJwt);
        } catch (JWSInputException e) {
            throw new ReferencedTokenValidationException(
                    String.format("Retrieved status list is not a valid JWT: %s", statusListJwt), e
            );
        }
    }

    private SignatureVerifierContext getVerifierFromX5C(JWSInput jws) throws ReferencedTokenValidationException {
        try {
            JWSHeader header = jws.getHeader();
            List<String> x5cList = header.getX5c();

            if (x5cList == null || x5cList.isEmpty()) {
                throw new VerificationException("Missing or empty x5c header in JWS");
            }

            // Convert base64-encoded leaf cert into X509Certificate
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream der = new ByteArrayInputStream(Base64.getDecoder().decode(x5cList.get(0)));
            X509Certificate cert = (X509Certificate) cf.generateCertificate(der);

            // Return verifier corresponing to certificate
            return toSignatureVerifier(cert, header.getAlgorithm().name());
        } catch (Exception e) {
            throw new ReferencedTokenValidationException("Could not extract verifier from X5C certificate chain", e);
        }
    }

    private SignatureVerifierContext toSignatureVerifier(X509Certificate cert, String alg)
            throws VerificationException, ReferencedTokenValidationException {
        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, alg);
        if (signatureProvider == null) {
            throw new ReferencedTokenValidationException("Unsupported signature algorithm: " + alg);
        }

        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setPublicKey(cert.getPublicKey());
        keyWrapper.setType(algorithmToKeyType(alg));
        keyWrapper.setAlgorithm(alg);

        return signatureProvider.verifier(keyWrapper);
    }

    protected String algorithmToKeyType(String alg) throws ReferencedTokenValidationException {
        return switch (alg) {
            case Algorithm.RS256, Algorithm.RS384, Algorithm.RS512,
                 Algorithm.PS256, Algorithm.PS384, Algorithm.PS512 -> KeyType.RSA;
            case Algorithm.ES256, Algorithm.ES384, Algorithm.ES512 -> KeyType.EC;
            default -> throw new ReferencedTokenValidationException("Unsupported signature algorithm");
        };
    }

    private void validateJwsSignature(JWSInput jws, SignatureVerifierContext verifier)
            throws ReferencedTokenValidationException {
        try {
            if (!verifier.verify(jws.getEncodedSignatureInput().getBytes(), jws.getSignature())) {
                throw new ReferencedTokenValidationException("Invalid JWS signature");
            }
        } catch (Exception e) {
            throw new ReferencedTokenValidationException("Error during JWS signature verification", e);
        }
    }
}
