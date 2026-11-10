/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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

package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.metadata;

import static org.keycloak.OID4VCConstants.SIGNED_METADATA_JWT_TYPE;
import static org.keycloak.jose.jwk.RSAPublicJWK.RS256;
import static org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider.SIGNED_METADATA_ALG_ATTR;
import static org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider.SIGNED_METADATA_LIFESPAN_ATTR;
import static org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider.getSupportedAsymmetricSignatureAlgorithms;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiConsumer;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider;
import org.keycloak.protocol.oid4vc.model.CredentialIssuer;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JsonSerialization;

/**
 * Verbatim copy of the signed-metadata generation logic from upstream
 * {@link OID4VCIssuerWellKnownProvider#generateSignedMetadata(CredentialIssuer, KeycloakSession)}.
 *
 * <p>This code is <strong>copied verbatim</strong> from upstream Keycloak because the certificate
 * header handling (upstream {@code addCertificateHeaders}) is {@code private} and therefore cannot
 * be overridden. To advertise only the leaf certificate in the {@code x5c} header (see
 * {@link OID4VCIssuerMetadataProvider#ATTR_PATCH_METADATA_X5C_TO_LEAF_CERT_ONLY}) we have to reproduce
 * the whole signing flow and inject the certificate-header step at the one place it differs from
 * upstream.
 *
 * <p>The only intentional divergence from upstream is that the {@code x5c} header is built by the
 * supplied {@code addCertificateHeaders} callback instead of the private upstream
 * {@code addCertificateHeaders}. Everything else mirrors the upstream implementation and should be
 * kept in sync when Keycloak is upgraded.
 */
public final class OID4VCIssuerWellKnownProviderCopy {

    private static final Logger LOGGER = Logger.getLogger(OID4VCIssuerWellKnownProviderCopy.class);

    private OID4VCIssuerWellKnownProviderCopy() {}

    /**
     * Generates signed metadata as a JWS using JsonWebToken infrastructure.
     *
     * @param metadata The CredentialIssuer metadata object to sign.
     * @param session  The Keycloak session.
     * @param addCertificateHeaders Hook that adds the x5c certificate header to the JWS builder.
     * @return Optional containing the compact JWS string if successful, empty if fallback to unsigned JSON is needed.
     */
    public static Optional<String> generateSignedMetadata(
            CredentialIssuer metadata,
            KeycloakSession session,
            BiConsumer<JWSBuilder, KeyWrapper> addCertificateHeaders) {
        RealmModel realm = session.getContext().getRealm();
        KeyManager keyManager = session.keys();

        // Select asymmetric signing algorithm
        String alg;
        try {
            alg = getSigningAlgorithm(realm, session);
        } catch (IllegalStateException e) {
            LOGGER.warnf("Failed to get signing algorithm: %s. Falling back to unsigned metadata.", e.getMessage());
            return Optional.empty(); // Return empty to indicate fallback to JSON
        }

        // Retrieve active key
        KeyWrapper keyWrapper = keyManager.getActiveKey(realm, KeyUse.SIG, alg);
        if (keyWrapper == null) {
            LOGGER.warnf(
                    "No active key found for realm '%s' with algorithm '%s'. Falling back to unsigned metadata.",
                    realm.getName(), alg);
            return Optional.empty();
        }

        // Create JsonWebToken with metadata as claims
        JsonWebToken jwt = createMetadataJwt(metadata, realm);

        // Validate lifespan configuration
        Optional<String> maybeLifespan = Optional.ofNullable(realm.getAttribute(SIGNED_METADATA_LIFESPAN_ATTR));
        if (maybeLifespan.isPresent()) {
            String lifespanVal = maybeLifespan.get();
            try {
                jwt.exp(Time.currentTime() + Long.parseLong(lifespanVal));
            } catch (NumberFormatException e) {
                LOGGER.warnf(
                        "Invalid lifespan duration for signed metadata: %s. Falling back to unsigned metadata.",
                        lifespanVal);
                return Optional.empty(); // Return empty to indicate fallback to JSON
            }
        } else {
            jwt.exp(Time.currentTime() + 3600L);
        }

        // Build JWS with proper headers
        JWSBuilder jwsBuilder = new JWSBuilder().type(SIGNED_METADATA_JWT_TYPE).kid(keyWrapper.getKid());

        // Add x5c certificate chain if available
        addCertificateHeaders.accept(jwsBuilder, keyWrapper);

        // Sign the JWS
        SignatureProvider signerProvider = session.getProvider(SignatureProvider.class, alg);
        if (signerProvider == null) {
            LOGGER.warnf("No signature provider for algorithm: %s. Falling back to unsigned metadata.", alg);
            return Optional.empty();
        }

        SignatureSignerContext signer = signerProvider.signer(keyWrapper);
        if (signer == null) {
            LOGGER.warnf("No signer context for algorithm: %s. Falling back to unsigned metadata.", alg);
            return Optional.empty();
        }

        try {
            return Optional.of(jwsBuilder.jsonContent(jwt).sign(signer));
        } catch (Exception e) {
            LOGGER.warnf(e, "Failed to sign metadata. Falling back to unsigned metadata.");
            return Optional.empty();
        }
    }

    private static String getSigningAlgorithm(RealmModel realm, KeycloakSession session) {
        List<String> supportedAlgorithms = getSupportedAsymmetricSignatureAlgorithms(session);

        if (supportedAlgorithms.isEmpty()) {
            throw new IllegalStateException("No asymmetric signing algorithms available for realm: " + realm.getName());
        }

        String configuredAlg = realm.getAttribute(SIGNED_METADATA_ALG_ATTR);
        if (configuredAlg != null) {
            if (!supportedAlgorithms.contains(configuredAlg)) {
                throw new IllegalStateException("Configured signing algorithm '" + configuredAlg
                        + "' is not supported for realm: " + realm.getName());
            }
            // Use the configured algorithm if present and supported
            return configuredAlg;
        }

        // Prefer RS256 if available, otherwise use the first supported asymmetric algorithm
        return supportedAlgorithms.contains(RS256) ? RS256 : supportedAlgorithms.get(0);
    }

    private static JsonWebToken createMetadataJwt(CredentialIssuer metadata, RealmModel realm) {
        JsonWebToken jwt = new JsonWebToken();

        // Set standard JWT claims
        jwt.subject(metadata.getCredentialIssuer());
        jwt.issuer(metadata.getCredentialIssuer());
        jwt.issuedNow();

        // Convert metadata to map and add as other claims
        Map<String, Object> metadataClaims = JsonSerialization.mapper.convertValue(metadata, Map.class);
        metadataClaims.forEach(jwt::setOtherClaims);

        return jwt;
    }
}
