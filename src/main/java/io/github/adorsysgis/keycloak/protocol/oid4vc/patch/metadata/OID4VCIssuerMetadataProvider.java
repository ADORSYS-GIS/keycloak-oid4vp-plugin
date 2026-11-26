package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.metadata;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.presentation.AuthorizationChallengeEndpointFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import org.jboss.logging.Logger;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider;
import org.keycloak.protocol.oid4vc.model.CredentialIssuer;
import org.keycloak.protocol.oid4vc.model.DisplayObject;
import org.keycloak.services.Urls;
import org.keycloak.urls.UrlType;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

public class OID4VCIssuerMetadataProvider extends OID4VCIssuerWellKnownProvider {

    private static final Logger logger = Logger.getLogger(OID4VCIssuerMetadataProvider.class);

    public static final String ATTR_DISPLAY = "oid4vci.display";
    public static final String ATTR_OMIT_ENCRYPTION_METADATA = "oid4vci.omit_encryption_metadata";
    public static final String ATTR_PRESENTATION_DURING_ISSUANCE = "oid4vci.presentation_during_issuance";
    public static final String ATTR_PATCH_METADATA_X5C_TO_LEAF_CERT_ONLY =
            "oid4vci.patch_metadata_x5c_to_leaf_cert_only";
    public static final String ATTR_PATCH_METADATA_X5C_TO_OID4VP_ACCESS_CERTIFICATE =
            "oid4vci.patch_metadata_x5c_to_oid4vp_access_certificate";

    private final RealmModel realm;

    public OID4VCIssuerMetadataProvider(KeycloakSession keycloakSession) {
        super(keycloakSession);
        realm = keycloakSession.getContext().getRealm();
    }

    @Override
    public CredentialIssuer getIssuerMetadata() {
        CredentialIssuer metadata = super.getIssuerMetadata();

        // The German EUDI Wallet ecosystem profile requires the Authorization Challenge Endpoint
        // directly in the Credential Issuer Metadata. Keep advertising it in the Authorization
        // Server Metadata as well, as required by the underlying First-Party Applications draft.
        if (isPresentationDuringIssuanceEnabled()) {
            metadata = ExtendedCredentialIssuer.from(metadata, authorizationChallengeEndpoint());
        }

        // Add root display metadata
        metadata.setDisplay(parseDisplay());

        // Omit encryption parameters from metadata when the realm attribute is enabled (default off)
        if (isOmitEncryptionEnabled()) {
            metadata.setCredentialResponseEncryption(null);
            metadata.setCredentialRequestEncryption(null);
        }

        // The spec forbids empty arrays: an empty zip_values_supported must be omitted from
        // the request encryption metadata. Keycloak may expose an empty array due to this
        // bug: https://github.com/keycloak/keycloak/issues/54115
        if (metadata.getCredentialRequestEncryption() != null) {
            pruneEmptyValues(
                    metadata.getCredentialRequestEncryption().getZipValuesSupported(),
                    metadata.getCredentialRequestEncryption()::setZipValuesSupported);
        }

        // Same for the response encryption metadata: omit an empty zip_values_supported array.
        if (metadata.getCredentialResponseEncryption() != null) {
            pruneEmptyValues(
                    metadata.getCredentialResponseEncryption().getZipValuesSupported(),
                    metadata.getCredentialResponseEncryption()::setZipValuesSupported);
        }

        return metadata;
    }

    /**
     * Builds the signed-metadata certificate header. The OpenID4VP access-certificate attribute, when
     * enabled, takes precedence and uses that certificate only if it matches the metadata signing key.
     * Otherwise, the leaf-only attribute can limit {@code x5c} to the signing key's leaf certificate;
     * when both attributes are disabled, upstream Keycloak's certificate-chain behavior is preserved.
     */
    @Override
    public Optional<String> generateSignedMetadata(CredentialIssuer metadata, KeycloakSession session) {
        if (isPatchMetadataX5cFromOid4vpAccessCertificateEnabled()) {
            Optional<X509Certificate> accessCertificate = configuredOid4vpAccessCertificate();
            if (accessCertificate.isPresent()) {
                X509Certificate certificate = accessCertificate.get();
                if (matchesIssuerMetadataSigningKey(certificate, session)) {
                    return OID4VCIssuerWellKnownProviderCopy.generateSignedMetadata(
                            metadata, session, (builder, keyWrapper) -> builder.x5c(List.of(certificate)));
                }

                logger.warnf(
                        "The configured OpenID4VP access certificate does not match the signed metadata key in realm '%s'; falling back to the next x5c setting",
                        realm.getName());
            } else {
                logger.warnf(
                        "Realm attribute %s is enabled but no valid OpenID4VP access certificate is configured in realm '%s'; falling back to the next x5c setting",
                        ATTR_PATCH_METADATA_X5C_TO_OID4VP_ACCESS_CERTIFICATE, realm.getName());
            }
        }

        if (isPatchMetadataX5cToLeafCertOnlyEnabled()) {
            return OID4VCIssuerWellKnownProviderCopy.generateSignedMetadata(
                    metadata, session, this::addLeafCertificateHeader);
        }

        return super.generateSignedMetadata(metadata, session);
    }

    private void addLeafCertificateHeader(JWSBuilder jwsBuilder, KeyWrapper keyWrapper) {
        List<X509Certificate> chain = keyWrapper.getCertificateChain();
        X509Certificate leaf = (chain != null && !chain.isEmpty()) ? chain.getFirst() : keyWrapper.getCertificate();
        if (leaf != null) {
            jwsBuilder.x5c(List.of(leaf));
        } else {
            logger.debugf("No leaf certificate available for x5c header in realm: %s", realm.getName());
        }
    }

    private Optional<X509Certificate> configuredOid4vpAccessCertificate() {
        AuthenticationFlowModel flow = realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW);
        if (flow == null) {
            return Optional.empty();
        }

        String encodedCertificate = realm.getAuthenticationExecutionsStream(flow.getId())
                .filter(execution -> OID4VPAuthenticatorFactory.PROVIDER_ID.equals(execution.getAuthenticator()))
                .map(AuthenticationExecutionModel::getAuthenticatorConfig)
                .filter(StringUtil::isNotBlank)
                .map(realm::getAuthenticatorConfigById)
                .filter(Objects::nonNull)
                .map(AuthenticatorConfigModel::getConfig)
                .filter(Objects::nonNull)
                .map(config -> config.get(OID4VPAuthenticatorFactory.ACCESS_CERTIFICATE_CONFIG))
                .filter(StringUtil::isNotBlank)
                .findFirst()
                .orElse(null);
        if (StringUtil.isBlank(encodedCertificate)) {
            return Optional.empty();
        }

        try {
            byte[] der = Base64.getDecoder().decode(encodedCertificate);
            X509Certificate certificate = (X509Certificate)
                    CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
            return Optional.of(certificate);
        } catch (IllegalArgumentException | CertificateException e) {
            logger.warnf(e, "Invalid OpenID4VP access certificate configured in realm '%s'", realm.getName());
            return Optional.empty();
        }
    }

    private boolean matchesIssuerMetadataSigningKey(X509Certificate certificate, KeycloakSession session) {
        try {
            String algorithm = OID4VCIssuerWellKnownProviderCopy.getSigningAlgorithm(realm, session);
            KeyWrapper signingKey = session.keys().getActiveKey(realm, KeyUse.SIG, algorithm);
            return signingKey != null
                    && signingKey.getPublicKey() instanceof PublicKey publicKey
                    && Arrays.equals(certificate.getPublicKey().getEncoded(), publicKey.getEncoded());
        } catch (IllegalStateException e) {
            logger.warnf(e, "Could not determine the signed metadata key for realm '%s'", realm.getName());
            return false;
        }
    }

    private boolean isOmitEncryptionEnabled() {
        return Boolean.parseBoolean(realm.getAttribute(ATTR_OMIT_ENCRYPTION_METADATA));
    }

    private boolean isPresentationDuringIssuanceEnabled() {
        return Boolean.parseBoolean(realm.getAttribute(ATTR_PRESENTATION_DURING_ISSUANCE));
    }

    private boolean isPatchMetadataX5cToLeafCertOnlyEnabled() {
        return Boolean.parseBoolean(realm.getAttribute(ATTR_PATCH_METADATA_X5C_TO_LEAF_CERT_ONLY));
    }

    private boolean isPatchMetadataX5cFromOid4vpAccessCertificateEnabled() {
        return Boolean.parseBoolean(realm.getAttribute(ATTR_PATCH_METADATA_X5C_TO_OID4VP_ACCESS_CERTIFICATE));
    }

    private String authorizationChallengeEndpoint() {
        String baseRealmUrl = Urls.realmIssuer(
                keycloakSession.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName());
        return baseRealmUrl + "/" + AuthorizationChallengeEndpointFactory.PROVIDER_ID;
    }

    /**
     * Helper to nullify empty arrays (often not permitted by the spec).
     */
    static <T> void pruneEmptyValues(List<T> values, Consumer<List<T>> setter) {
        if (values != null && values.isEmpty()) {
            setter.accept(null);
        }
    }

    private List<DisplayObject> parseDisplay() {
        String displayJson = realm.getAttribute(ATTR_DISPLAY);
        if (StringUtil.isBlank(displayJson)) {
            return null;
        }

        try {
            List<DisplayObject> display = JsonSerialization.readValue(displayJson, new TypeReference<>() {});

            // Select only legal fields for root display metadata
            List<DisplayObject> prunedDisplay = Optional.ofNullable(display).orElseGet(Collections::emptyList).stream()
                    .filter(Objects::nonNull)
                    .map(d -> new DisplayObject()
                            .setName(d.getName())
                            .setLocale(d.getLocale())
                            .setLogo(d.getLogo()))
                    .toList();

            // Empty arrays are not valid according to the spec
            return prunedDisplay.isEmpty() ? null : prunedDisplay;
        } catch (IOException e) {
            // Log the error and return null if parsing fails
            logger.error("Failed to parse display metadata", e);
            return null;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private static final class ExtendedCredentialIssuer extends CredentialIssuer {

        @JsonProperty("authorization_challenge_endpoint")
        private String authorizationChallengeEndpoint;

        private static ExtendedCredentialIssuer from(CredentialIssuer source, String authorizationChallengeEndpoint) {
            ExtendedCredentialIssuer target =
                    JsonSerialization.mapper.convertValue(source, ExtendedCredentialIssuer.class);
            target.authorizationChallengeEndpoint = authorizationChallengeEndpoint;
            return target;
        }
    }
}
