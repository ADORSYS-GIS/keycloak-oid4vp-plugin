package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.metadata;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import io.github.adorsysgis.keycloak.protocol.oid4vc.presentation.AuthorizationChallengeEndpointFactory;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Consumer;
import org.jboss.logging.Logger;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.JWSBuilder;
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
     * The German EUDI Wallet (Android) only tolerates the leaf certificate in the {@code x5c} header of
     * the signed Credential Issuer Metadata. Upstream Keycloak advertises the whole certificate chain
     * (minus the trailing self-signed trust anchor), which the wallet rejects. When the realm
     * attribute {@value ATTR_PATCH_METADATA_X5C_TO_LEAF_CERT_ONLY} is enabled, only the leaf certificate
     * is advertised; otherwise the upstream behavior is preserved.
     */
    @Override
    public Optional<String> generateSignedMetadata(CredentialIssuer metadata, KeycloakSession session) {
        if (!isPatchMetadataX5cToLeafCertOnlyEnabled()) {
            return super.generateSignedMetadata(metadata, session);
        }

        return OID4VCIssuerWellKnownProviderCopy.generateSignedMetadata(
                metadata, session, this::addLeafCertificateHeader);
    }

    private void addLeafCertificateHeader(JWSBuilder jwsBuilder, KeyWrapper keyWrapper) {
        List<X509Certificate> chain = keyWrapper.getCertificateChain();
        X509Certificate leaf = (chain != null && !chain.isEmpty()) ? chain.get(0) : keyWrapper.getCertificate();
        if (leaf != null) {
            jwsBuilder.x5c(List.of(leaf));
        } else {
            logger.debugf("No leaf certificate available for x5c header in realm: %s", realm.getName());
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
