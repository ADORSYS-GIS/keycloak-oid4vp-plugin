package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.metadata;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import io.github.adorsysgis.keycloak.protocol.oid4vc.presentation.AuthorizationChallengeEndpointFactory;
import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.jboss.logging.Logger;
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
    public static final String ATTR_PRESENTATION_DURING_ISSUANCE = "oid4vci.presentation_during_issuance";

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

        // Always omit encryption parameters from metadata
        metadata.setCredentialResponseEncryption(null);
        metadata.setCredentialRequestEncryption(null);

        return metadata;
    }

    private boolean isPresentationDuringIssuanceEnabled() {
        return Boolean.parseBoolean(realm.getAttribute(ATTR_PRESENTATION_DURING_ISSUANCE));
    }

    private String authorizationChallengeEndpoint() {
        String baseRealmUrl = Urls.realmIssuer(
                keycloakSession.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName());
        return baseRealmUrl + "/" + AuthorizationChallengeEndpointFactory.PROVIDER_ID;
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
