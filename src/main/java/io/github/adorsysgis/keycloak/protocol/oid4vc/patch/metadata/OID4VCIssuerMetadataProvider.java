package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.metadata;

import com.fasterxml.jackson.core.type.TypeReference;
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
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

public class OID4VCIssuerMetadataProvider extends OID4VCIssuerWellKnownProvider {

    private static final Logger logger = Logger.getLogger(OID4VCIssuerMetadataProvider.class);

    public static final String ATTR_DISPLAY = "oid4vci.display";

    private final RealmModel realm;

    public OID4VCIssuerMetadataProvider(KeycloakSession keycloakSession) {
        super(keycloakSession);
        realm = keycloakSession.getContext().getRealm();
    }

    @Override
    public CredentialIssuer getIssuerMetadata() {
        CredentialIssuer metadata = super.getIssuerMetadata();

        // Add root display metadata
        metadata.setDisplay(parseDisplay());

        return metadata;
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
}
