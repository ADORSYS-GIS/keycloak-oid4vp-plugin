package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.metadata;

import io.github.adorsysgis.keycloak.protocol.oid4vc.presentation.AuthorizationChallengeEndpointFactory;
import java.util.Map;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCWellKnownProvider;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.services.Urls;
import org.keycloak.urls.UrlType;

/**
 * Extends the OIDC/OAuth Authorization Server Metadata with the {@code authorization_challenge_endpoint}
 * parameter when Interactive Authorization (presentation during issuance) is enabled.
 *
 * <p>OID4VCI §6 (and RFC 9470) require the {@code authorization_challenge_endpoint} to be advertised in
 * the Authorization Server Metadata, not the Credential Issuer Metadata. This provider adds it there.
 */
public class OIDCAsMetadataProvider extends OIDCWellKnownProvider {

    public static final String AUTHORIZATION_CHALLENGE_ENDPOINT = "authorization_challenge_endpoint";

    private final KeycloakSession session;

    public OIDCAsMetadataProvider(
            KeycloakSession session, Map<String, Object> openidConfigOverride, boolean includeClientScopes) {
        super(session, openidConfigOverride, includeClientScopes);
        this.session = session;
    }

    @Override
    public Object getConfig() {
        Object config = super.getConfig();

        if (config instanceof OIDCConfigurationRepresentation representation && isPresentationDuringIssuanceEnabled()) {
            representation.setOtherClaims(AUTHORIZATION_CHALLENGE_ENDPOINT, authorizationChallengeEndpoint());
        }

        return config;
    }

    private boolean isPresentationDuringIssuanceEnabled() {
        RealmModel realm = session.getContext().getRealm();
        return Boolean.parseBoolean(realm.getAttribute(OID4VCIssuerMetadataProvider.ATTR_PRESENTATION_DURING_ISSUANCE));
    }

    private String authorizationChallengeEndpoint() {
        RealmModel realm = session.getContext().getRealm();
        String baseRealmUrl =
                Urls.realmIssuer(session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName());
        return baseRealmUrl + "/" + AuthorizationChallengeEndpointFactory.PROVIDER_ID;
    }
}
