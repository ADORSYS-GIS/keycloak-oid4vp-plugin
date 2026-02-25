package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.SdGenericFormat;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.services.Urls;
import org.keycloak.urls.UrlType;

/**
 * Discovers client metadata and other properties as Keycloak acts as an OpenID4VP client.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#name-verifier-metadata-client-me">
 * Verifier Metadata (Client Metadata)</a>
 */
public class VerifierDiscoveryService {

    private static final Logger logger = Logger.getLogger(VerifierDiscoveryService.class);

    private final KeycloakSession session;

    public VerifierDiscoveryService(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Discovers and return client metadata as Keycloak acts as an OpenID4VP client.
     */
    public ClientMetadata getClientMetadata() {
        logger.debug("Discovering Keycloak's metadata as an OpenID4VP client");

        // Only SD-JWT presentations are supported for now.
        ClientMetadata.VpFormat vpFormat = new ClientMetadata.VpFormat();
        vpFormat.setVcSdJwt(getSdJwtVpFormat());

        // Aggregate metadata
        return new ClientMetadata().setClientId(getClientId()).setVpFormat(vpFormat);
    }

    /**
     * Returns the root URL path common to OpenID4VP routes.
     */
    public String getOpenID4VPRootUrl() {
        KeycloakContext context = session.getContext();
        String baseRealmUrl = Urls.realmIssuer(
                context.getUri(UrlType.FRONTEND).getBaseUri(),
                context.getRealm().getName());

        return baseRealmUrl + "/" + OID4VPUserAuthEndpointFactory.PROVIDER_ID;
    }

    /**
     * Returns the signing key to use for signing authorization requests.
     * <p>
     * Preferred algorithm is ES256, but falls back to any available signing key.
     * </p>
     */
    public KeyWrapper getSigningKey() {
        logger.debug("Retrieving active key for signing OpenID4VP authorization requests");
        KeyManager keyManager = session.keys();
        RealmModel realm = session.getContext().getRealm();

        // EC cryptography is widely preferred in the OpenID4VC ecosystem.
        KeyWrapper key = keyManager.getActiveKey(realm, KeyUse.SIG, Algorithm.ES256);

        // Fall back to available key if ES256 is not available or its certificate missing.
        if (key == null || key.getCertificate() == null) {
            key = session.keys()
                    .getKeysStream(realm)
                    .filter(k -> k.getStatus().isActive() && k.getUse() == KeyUse.SIG && k.getCertificate() != null)
                    .findFirst()
                    .orElseThrow(() -> new IllegalStateException("No active signing key with certificate found"));
        }

        return key;
    }

    private String getClientId() {
        // The client ID is typically the hostname of the Keycloak server.
        return session.getContext().getUri().getBaseUri().getHost();
    }

    private SdGenericFormat getSdJwtVpFormat() {
        // This is about verification capabilities, so does not depend on current keys.
        var supportedSignatureAlgorithms = getSupportedSignatureAlgorithms();

        SdGenericFormat format = new SdGenericFormat();
        format.setSdJwtAlgValues(supportedSignatureAlgorithms);
        format.setKbJwtAlgValues(supportedSignatureAlgorithms);

        return format;
    }

    private List<String> getSupportedSignatureAlgorithms() {
        return session.getKeycloakSessionFactory()
                .getProviderFactoriesStream(SignatureProvider.class)
                .map(ProviderFactory::getId)
                .toList();
    }
}
