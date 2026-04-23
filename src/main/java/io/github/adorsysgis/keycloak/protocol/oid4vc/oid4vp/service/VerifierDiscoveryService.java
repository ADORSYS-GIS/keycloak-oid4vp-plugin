package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.EphemeralKeyUtils.EphemeralKey;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientIdScheme;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.SdGenericFormat;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.X509HashUtils;
import java.security.cert.X509Certificate;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
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

    public static final List<String> SUPPORTED_ENC_ALGS = List.of(JWEConstants.A256GCM);

    private final KeycloakSession session;

    public VerifierDiscoveryService(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Discovers and return client metadata as Keycloak acts as an OpenID4VP client.
     */
    public ClientMetadata getClientMetadata(EphemeralKey ephemeralKey) {
        logger.debug("Discovering Keycloak's metadata as an OpenID4VP client");
        ClientMetadata metadata = new ClientMetadata();

        // Only SD-JWT presentations are supported for now.
        ClientMetadata.VpFormat vpFormat = new ClientMetadata.VpFormat();
        vpFormat.setDcSdJwt(getSdJwtVpFormat());
        metadata.setVpFormat(vpFormat);

        // Advertise ephemeral key if any
        if (ephemeralKey != null) {
            JSONWebKeySet jwks = new JSONWebKeySet();
            jwks.setKeys(new JWK[] {ephemeralKey.publicKey()});
            metadata.setJwks(jwks).setEncryptedResponseEncValuesSupported(SUPPORTED_ENC_ALGS);
        }

        // Return aggregated metadata
        return metadata;
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
    public KeyWrapper getSigningKey(boolean requireSelfSignedCert) {
        logger.debug("Retrieving active key for signing OpenID4VP authorization requests");
        RealmModel realm = session.getContext().getRealm();

        // EC cryptography is widely preferred in the OpenID4VC ecosystem.
        // Favor ES256 keys but fall back to any active signing key if no such key is available.
        return session.keys()
                .getKeysStream(realm)
                .filter(k -> k.getStatus().isActive()
                        && k.getUse() == KeyUse.SIG
                        && (!requireSelfSignedCert || k.getCertificate() != null))
                .min((k1, k2) -> {
                    boolean isK1ES256 = Algorithm.ES256.equals(k1.getAlgorithm());
                    boolean isK2ES256 = Algorithm.ES256.equals(k2.getAlgorithm());
                    return Boolean.compare(isK2ES256, isK1ES256);
                })
                .orElseThrow(() -> new IllegalStateException(String.format(
                        "No active signing key found (requireSelfSignedCert = %s)", requireSelfSignedCert)));
    }

    public String getDnsNameClientId() {
        // Typically the hostname of the Keycloak server.
        return session.getContext().getUri().getBaseUri().getHost();
    }

    public String getClientId(ClientIdScheme clientIdScheme, X509Certificate clientCertificate) {
        // Compute client ID as per client ID scheme rules
        String clientId =
                switch (clientIdScheme) {
                    case X509_SAN_DNS -> getDnsNameClientId();
                    case X509_HASH -> X509HashUtils.computeX509Hash(clientCertificate);
                    default ->
                        throw new IllegalArgumentException(
                                "ClientIdScheme not supported: " + clientIdScheme.getValue());
                };

        // Prefix with scheme as per spec requirements
        return String.join(":", clientIdScheme.getValue(), clientId);
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
        // TODO: CryptoUtils.getSupportedAsymmetricSignatureAlgorithms(session);
        return List.of(Algorithm.ES256);
    }
}
