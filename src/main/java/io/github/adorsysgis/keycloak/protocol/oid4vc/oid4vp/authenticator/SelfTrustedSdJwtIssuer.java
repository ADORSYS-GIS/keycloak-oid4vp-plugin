package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import java.util.List;
import java.util.stream.Stream;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.consumer.TrustedSdJwtIssuer;

/**
 * Trust anchor enforcing Keycloak only trusts SD-JWTs that it issued can verify itself.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SelfTrustedSdJwtIssuer implements TrustedSdJwtIssuer {

    private static final Logger logger = Logger.getLogger(SelfTrustedSdJwtIssuer.class);

    private final KeycloakSession session;

    public SelfTrustedSdJwtIssuer(AuthenticationFlowContext context) {
        this.session = context.getSession();
    }

    @Override
    public List<SignatureVerifierContext> resolveIssuerVerifyingKeys(IssuerSignedJWT issuerSignedJWT) {
        logger.debugf("Gathering potential verifying keys for FiPA-based SDJWT authentication");

        RealmModel realm = session.getContext().getRealm();
        KeyManager keyManager = session.keys();
        Stream<KeyWrapper> keyStream = keyManager.getKeysStream(realm).filter(key -> KeyUse.SIG.equals(key.getUse()));

        String signingKeyId = issuerSignedJWT.getJwsHeader().getKeyId();
        if (signingKeyId != null) {
            keyStream = keyStream.filter(key -> signingKeyId.equals(key.getKid()));
        }

        return keyStream
                .map(key -> {
                    SignatureProvider signatureProvider =
                            session.getProvider(SignatureProvider.class, key.getAlgorithmOrDefault());
                    try {
                        return signatureProvider.verifier(key);
                    } catch (VerificationException e) {
                        throw new RuntimeException(e);
                    }
                })
                .toList();
    }
}
