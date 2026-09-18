package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sdjwt.IssuerSignedJWT;

/**
 * Classifies a credential independently of the trust policy that accepted it.
 *
 * <p>A credential belongs to the current realm only when its verified issuer signature can be
 * attributed to a signing key owned by that realm. Key IDs and issuer strings are hints, never the
 * proof: SD-JWT signatures are checked again with realm keys and mdoc public keys are compared with
 * the leaf certificate whose chain and COSE signature were already verified.
 */
public final class CredentialOriginResolver {

    private CredentialOriginResolver() {}

    public static CredentialOrigin forSdJwt(KeycloakSession session, IssuerSignedJWT issuerSignedJwt) {
        RealmModel realm = session.getContext().getRealm();

        boolean signedByRealm = session.keys()
                .getKeysStream(realm)
                .filter(key -> KeyUse.SIG.equals(key.getUse()))
                .anyMatch(key -> verifies(session, issuerSignedJwt, key));
        return signedByRealm ? CredentialOrigin.CURRENT_REALM : CredentialOrigin.EXTERNAL;
    }

    public static CredentialOrigin forMdoc(KeycloakSession session, X509Certificate verifiedIssuerCertificate) {
        if (verifiedIssuerCertificate == null) {
            return CredentialOrigin.EXTERNAL;
        }
        Key issuerKey = verifiedIssuerCertificate.getPublicKey();
        RealmModel realm = session.getContext().getRealm();
        boolean ownedByRealm = session.keys()
                .getKeysStream(realm)
                .filter(key -> KeyUse.SIG.equals(key.getUse()))
                .map(KeyWrapper::getPublicKey)
                .anyMatch(key -> sameKey(key, issuerKey));
        return ownedByRealm ? CredentialOrigin.CURRENT_REALM : CredentialOrigin.EXTERNAL;
    }

    private static boolean verifies(KeycloakSession session, IssuerSignedJWT jwt, KeyWrapper key) {
        SignatureProvider provider = session.getProvider(SignatureProvider.class, key.getAlgorithmOrDefault());
        if (provider == null) {
            return false;
        }
        try {
            SignatureVerifierContext verifier = provider.verifier(key);
            jwt.verifySignature(verifier);
            return true;
        } catch (VerificationException | RuntimeException ignored) {
            return false;
        }
    }

    private static boolean sameKey(Key left, Key right) {
        return left != null
                && right != null
                && left.getEncoded() != null
                && right.getEncoded() != null
                && Arrays.equals(left.getEncoded(), right.getEncoded());
    }
}
