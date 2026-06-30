package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.TrustPolicy;
import java.security.cert.X509Certificate;
import java.util.List;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.consumer.TrustedSdJwtIssuer;
import org.keycloak.utils.StringUtil;

public class EudiPidTrustedSdJwtIssuer implements TrustedSdJwtIssuer {

    private final TrustPolicy policy;
    private final EudiPidTrustListProvider trustListProvider;
    private final EudiCertificateChainValidator chainValidator = new EudiCertificateChainValidator();

    public EudiPidTrustedSdJwtIssuer(KeycloakSession session, TrustPolicy policy) {
        this(policy, new EudiPidTrustListProvider(session));
    }

    EudiPidTrustedSdJwtIssuer(TrustPolicy policy, EudiPidTrustListProvider trustListProvider) {
        this.policy = policy;
        this.trustListProvider = trustListProvider;
    }

    @Override
    public List<SignatureVerifierContext> resolveIssuerVerifyingKeys(IssuerSignedJWT issuerSignedJWT)
            throws VerificationException {
        validateConfiguredIssuer(issuerSignedJWT);

        EudiPidTrustListProvider.TrustListSnapshot trustList = trustListProvider.resolve(policy);
        X509Certificate[] issuerChain =
                chainValidator.validate(issuerSignedJWT.getJwsHeader().getX5c(), trustList.trustedIssuerCertificates());
        X509Certificate issuerLeaf = issuerChain[0];
        SignatureVerifierContext verifier =
                trustListProvider.verifier(issuerSignedJWT.getJwsHeader().getRawAlgorithm(), issuerLeaf);
        return List.of(verifier);
    }

    private void validateConfiguredIssuer(IssuerSignedJWT issuerSignedJWT) throws EudiPidTrustException {
        if (StringUtil.isBlank(policy.getIssuer())) {
            return;
        }
        String actualIssuer = issuerSignedJWT.getPayload().path("iss").asText(null);
        if (!policy.getIssuer().equals(actualIssuer)) {
            throw new EudiPidTrustException(
                    "PID credential issuer does not match configured trusted issuer: " + actualIssuer);
        }
    }
}
