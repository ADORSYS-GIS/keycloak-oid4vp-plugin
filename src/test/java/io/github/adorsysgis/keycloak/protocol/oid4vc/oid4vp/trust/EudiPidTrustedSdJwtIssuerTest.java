package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.TestCryptoUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.TrustPolicy;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.VerificationException;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sdjwt.IssuerSignedJWT;

class EudiPidTrustedSdJwtIssuerTest {

    private static final String PID_PROVIDER_ISSUER = "https://preprod.pid-provider.bundesdruckerei.de";

    @BeforeAll
    static void setupCrypto() {
        CryptoIntegration.init(EudiPidTrustedSdJwtIssuerTest.class.getClassLoader());
    }

    @Test
    void shouldResolveVerifierWhenPidCredentialChainsToTrustedCertificate() throws Exception {
        KeyPair caKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate caCertificate = TestCryptoUtils.createSelfSignedCaCert(caKeyPair);
        KeyPair leafKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate leafCertificate =
                TestCryptoUtils.createLeafCert(leafKeyPair, caKeyPair, caCertificate, "CN=PID Issuer");
        SignatureVerifierContext verifier = verifier(Algorithm.ES256);

        EudiPidTrustedSdJwtIssuer trustedIssuer = new EudiPidTrustedSdJwtIssuer(
                policy(PID_PROVIDER_ISSUER), new StubTrustListProvider(List.of(caCertificate), verifier));

        List<SignatureVerifierContext> verifiers = trustedIssuer.resolveIssuerVerifyingKeys(
                issuerSignedJwt(PID_PROVIDER_ISSUER, leafCertificate, caCertificate));

        assertEquals(1, verifiers.size());
        assertSame(verifier, verifiers.get(0));
    }

    @Test
    void shouldRejectPidCredentialFromUnexpectedIssuer() throws Exception {
        EudiPidTrustedSdJwtIssuer trustedIssuer = new EudiPidTrustedSdJwtIssuer(
                policy(PID_PROVIDER_ISSUER), new StubTrustListProvider(List.of(), verifier(Algorithm.ES256)));

        EudiPidTrustException error = assertThrows(
                EudiPidTrustException.class,
                () -> trustedIssuer.resolveIssuerVerifyingKeys(issuerSignedJwt("https://issuer.example")));

        assertEquals(
                "PID credential issuer does not match configured trusted issuer: https://issuer.example",
                error.getMessage());
    }

    private TrustPolicy policy(String issuer) {
        return new TrustPolicy().setType(TrustPolicy.EUDI_PID_TRUST_LIST).setIssuer(issuer);
    }

    private IssuerSignedJWT issuerSignedJwt(String issuer, X509Certificate... chain) throws Exception {
        JWSHeader header = new JWSHeader(org.keycloak.jose.jws.Algorithm.ES256, null, null);
        for (X509Certificate certificate : chain) {
            header.addX5c(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        }
        ObjectNode payload = JsonNodeFactory.instance.objectNode();
        payload.put("iss", issuer);
        return new IssuerSignedJWT(header, payload);
    }

    private SignatureVerifierContext verifier(String alg) {
        return new SignatureVerifierContext() {
            @Override
            public String getKid() {
                return null;
            }

            @Override
            public String getAlgorithm() {
                return alg;
            }

            @Override
            public boolean verify(byte[] data, byte[] signature) throws VerificationException {
                return true;
            }
        };
    }

    private static class StubTrustListProvider extends EudiPidTrustListProvider {

        private final List<X509Certificate> trustedCertificates;
        private final SignatureVerifierContext verifier;

        StubTrustListProvider(List<X509Certificate> trustedCertificates, SignatureVerifierContext verifier) {
            super(mock(KeycloakSession.class));
            this.trustedCertificates = trustedCertificates;
            this.verifier = verifier;
        }

        @Override
        public TrustListSnapshot resolve(TrustPolicy policy) {
            return new TrustListSnapshot(Instant.now().plusSeconds(3600), trustedCertificates);
        }

        @Override
        SignatureVerifierContext verifier(String alg, X509Certificate certificate) {
            assertEquals(Algorithm.ES256, alg);
            return verifier;
        }
    }
}
