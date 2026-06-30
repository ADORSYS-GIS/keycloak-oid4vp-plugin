package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;

class EudiTrustListJwtVerifier {

    private static final String TRUST_LIST_TYP = "trustlist+jwt";
    private static final Set<String> SUPPORTED_SIGNATURE_ALGORITHMS = Set.of(
            Algorithm.ES256,
            Algorithm.ES384,
            Algorithm.ES512,
            Algorithm.RS256,
            Algorithm.RS384,
            Algorithm.RS512,
            Algorithm.PS256,
            Algorithm.PS384,
            Algorithm.PS512);

    private final KeycloakSession session;

    EudiTrustListJwtVerifier(KeycloakSession session) {
        this.session = session;
    }

    JsonNode verifyAndReadPayload(String trustListJwt, X509Certificate configuredSigningCertificate)
            throws EudiPidTrustException {
        JWSInput jws = parseTrustListJwt(trustListJwt);
        if (!TRUST_LIST_TYP.equals(jws.getHeader().getType())) {
            throw new EudiPidTrustException("EUDI trust list JWT has unsupported typ: "
                    + jws.getHeader().getType());
        }

        X509Certificate headerSigningCertificate = signingCertificateFromHeader(jws);
        if (!CertificateUtil.sha256Fingerprint(configuredSigningCertificate)
                .equals(CertificateUtil.sha256Fingerprint(headerSigningCertificate))) {
            throw new EudiPidTrustException(
                    "EUDI trust list signer does not match configured LoTE signing certificate");
        }

        verifySignature(jws, headerSigningCertificate);
        return readPayload(jws);
    }

    private JWSInput parseTrustListJwt(String trustListJwt) throws EudiPidTrustException {
        try {
            return new JWSInput(trustListJwt);
        } catch (JWSInputException e) {
            throw new EudiPidTrustException("Could not parse EUDI trust list JWT", e);
        }
    }

    private X509Certificate signingCertificateFromHeader(JWSInput jws) throws EudiPidTrustException {
        List<String> x5c = jws.getHeader().getX5c();
        if (x5c == null || x5c.isEmpty()) {
            throw new EudiPidTrustException("EUDI trust list JWT does not contain an x5c signer certificate");
        }
        try {
            return CertificateUtil.parseCertificate(x5c.get(0));
        } catch (Exception e) {
            throw new EudiPidTrustException("Could not parse EUDI trust list signer certificate", e);
        }
    }

    private void verifySignature(JWSInput jws, X509Certificate signingCertificate) throws EudiPidTrustException {
        try {
            SignatureVerifierContext verifier = verifier(jws.getHeader().getRawAlgorithm(), signingCertificate);
            byte[] data = jws.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8);
            if (!verifier.verify(data, jws.getSignature())) {
                throw new EudiPidTrustException("EUDI trust list JWT signature is invalid");
            }
        } catch (EudiPidTrustException e) {
            throw e;
        } catch (Exception e) {
            throw new EudiPidTrustException("Could not verify EUDI trust list JWT signature", e);
        }
    }

    private JsonNode readPayload(JWSInput jws) throws EudiPidTrustException {
        try {
            return JsonSerialization.mapper.readTree(jws.getContent());
        } catch (Exception e) {
            throw new EudiPidTrustException("Could not parse EUDI trust list JWT payload", e);
        }
    }

    SignatureVerifierContext verifier(String alg, X509Certificate certificate) throws EudiPidTrustException {
        if (!SUPPORTED_SIGNATURE_ALGORITHMS.contains(alg)) {
            throw new EudiPidTrustException("Unsupported signature algorithm: " + alg);
        }
        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, alg);
        if (signatureProvider == null) {
            throw new EudiPidTrustException("Unsupported signature algorithm: " + alg);
        }
        try {
            KeyWrapper keyWrapper = new KeyWrapper();
            keyWrapper.setPublicKey(certificate.getPublicKey());
            keyWrapper.setAlgorithm(alg);
            keyWrapper.setType(algorithmToKeyType(alg));
            keyWrapper.setUse(KeyUse.SIG);
            return signatureProvider.verifier(keyWrapper);
        } catch (Exception e) {
            throw new EudiPidTrustException("Could not create signature verifier for algorithm: " + alg, e);
        }
    }

    private static String algorithmToKeyType(String alg) throws EudiPidTrustException {
        if (Algorithm.ES256.equals(alg) || Algorithm.ES384.equals(alg) || Algorithm.ES512.equals(alg)) {
            return KeyType.EC;
        }
        if (Algorithm.RS256.equals(alg)
                || Algorithm.RS384.equals(alg)
                || Algorithm.RS512.equals(alg)
                || Algorithm.PS256.equals(alg)
                || Algorithm.PS384.equals(alg)
                || Algorithm.PS512.equals(alg)) {
            return KeyType.RSA;
        }
        throw new EudiPidTrustException("Unsupported signature algorithm: " + alg);
    }
}
