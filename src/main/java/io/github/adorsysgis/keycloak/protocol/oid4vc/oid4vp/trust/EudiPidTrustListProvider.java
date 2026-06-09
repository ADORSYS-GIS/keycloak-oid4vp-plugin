package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.TrustPolicy;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.common.util.Time;
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
import org.keycloak.utils.StringUtil;

public class EudiPidTrustListProvider {

    public static final String PID_ISSUANCE_SERVICE_TYPE = "http://uri.etsi.org/19602/SvcType/PID/Issuance";
    private static final String TRUST_LIST_TYP = "trustlist+jwt";

    private static final Cache<CacheKey, TrustListSnapshot> CACHE = Caffeine.newBuilder()
            .maximumSize(20)
            .expireAfterWrite(15, TimeUnit.MINUTES)
            .build();

    private final KeycloakSession session;

    public EudiPidTrustListProvider(KeycloakSession session) {
        this.session = session;
    }

    public TrustListSnapshot resolve(TrustPolicy policy) throws EudiPidTrustException {
        validatePolicy(policy);
        X509Certificate signingCertificate = parseConfiguredSigningCertificate(policy);
        String signingFingerprint = CertificateUtil.sha256Fingerprint(signingCertificate);
        String serviceType = serviceType(policy);
        CacheKey cacheKey = new CacheKey(policy.getTrustListUrl(), signingFingerprint, serviceType);
        TrustListSnapshot cached = CACHE.getIfPresent(cacheKey);
        if (cached != null && !cached.isExpired()) {
            return cached;
        }

        String trustListJwt = fetchTrustList(policy.getTrustListUrl());
        TrustListSnapshot snapshot = verifyAndParse(trustListJwt, signingCertificate, serviceType);
        CACHE.put(cacheKey, snapshot);
        return snapshot;
    }

    protected String fetchTrustList(String url) throws EudiPidTrustException {
        try {
            return SimpleHttp.doGet(url, session)
                    .header("Accept", "application/trustlist+jwt")
                    .asString();
        } catch (Exception e) {
            throw new EudiPidTrustException("Could not fetch EUDI PID trust list: " + url, e);
        }
    }

    private TrustListSnapshot verifyAndParse(
            String trustListJwt, X509Certificate configuredSigningCertificate, String serviceType)
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
        JsonNode payload = readPayload(jws);
        Instant nextUpdate = readNextUpdate(payload);
        if (nextUpdate.isBefore(Instant.ofEpochMilli(Time.currentTimeMillis()))) {
            throw new EudiPidTrustException("EUDI PID trust list is expired");
        }

        List<X509Certificate> serviceCertificates = extractServiceCertificates(payload, serviceType);
        if (serviceCertificates.isEmpty()) {
            throw new EudiPidTrustException("EUDI PID trust list contains no PID issuance certificates");
        }
        return new TrustListSnapshot(nextUpdate, serviceCertificates);
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

    private Instant readNextUpdate(JsonNode payload) throws EudiPidTrustException {
        JsonNode nextUpdate = payload.at("/LoTE/ListAndSchemeInformation/NextUpdate");
        if (!nextUpdate.isTextual()) {
            throw new EudiPidTrustException("EUDI trust list is missing LoTE.ListAndSchemeInformation.NextUpdate");
        }
        try {
            return Instant.parse(nextUpdate.asText());
        } catch (DateTimeParseException e) {
            throw new EudiPidTrustException("EUDI trust list NextUpdate is not an ISO-8601 instant", e);
        }
    }

    private List<X509Certificate> extractServiceCertificates(JsonNode payload, String serviceType)
            throws EudiPidTrustException {
        List<X509Certificate> certificates = new ArrayList<>();
        JsonNode entities = payload.at("/LoTE/TrustedEntitiesList");
        if (!entities.isArray()) {
            throw new EudiPidTrustException("EUDI trust list is missing LoTE.TrustedEntitiesList");
        }

        for (JsonNode entity : entities) {
            JsonNode services = entity.at("/TrustedEntityServices");
            if (!services.isArray()) {
                continue;
            }
            for (JsonNode service : services) {
                JsonNode serviceInfo = service.at("/ServiceInformation");
                if (!serviceType.equals(
                        serviceInfo.path("ServiceTypeIdentifier").asText())) {
                    continue;
                }
                JsonNode x509Certificates = serviceInfo.at("/ServiceDigitalIdentity/X509Certificates");
                if (!x509Certificates.isArray()) {
                    continue;
                }
                for (JsonNode certificateNode : x509Certificates) {
                    JsonNode value = certificateNode.path("val");
                    if (value.isTextual()) {
                        certificates.add(parseTrustListCertificate(value.asText()));
                    }
                }
            }
        }
        return certificates;
    }

    private X509Certificate parseTrustListCertificate(String value) throws EudiPidTrustException {
        try {
            return CertificateUtil.parseCertificate(value);
        } catch (Exception e) {
            throw new EudiPidTrustException("Could not parse EUDI trust-list service certificate", e);
        }
    }

    private X509Certificate parseConfiguredSigningCertificate(TrustPolicy policy) throws EudiPidTrustException {
        try {
            return CertificateUtil.parseCertificate(policy.getTrustListSigningCertificate());
        } catch (Exception e) {
            throw new EudiPidTrustException("Could not parse configured EUDI trust-list signing certificate", e);
        }
    }

    private void validatePolicy(TrustPolicy policy) throws EudiPidTrustException {
        if (policy == null || !TrustPolicy.EUDI_PID_TRUST_LIST.equals(policy.getType())) {
            throw new EudiPidTrustException("Trust policy is not an EUDI PID trust-list policy");
        }
        if (StringUtil.isBlank(policy.getTrustListUrl())
                || !policy.getTrustListUrl().startsWith("https://")) {
            throw new EudiPidTrustException("EUDI PID trust-list URL must be configured and use HTTPS");
        }
        if (StringUtil.isBlank(policy.getTrustListSigningCertificate())) {
            throw new EudiPidTrustException("EUDI PID trust-list signing certificate must be configured");
        }
    }

    private String serviceType(TrustPolicy policy) {
        return StringUtil.isBlank(policy.getServiceType()) ? PID_ISSUANCE_SERVICE_TYPE : policy.getServiceType();
    }

    SignatureVerifierContext verifier(String alg, X509Certificate certificate) throws EudiPidTrustException {
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

    private record CacheKey(String trustListUrl, String signingCertificateFingerprint, String serviceType) {}

    public record TrustListSnapshot(Instant nextUpdate, List<X509Certificate> trustedIssuerCertificates) {
        boolean isExpired() {
            return nextUpdate.isBefore(Instant.ofEpochMilli(Time.currentTimeMillis()));
        }

        public TrustListSnapshot {
            trustedIssuerCertificates = List.copyOf(Objects.requireNonNull(trustedIssuerCertificates));
        }
    }
}
