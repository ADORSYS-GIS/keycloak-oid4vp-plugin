package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.TrustPolicy;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.utils.StringUtil;

public class EudiPidTrustListProvider {

    public static final String PID_ISSUANCE_SERVICE_TYPE = "http://uri.etsi.org/19602/SvcType/PID/Issuance";
    public static final String PID_PROVIDERS_LOTE_TYPE = "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList";
    private static final int TRUST_LIST_FETCH_TIMEOUT_MILLIS = 10_000;

    private static final Cache<CacheKey, TrustListSnapshot> CACHE = Caffeine.newBuilder()
            .maximumSize(20)
            .expireAfterWrite(15, TimeUnit.MINUTES)
            .build();

    private final KeycloakSession session;
    private final EudiTrustListJwtVerifier jwtVerifier;
    private final EudiTrustListPayloadParser payloadParser = new EudiTrustListPayloadParser();

    public EudiPidTrustListProvider(KeycloakSession session) {
        this(session, new EudiTrustListJwtVerifier(session));
    }

    EudiPidTrustListProvider(KeycloakSession session, EudiTrustListJwtVerifier jwtVerifier) {
        this.session = session;
        this.jwtVerifier = jwtVerifier;
    }

    public TrustListSnapshot resolve(TrustPolicy policy) throws EudiPidTrustException {
        validatePolicy(policy);
        X509Certificate signingCertificate = parseConfiguredSigningCertificate(policy);
        String signingFingerprint = CertificateUtil.sha256Fingerprint(signingCertificate);
        String serviceType = serviceType(policy);
        CacheKey cacheKey = new CacheKey(realmId(), policy.getTrustListUrl(), signingFingerprint, serviceType);
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
                    .connectTimeoutMillis(TRUST_LIST_FETCH_TIMEOUT_MILLIS)
                    .connectionRequestTimeoutMillis(TRUST_LIST_FETCH_TIMEOUT_MILLIS)
                    .socketTimeOutMillis(TRUST_LIST_FETCH_TIMEOUT_MILLIS)
                    .asString();
        } catch (Exception e) {
            throw new EudiPidTrustException("Could not fetch EUDI PID trust list: " + url, e);
        }
    }

    private TrustListSnapshot verifyAndParse(
            String trustListJwt, X509Certificate configuredSigningCertificate, String serviceType)
            throws EudiPidTrustException {
        JsonNode payload = jwtVerifier.verifyAndReadPayload(trustListJwt, configuredSigningCertificate);
        EudiTrustListPayloadParser.TrustListData trustListData = payloadParser.parse(payload, serviceType);
        if (trustListData.nextUpdate().isBefore(Instant.ofEpochMilli(Time.currentTimeMillis()))) {
            throw new EudiPidTrustException("EUDI PID trust list is expired");
        }

        List<X509Certificate> trustedCertificates = trustListData.providers().stream()
                .flatMap(provider -> provider.trustedCertificates().stream())
                .toList();
        if (trustedCertificates.isEmpty()) {
            throw new EudiPidTrustException(
                    "EUDI PID trust list contains no certificates for service type: " + serviceType);
        }
        return new TrustListSnapshot(trustListData.nextUpdate(), trustedCertificates, trustListData.providers());
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

    private String realmId() {
        if (session == null || session.getContext() == null) {
            return null;
        }
        RealmModel realm = session.getContext().getRealm();
        return realm == null ? null : realm.getId();
    }

    SignatureVerifierContext verifier(String alg, X509Certificate certificate) throws EudiPidTrustException {
        return jwtVerifier.verifier(alg, certificate);
    }

    private record CacheKey(
            String realmId, String trustListUrl, String signingCertificateFingerprint, String serviceType) {}

    public record TrustListSnapshot(
            Instant nextUpdate, List<X509Certificate> trustedIssuerCertificates, List<TrustedPidProvider> providers) {
        boolean isExpired() {
            return nextUpdate.isBefore(Instant.ofEpochMilli(Time.currentTimeMillis()));
        }

        public TrustListSnapshot {
            trustedIssuerCertificates = List.copyOf(Objects.requireNonNull(trustedIssuerCertificates));
            providers = List.copyOf(Objects.requireNonNull(providers));
        }

        public TrustedPidProvider resolveIssuer(String issuer) throws EudiPidTrustException {
            if (StringUtil.isBlank(issuer)) {
                throw new EudiPidTrustException("EUDI PID trust-list issuer must be configured");
            }

            List<TrustedPidProvider> matches = providers.stream()
                    .filter(provider -> provider.identifiers().contains(issuer))
                    .toList();
            if (matches.isEmpty()) {
                throw new EudiPidTrustException(
                        "Configured issuer does not identify a PID Provider in the EUDI trust list: " + issuer);
            }
            if (matches.size() != 1) {
                throw new EudiPidTrustException(
                        "Configured issuer identifies multiple PID Providers in the EUDI trust list: " + issuer);
            }
            return matches.getFirst();
        }
    }

    public record TrustedPidProvider(
            String providerName, List<String> identifiers, List<TrustedPidIssuanceService> issuanceServices) {

        public TrustedPidProvider {
            providerName = Objects.requireNonNull(providerName);
            identifiers = List.copyOf(Objects.requireNonNull(identifiers));
            issuanceServices = List.copyOf(Objects.requireNonNull(issuanceServices));
        }

        public List<X509Certificate> trustedCertificates() {
            List<X509Certificate> certificates = new ArrayList<>();
            issuanceServices.forEach(service -> certificates.addAll(service.certificates()));
            return List.copyOf(certificates);
        }
    }

    public record TrustedPidIssuanceService(String serviceName, List<X509Certificate> certificates) {
        public TrustedPidIssuanceService {
            serviceName = Objects.requireNonNull(serviceName);
            certificates = List.copyOf(Objects.requireNonNull(certificates));
        }
    }
}
