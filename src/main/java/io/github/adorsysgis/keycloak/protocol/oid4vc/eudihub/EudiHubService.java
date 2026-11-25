package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonValue;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.VerifierDiscoveryService;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;

/**
 * Client for the Organization API of the German EUDI Hub.
 *
 * <p>Every call takes the portal access token of the user and uses it for that request only. The
 * token is never stored or logged.
 */
public class EudiHubService {

    private static final Logger logger = Logger.getLogger(EudiHubService.class);

    /** Organization API of the production EUDI Hub. */
    static final String DEFAULT_BASE_URL = "https://api.eudi-hub.gov.de/org-management";

    private static final String BEARER_PREFIX = "bearer ";
    private static final int MAX_DETAIL_LENGTH = 300;

    /** Upper bound on the certificates downloaded while looking for the one of the signing key. */
    private static final int MAX_RECOVERY_DOWNLOADS = 10;

    private final KeycloakSession session;
    private final String baseUrl;

    public EudiHubService(KeycloakSession session, String baseUrl) {
        this(session, baseUrl, true);
    }

    EudiHubService(KeycloakSession session, String baseUrl, boolean requireHttps) {
        this.session = session;
        this.baseUrl = normalizeBaseUrl(baseUrl, requireHttps);
    }

    /**
     * Returns the organizations the token's user is assigned to, together with the environment and
     * support URIs the certificate request needs.
     */
    public List<Organization> listOrganizations(String token) throws EudiHubException {
        String normalizedToken = normalizeToken(token);
        MeResponse me = getJson(normalizedToken, "/v1/me", MeResponse.class);
        if (me.organizations() == null) {
            throw new EudiHubException(502, "The EUDI Hub answered without a list of organizations.");
        }

        List<Organization> result = new ArrayList<>();
        for (OrganizationSummary entry : me.organizations()) {
            if (entry == null || entry.id() == null || entry.name() == null) {
                continue;
            }

            List<String> supportUris = List.of();
            Environment environment = Environment.SANDBOX;
            try {
                OrganizationDetails details = getDetails(normalizedToken, entry.id());
                supportUris = supportUris(details);
                environment = Environment.from(details.environments());
            } catch (EudiHubException e) {
                if (e.getStatus() == 401 || e.getStatus() == 403) {
                    throw e;
                }
                // An organization without details is still selectable. The
                // certificate request will fail later if the support URI is
                // required, but one broken entry must not hide the others.
                logger.warnf("Could not load details of EUDI Hub organization %s: %s", entry.id(), e.getMessage());
            } catch (IllegalArgumentException e) {
                logger.warnf("Ignoring EUDI Hub organization with an invalid ID: %s", entry.id());
            }

            result.add(new Organization(entry.id(), entry.name(), environment, supportUris));
        }
        return result;
    }

    /**
     * Requests an access certificate from the EUDI Hub for the realm's OpenID4VP signing key.
     *
     * <p>The CSR is created for the public key of the signing key and signed by its private key, so
     * the private key never leaves Keycloak. The issued certificate is returned as base64 DER, the
     * form the OpenID4VP authenticator expects.
     */
    public AccessCertificateResult requestAccessCertificate(
            String token, String organizationId, String environment, String name) throws EudiHubException {
        String normalizedToken = normalizeToken(token);
        String safeId = normalizeOrganizationId(organizationId);
        String normalizedEnvironment = normalizeEnvironment(environment);

        OrganizationDetails details = getDetails(normalizedToken, safeId);
        List<String> supportUris = supportUris(details);
        if (supportUris.isEmpty()) {
            throw new EudiHubException(
                    400, "The EUDI Hub organization has no support URI to request a certificate for.");
        }

        String certificateName = name == null || name.isBlank() ? "Access Certificate" : name.trim();
        KeyWrapper signingKey = getSigningKey();
        String csr = createCertificateSigningRequest(signingKey, certificateName);

        AccessCertificate created;
        try {
            created = postJson(
                    normalizedToken,
                    "/v1/organizations/" + safeId + "/access-certificates",
                    new AccessCertificateRequest(certificateName, csr, normalizedEnvironment, supportUris.get(0)),
                    AccessCertificate.class);
        } catch (EudiHubException e) {
            if (e.getStatus() == 401 || e.getStatus() == 403) {
                throw e;
            }
            // The EUDI Hub issues one certificate per key. When the current
            // OpenID4VP signing key already has one, retrieve that certificate
            // instead of failing the request.
            ExistingCertificate existing =
                    findCertificateForSigningKey(normalizedToken, safeId, normalizedEnvironment, signingKey);
            if (existing != null) {
                if (existing.der() == null) {
                    throw new EudiHubException(
                            409,
                            notValidCertificateMessage(existing.certificate().status()));
                }
                logger.infof(
                        "Reusing the access certificate the EUDI Hub already issued for the OpenID4VP signing key (%s)",
                        signingKey.getKid());
                return new AccessCertificateResult(
                        Base64.getEncoder().encodeToString(existing.der()),
                        existing.certificate().name());
            }
            throw e;
        }

        if (created == null || created.id() == null || created.id().isBlank()) {
            throw new EudiHubException(502, "The EUDI Hub answered without an access certificate ID.");
        }

        byte[] certificate = download(
                normalizedToken,
                "/v1/organizations/" + safeId + "/access-certificates/" + encodePathSegment(created.id())
                        + "/download");
        return new AccessCertificateResult(
                Base64.getEncoder().encodeToString(certificate),
                created.name() == null || created.name().isBlank() ? certificateName : created.name());
    }

    private static String notValidCertificateMessage(String status) {
        String normalized = status == null ? "" : status.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "revoked" ->
                "The EUDI Hub already has a revoked certificate for the current OpenID4VP signing key; "
                        + "rotate the signing key and request again.";
            case "expired" ->
                "The EUDI Hub already has an expired certificate for the current OpenID4VP signing key; "
                        + "rotate the signing key and request again.";
            default ->
                "The EUDI Hub already has a certificate for the current OpenID4VP signing key that is not valid"
                        + (normalized.isEmpty() ? "" : " (status: " + normalized + ")")
                        + "; rotate the signing key and request again.";
        };
    }

    /**
     * Finds the certificate the EUDI Hub already issued for the given signing key. This is a
     * best-effort lookup used when the Hub refuses a second certificate for the same key: it
     * returns {@code null} when no listed certificate holds the key's public key. A certificate
     * that holds the key but is revoked or expired is returned without DER bytes so the caller can
     * explain why a new one cannot be issued.
     */
    private ExistingCertificate findCertificateForSigningKey(
            String token, String organizationId, String environment, KeyWrapper signingKey) {
        if (signingKey == null || signingKey.getPublicKey() == null) {
            return null;
        }
        byte[] signingPublicKey = signingKey.getPublicKey().getEncoded();

        List<AccessCertificate> certificates;
        try {
            certificates = listAccessCertificates(token, organizationId, environment);
        } catch (EudiHubException e) {
            logger.warnf(
                    "Could not list the access certificates of EUDI Hub organization %s: %s",
                    organizationId, e.getMessage());
            return null;
        }

        AccessCertificate bestValid = null;
        byte[] bestValidDer = null;
        AccessCertificate bestInvalid = null;
        int downloads = 0;
        for (AccessCertificate candidate : certificates) {
            if (candidate == null || candidate.id() == null || candidate.id().isBlank()) {
                continue;
            }
            if (downloads++ >= MAX_RECOVERY_DOWNLOADS) {
                break;
            }

            byte[] der;
            try {
                der = download(
                        token,
                        "/v1/organizations/" + organizationId + "/access-certificates/"
                                + encodePathSegment(candidate.id()) + "/download");
            } catch (EudiHubException e) {
                logger.warnf(
                        "Could not download EUDI Hub access certificate %s while looking for the signing key's certificate: %s",
                        candidate.id(), e.getMessage());
                continue;
            }
            if (!holdsPublicKey(der, signingPublicKey)) {
                continue;
            }

            boolean valid = candidate.status() == null || "valid".equalsIgnoreCase(candidate.status());
            if (valid) {
                if (bestValid == null || isNewer(candidate, bestValid)) {
                    bestValid = candidate;
                    bestValidDer = der;
                }
            } else if (bestInvalid == null || isNewer(candidate, bestInvalid)) {
                bestInvalid = candidate;
            }
        }

        if (bestValid != null) {
            return new ExistingCertificate(bestValid, bestValidDer);
        }
        return bestInvalid == null ? null : new ExistingCertificate(bestInvalid, null);
    }

    private List<AccessCertificate> listAccessCertificates(String token, String organizationId, String environment)
            throws EudiHubException {
        AccessCertificatePage page = getJson(
                token,
                "/v1/organizations/" + organizationId + "/access-certificates?environment="
                        + encodePathSegment(environment) + "&limit=100",
                AccessCertificatePage.class);
        return page.items() == null ? List.of() : page.items();
    }

    private static boolean holdsPublicKey(byte[] der, byte[] publicKey) {
        try {
            X509Certificate certificate = (X509Certificate)
                    CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
            return Arrays.equals(certificate.getPublicKey().getEncoded(), publicKey);
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean isNewer(AccessCertificate candidate, AccessCertificate current) {
        String candidateExpiry = candidate.expirationDate();
        String currentExpiry = current.expirationDate();
        if (candidateExpiry == null) {
            return false;
        }
        return currentExpiry == null || candidateExpiry.compareTo(currentExpiry) > 0;
    }

    private KeyWrapper getSigningKey() throws EudiHubException {
        try {
            return VerifierDiscoveryService.getSigningKey(session, false);
        } catch (IllegalArgumentException | IllegalStateException e) {
            throw new EudiHubException(409, e.getMessage());
        }
    }

    private static String createCertificateSigningRequest(KeyWrapper signingKey, String name) throws EudiHubException {
        try {
            return EudiHubCsr.create(signingKey, name);
        } catch (IllegalArgumentException e) {
            throw new EudiHubException(409, e.getMessage());
        } catch (Exception e) {
            throw new EudiHubException(500, "Could not create the certificate signing request.");
        }
    }

    private OrganizationDetails getDetails(String token, String organizationId) throws EudiHubException {
        String safeId = normalizeOrganizationId(organizationId);
        return getJson(token, "/v1/organizations/" + safeId, OrganizationDetails.class);
    }

    private static List<String> supportUris(OrganizationDetails details) {
        if (details.contactInformation() == null || details.contactInformation().supportUris() == null) {
            return List.of();
        }

        return details.contactInformation().supportUris().stream()
                .filter(uri -> uri != null && !uri.isBlank())
                .toList();
    }

    private <T> T getJson(String token, String path, Class<T> type) throws EudiHubException {
        try (SimpleHttpResponse response = SimpleHttp.create(session)
                .doGet(baseUrl + path)
                .header("Accept", "application/json")
                .auth(token)
                .asResponse()) {
            return readJson(response, type);
        } catch (EudiHubException e) {
            throw e;
        } catch (IOException e) {
            throw new EudiHubException(502, "The EUDI Hub could not be reached or answered with invalid JSON.");
        }
    }

    private <T> T postJson(String token, String path, Object body, Class<T> type) throws EudiHubException {
        try (SimpleHttpResponse response = SimpleHttp.create(session)
                .doPost(baseUrl + path)
                .header("Accept", "application/json")
                .auth(token)
                .json(body)
                .asResponse()) {
            return readJson(response, type);
        } catch (EudiHubException e) {
            throw e;
        } catch (IOException e) {
            throw new EudiHubException(502, "The EUDI Hub could not be reached or answered with invalid JSON.");
        }
    }

    private static <T> T readJson(SimpleHttpResponse response, Class<T> type) throws IOException, EudiHubException {
        int status = response.getStatus();
        String payload = response.asString();
        if (status < 200 || status >= 300) {
            int mappedStatus = status == 401 || status == 403 ? status : 502;
            throw new EudiHubException(mappedStatus, problemDetail(payload));
        }
        if (payload == null || payload.isBlank()) {
            throw new EudiHubException(502, "The EUDI Hub answered with an empty body.");
        }

        return JsonSerialization.mapper.readValue(payload, type);
    }

    /** Downloads the issued certificate. The EUDI Hub answers with the DER bytes. */
    private byte[] download(String token, String path) throws EudiHubException {
        CloseableHttpClient client =
                session.getProvider(HttpClientProvider.class).getHttpClient();
        HttpGet request = new HttpGet(baseUrl + path);
        request.setHeader("Accept", "application/pkix-cert, application/octet-stream");
        request.setHeader("Authorization", "Bearer " + token);

        try (CloseableHttpResponse response = client.execute(request)) {
            int status = response.getStatusLine().getStatusCode();
            HttpEntity entity = response.getEntity();
            byte[] payload = entity == null ? new byte[0] : EntityUtils.toByteArray(entity);
            if (status < 200 || status >= 300) {
                int mappedStatus = status == 401 || status == 403 ? status : 502;
                throw new EudiHubException(mappedStatus, problemDetail(new String(payload, StandardCharsets.UTF_8)));
            }
            if (payload.length == 0) {
                throw new EudiHubException(502, "The EUDI Hub answered with an empty certificate.");
            }
            return payload;
        } catch (EudiHubException e) {
            throw e;
        } catch (IOException e) {
            throw new EudiHubException(
                    502, "The EUDI Hub could not be reached or answered with an invalid certificate.");
        }
    }

    private static String encodePathSegment(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    /**
     * Extracts only the problem detail or title from an RFC 9457 answer. The raw payload is never
     * returned because it could contain request data.
     */
    private static String problemDetail(String payload) {
        if (payload != null && !payload.isBlank()) {
            try {
                ProblemDetail problem = JsonSerialization.mapper.readValue(payload, ProblemDetail.class);
                if (problem.detail() != null && !problem.detail().isBlank()) {
                    return truncate(problem.detail());
                }
                if (problem.title() != null && !problem.title().isBlank()) {
                    return truncate(problem.title());
                }
            } catch (IOException ignored) {
                // Fall through to the generic message.
            }
        }
        return "The EUDI Hub rejected the request.";
    }

    static String normalizeToken(String token) {
        if (token == null) {
            throw new IllegalArgumentException("The portal access token is required.");
        }

        String normalized = token.trim();
        if (normalized.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            normalized = normalized.substring(BEARER_PREFIX.length()).trim();
        }
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("The portal access token is required.");
        }
        return normalized;
    }

    static String normalizeOrganizationId(String organizationId) {
        if (organizationId == null) {
            throw new IllegalArgumentException("The organization ID is required.");
        }

        try {
            return UUID.fromString(organizationId.trim()).toString();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("The organization ID is not a UUID.");
        }
    }

    static String normalizeEnvironment(String environment) {
        if (environment == null) {
            throw new IllegalArgumentException("The EUDI Hub environment is required.");
        }

        String normalized = environment.trim().toLowerCase(Locale.ROOT);
        if (!Environment.SANDBOX.value().equals(normalized)
                && !Environment.LIVE.value().equals(normalized)) {
            throw new IllegalArgumentException("The EUDI Hub environment must be 'sandbox' or 'live'.");
        }
        return normalized;
    }

    static String normalizeBaseUrl(String baseUrl) {
        return normalizeBaseUrl(baseUrl, true);
    }

    private static String normalizeBaseUrl(String baseUrl, boolean requireHttps) {
        String normalized = baseUrl == null || baseUrl.isBlank() ? DEFAULT_BASE_URL : baseUrl.trim();
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }

        URI uri = URI.create(normalized);
        if (requireHttps && !"https".equalsIgnoreCase(uri.getScheme())) {
            throw new IllegalArgumentException("The EUDI Hub API URL must use HTTPS.");
        }
        return normalized;
    }

    private static String truncate(String value) {
        return value.length() <= MAX_DETAIL_LENGTH ? value : value.substring(0, MAX_DETAIL_LENGTH) + "...";
    }

    /** An organization with the environment and support URIs loaded from its EUDI Hub details. */
    public record Organization(String id, String name, Environment environment, List<String> supportUris) {}

    /** The EUDI Hub environment an organization currently belongs to. */
    public enum Environment {
        SANDBOX("sandbox"),
        LIVE("live");

        private final String value;

        Environment(String value) {
            this.value = value;
        }

        @JsonValue
        public String value() {
            return value;
        }

        static Environment from(List<String> environments) {
            if (environments == null) {
                return SANDBOX;
            }
            return environments.stream().anyMatch("live"::equalsIgnoreCase) ? LIVE : SANDBOX;
        }
    }

    /** The certificate returned to the admin UI and the name the EUDI Hub knows it by. */
    public record AccessCertificateResult(String certificate, String name) {}

    /** A listed certificate that holds the signing key, with its DER bytes only when it is valid. */
    private record ExistingCertificate(AccessCertificate certificate, byte[] der) {}

    /** Response of {@code GET /v1/me}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    private record MeResponse(List<OrganizationSummary> organizations) {}

    /** Organization entry of {@code GET /v1/me}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    private record OrganizationSummary(String id, String name) {}

    /** Response of {@code GET /v1/organizations/{id}}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    private record OrganizationDetails(ContactInformation contactInformation, List<String> environments) {}

    /** Contact information of an organization. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    private record ContactInformation(List<String> supportUris) {}

    /** Request body of {@code POST /v1/organizations/{id}/access-certificates}. */
    private record AccessCertificateRequest(String name, String csr, String environment, String supportUri) {}

    /** Response of {@code POST /v1/organizations/{id}/access-certificates}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    private record AccessCertificate(
            String id, String name, String status, String environment, String expirationDate) {}

    /** First page of {@code GET /v1/organizations/{id}/access-certificates}. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    private record AccessCertificatePage(List<AccessCertificate> items) {}

    /** RFC 9457 problem detail returned by the EUDI Hub. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    private record ProblemDetail(String detail, String title) {}

    /** A request to the EUDI Hub that failed. The message never contains the token. */
    public static class EudiHubException extends Exception {

        private final int status;

        public EudiHubException(int status, String message) {
            super(message);
            this.status = status;
        }

        public int getStatus() {
            return status;
        }
    }
}
