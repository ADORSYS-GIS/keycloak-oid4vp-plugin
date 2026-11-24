package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonValue;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.jboss.logging.Logger;
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
        } catch (EudiHubException e) {
            throw e;
        } catch (IOException e) {
            throw new EudiHubException(502, "The EUDI Hub could not be reached or answered with invalid JSON.");
        }
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
