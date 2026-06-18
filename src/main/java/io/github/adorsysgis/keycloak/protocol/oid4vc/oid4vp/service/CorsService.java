package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service;

import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.util.Optional;
import java.util.Set;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.cors.Cors;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Service class for handling CORS (Cross-Origin Resource Sharing) policies.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class CorsService {

    private static final String HTTP_METHOD_OPTIONS = "OPTIONS";
    private static final String HTTP_METHOD_POST = "POST";
    private static final String WEB_ORIGINS_PLUS = "+";
    private static final String WEB_ORIGINS_WILDCARD = "*";
    private static final String ACCESS_CONTROL_ALLOW_ORIGIN = "Access-Control-Allow-Origin";
    private static final String ACCESS_CONTROL_ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials";
    private static final String VARY = "Vary";
    private static final String ORIGIN = "Origin";

    /**
     * Creates a CORS policy that allows all origins.
     * This is used for endpoints that need to be accessible from any origin.
     *
     * @return CORS builder configured for open access
     */
    public static Cors open() {
        return Cors.builder().allowAllOrigins().auth();
    }

    /**
     * Creates a CORS policy for preflight requests.
     * This allows OPTIONS and POST methods from any origin.
     *
     * @return CORS builder configured for preflight requests
     */
    public static Cors openPreflight() {
        return Cors.builder()
                .preflight()
                .allowedMethods(HTTP_METHOD_OPTIONS, HTTP_METHOD_POST)
                .auth();
    }

    /**
     * Creates a CORS policy based on the client's configured web origins.
     * This restricts access to only the origins configured for the client
     * associated with the authentication session.
     *
     * @param session the current Keycloak session
     * @param authSession the authentication session containing client information
     * @param response response builder to decorate
     * @return response decorated with CORS headers when the request origin is allowed
     */
    public static Response addForWebOrigins(
            KeycloakSession session, AuthenticationSessionModel authSession, Response.ResponseBuilder response) {
        ClientModel client = Optional.ofNullable(authSession)
                .map(AuthenticationSessionModel::getClient)
                .orElse(null);
        String origin = Optional.ofNullable(session)
                .map(KeycloakSession::getContext)
                .map(context -> context.getRequestHeaders())
                .map(headers -> headers.getHeaderString(ORIGIN))
                .orElse(null);

        if (isAllowedOrigin(client, origin)) {
            response.header(ACCESS_CONTROL_ALLOW_ORIGIN, origin)
                    .header(ACCESS_CONTROL_ALLOW_CREDENTIALS, "true")
                    .header(VARY, ORIGIN);
        }

        return response.build();
    }

    private static boolean isAllowedOrigin(ClientModel client, String origin) {
        if (client == null || origin == null || origin.isBlank()) {
            return false;
        }

        Set<String> webOrigins = client.getWebOrigins();
        if (webOrigins.contains(WEB_ORIGINS_WILDCARD) || webOrigins.contains(origin)) {
            return true;
        }

        return webOrigins.contains(WEB_ORIGINS_PLUS) && isRedirectOrigin(client, origin);
    }

    private static boolean isRedirectOrigin(ClientModel client, String origin) {
        return client.getRedirectUris().stream()
                .map(CorsService::originFromUri)
                .flatMap(Optional::stream)
                .anyMatch(origin::equals);
    }

    private static Optional<String> originFromUri(String uri) {
        try {
            URI parsed = URI.create(uri.replace("*", ""));
            if (parsed.getScheme() == null || parsed.getHost() == null) {
                return Optional.empty();
            }

            StringBuilder origin =
                    new StringBuilder().append(parsed.getScheme()).append("://").append(parsed.getHost());
            if (parsed.getPort() >= 0) {
                origin.append(":").append(parsed.getPort());
            }

            return Optional.of(origin.toString());
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
