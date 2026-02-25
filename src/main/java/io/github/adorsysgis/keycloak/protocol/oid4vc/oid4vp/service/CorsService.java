package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service;

import java.util.Optional;
import org.keycloak.models.ClientModel;
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
     * @param authSession the authentication session containing client information
     * @return CORS builder configured for client-specific origins
     */
    public static Cors forWebOrigins(AuthenticationSessionModel authSession) {
        String[] clientWebOrigins = Optional.ofNullable(authSession.getClient())
                .map(ClientModel::getWebOrigins)
                .map(s -> s.toArray(String[]::new))
                .orElseGet(() -> new String[0]);

        return Cors.builder().allowedOrigins(clientWebOrigins).auth();
    }
}
