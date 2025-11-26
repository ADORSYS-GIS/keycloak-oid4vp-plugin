package de.adorsys.gis.keycloak.protocol.oid4vc.tokenstatus.http;

import de.adorsys.gis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;

/**
 * Simple implementation of StatusListJwtFetcher for token status list validation.
 *
 * @author <a href="mailto:Forkim.Akwichek@adorsys.com">Forkim Akwichek</a>
 */
public class SimpleStatusListJwtFetcher implements StatusListJwtFetcher {

    /**
     * Accept header value for Status List JWT format.
     * Used when requesting Status List Tokens from status list servers.
     */
    public static final String STATUS_LIST_JWT_ACCEPT_HEADER = "application/statuslist+jwt";

    protected final KeycloakSession session;

    public SimpleStatusListJwtFetcher(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String fetchStatusListJwt(String uri) throws ReferencedTokenValidationException {
        try {
            return SimpleHttp.doGet(uri, session)
                    .header("Accept", STATUS_LIST_JWT_ACCEPT_HEADER)
                    .asString();
        } catch (Exception e) {
            throw new ReferencedTokenValidationException(
                    String.format("Error retrieving or parsing Status List JWT from URI: %s", uri), e
            );
        }
    }
}
