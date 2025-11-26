package de.adorsys.gis.keycloak.protocol.oid4vc.tokenstatus.http;

import de.adorsys.gis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;

/**
 * Functional interface for fetching Status List JWT tokens.
 *
 * @author <a href="mailto:Forkim.Akwichek@adorsys.com">Forkim Akwichek</a>
 */
public interface StatusListJwtFetcher {

    /**
     * Performs an HTTP GET at the URI and returns the response as a JWT string.
     * This method is specifically for fetching Status List JWT tokens with the
     * appropriate Accept header (application/statuslist+jwt).
     *
     * @param uri The URI to fetch the Status List JWT from
     * @return The Status List JWT as a string
     * @throws ReferencedTokenValidationException if any issue arises or HTTP status not OK (200)
     */
    String fetchStatusListJwt(String uri) throws ReferencedTokenValidationException;
}
