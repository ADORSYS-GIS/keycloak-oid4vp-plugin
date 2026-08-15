package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc;

import jakarta.ws.rs.Path;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCLoginProtocolService;

/**
 * {@link OIDCLoginProtocolService} whose {@code auth} sub-resource is backed by the
 * {@link GatedOIDCAuthorizationEndpoint}, so that OpenID4VP presentation can replace the
 * username/password login for "presentation during issuance" requests. All other OIDC endpoints
 * (token, certs, userinfo, ...) are untouched.
 */
public class GatedOIDCLoginProtocolService extends OIDCLoginProtocolService {

    private final KeycloakSession session;
    private final EventBuilder event;

    public GatedOIDCLoginProtocolService(KeycloakSession session, EventBuilder event) {
        super(session, event);
        this.session = session;
        this.event = event;
    }

    @Override
    @Path("auth")
    public Object auth() {
        return new GatedOIDCAuthorizationEndpoint(session, event);
    }
}
