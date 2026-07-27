package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.metadata;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCWellKnownProviderFactory;
import org.keycloak.wellknown.WellKnownProvider;

/**
 * Registers {@link OIDCAsMetadataProvider} under the {@code openid-configuration} alias with a higher
 * priority than the default {@link OIDCWellKnownProviderFactory}, so the enriched Authorization Server
 * Metadata (including {@code authorization_challenge_endpoint}) wins.
 */
public class OIDCAsMetadataProviderFactory extends OIDCWellKnownProviderFactory {

    private boolean includeClientScopes = true;

    @Override
    public void init(Config.Scope config) {
        super.init(config);
        this.includeClientScopes = config.getBoolean("include-client-scopes", true);
    }

    @Override
    public WellKnownProvider create(KeycloakSession session) {
        return new OIDCAsMetadataProvider(session, getOpenidConfigOverride(), includeClientScopes);
    }

    @Override
    public int getPriority() {
        return super.getPriority() + 1000;
    }
}
