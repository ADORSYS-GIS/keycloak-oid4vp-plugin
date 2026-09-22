package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;

/**
 * Hidden identity provider backing OpenID4VP user import.
 *
 * <p>Verification and login stay owned by the plugin's {@code oid4vp-authenticator} and
 * {@code /oid4vp-auth} endpoints. This provider only hosts the import configuration, the
 * attribute mappers, and the federated identity links, so imported users behave like any other
 * brokered users.
 */
public class OID4VPImportIdentityProvider extends AbstractIdentityProvider<OID4VPImportIdentityProviderConfig> {

    private static final Logger logger = Logger.getLogger(OID4VPImportIdentityProvider.class);

    /**
     * Context-data key exposing the verified credential claims to import mappers. Intentionally the
     * same wire value as upstream Keycloak's {@code OID4VPIdentityProvider.CREDENTIAL_CLAIMS} so
     * ported mappers read claims without adaptation.
     */
    public static final String CREDENTIAL_CLAIMS = "OID4VP_CREDENTIAL_CLAIMS";

    public OID4VPImportIdentityProvider(KeycloakSession session, OID4VPImportIdentityProviderConfig config) {
        super(session, config);
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        logger.warnf(
                "Direct login through the hidden import provider '%s' is not supported",
                getConfig().getAlias());
        throw new IdentityBrokerException("Direct login through the OpenID4VP Plugin Import provider is not supported."
                + " Authenticate through the OpenID4VP login page instead.");
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        logger.warnf(
                "Direct callback through the hidden import provider '%s' is not supported",
                getConfig().getAlias());
        throw new IdentityBrokerException("Direct login through the OpenID4VP Plugin Import provider is not supported."
                + " Authenticate through the OpenID4VP login page instead.");
    }

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        return null;
    }

    @Override
    public Response retrieveToken(
            KeycloakSession session, FederatedIdentityModel identity, UserSessionModel userSession, UserModel user) {
        return null;
    }
}
