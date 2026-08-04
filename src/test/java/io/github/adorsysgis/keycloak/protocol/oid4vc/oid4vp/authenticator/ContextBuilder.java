package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.AuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import java.util.HashMap;
import java.util.Map;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Test-only builder for {@link OID4VPAuthenticator.Context}.
 */
public class ContextBuilder {

    private String id;
    private AuthenticationFlowContext authenticationFlowContext;
    private AuthenticationSessionModel authenticationSession;
    private AuthorizationContext authorizationContext;
    private AuthenticationProfile authenticationProfile;
    private AuthRequirements authRequirements;
    private final Map<String, String> presentedTokens = new HashMap<>();
    private final Map<String, CredentialVerifier> credentialVerifiers = new HashMap<>();

    public ContextBuilder id(String id) {
        this.id = id;
        return this;
    }

    public ContextBuilder authenticationFlowContext(AuthenticationFlowContext authenticationFlowContext) {
        this.authenticationFlowContext = authenticationFlowContext;
        return this;
    }

    public ContextBuilder authenticationSession(AuthenticationSessionModel authenticationSession) {
        this.authenticationSession = authenticationSession;
        return this;
    }

    public ContextBuilder authorizationContext(AuthorizationContext authorizationContext) {
        this.authorizationContext = authorizationContext;
        return this;
    }

    public ContextBuilder authenticationProfile(AuthenticationProfile authenticationProfile) {
        this.authenticationProfile = authenticationProfile;
        return this;
    }

    public ContextBuilder authRequirements(AuthRequirements authRequirements) {
        this.authRequirements = authRequirements;
        return this;
    }

    public ContextBuilder presentedToken(String credentialId, String token) {
        this.presentedTokens.put(credentialId, token);
        return this;
    }

    public ContextBuilder credentialVerifier(String credentialId, CredentialVerifier verifier) {
        this.credentialVerifiers.put(credentialId, verifier);
        return this;
    }

    public OID4VPAuthenticator.Context build() {
        return new OID4VPAuthenticator.Context(
                id,
                authenticationFlowContext,
                authenticationSession,
                authorizationContext,
                authenticationProfile,
                authRequirements,
                presentedTokens,
                credentialVerifiers);
    }
}
