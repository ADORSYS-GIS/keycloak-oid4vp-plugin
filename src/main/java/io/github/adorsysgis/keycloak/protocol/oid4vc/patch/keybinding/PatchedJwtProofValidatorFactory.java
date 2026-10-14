package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.keybinding;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.keybinding.AttestationKeyResolver;
import org.keycloak.protocol.oid4vc.issuance.keybinding.JwtProofValidatorFactory;
import org.keycloak.protocol.oid4vc.issuance.keybinding.TrustedAttestationKeyResolver;

/**
 * Overrides the default JWT proof validator with a higher-priority decorated instance that
 * tolerates a JWT proof whose {@code iss} claim equals the Credential Issuer identifier instead
 * of the requesting {@code client_id} (see {@link PatchedJwtProofValidator}).
 *
 * <p>Remove this factory together with {@link PatchedJwtProofValidator} once the fix is part of the
 * supported Keycloak release.
 */
public final class PatchedJwtProofValidatorFactory extends JwtProofValidatorFactory {

    @Override
    public int order() {
        return super.order() + 9;
    }

    @Override
    public PatchedJwtProofValidator create(KeycloakSession session) {
        AttestationKeyResolver keyResolver = new TrustedAttestationKeyResolver(session);
        return new PatchedJwtProofValidator(session, keyResolver);
    }
}
