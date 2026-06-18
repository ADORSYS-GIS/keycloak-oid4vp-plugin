package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.TrustPolicy;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.EudiPidTrustedSdJwtIssuer;
import java.util.ArrayList;
import java.util.List;
import org.keycloak.common.VerificationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sdjwt.consumer.TrustedSdJwtIssuer;

final class SdJwtTrustedIssuerResolver {

    private SdJwtTrustedIssuerResolver() {}

    static List<TrustedSdJwtIssuer> resolve(KeycloakSession session, CredentialRequirement credential)
            throws VerificationException {
        if (credential.getTrust() == null || credential.getTrust().isEmpty()) {
            return List.of(new SelfTrustedSdJwtIssuer(session));
        }

        List<TrustedSdJwtIssuer> trustedIssuers = new ArrayList<>();
        for (TrustPolicy trust : credential.getTrust()) {
            switch (trust.getType()) {
                case TrustPolicy.SELF -> trustedIssuers.add(new SelfTrustedSdJwtIssuer(session));
                case TrustPolicy.EUDI_PID_TRUST_LIST ->
                    trustedIssuers.add(new EudiPidTrustedSdJwtIssuer(session, trust));
                default ->
                    throw new VerificationException("Credential '%s' uses an unsupported trust policy: %s"
                            .formatted(credential.getId(), trust.getType()));
            }
        }
        return trustedIssuers;
    }
}
