package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.mdoc;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.TrustPolicy;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.EudiPidTrustException;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.EudiPidTrustListProvider;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.StaticTruststoreProvider;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.TrustAnchorProvider;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.common.VerificationException;
import org.keycloak.models.KeycloakSession;

/**
 * Resolves the trust policy configured on a {@link CredentialRequirement} into a
 * {@link TrustAnchorProvider} suitable for mDoc issuer PKIX verification.
 *
 * <p>Unlike its SD-JWT counterpart {@code SdJwtTrustedIssuerResolver}, this resolver
 * does <strong>not</strong> support self-trust: mDoc issuers are always external to
 * the Keycloak realm, so a trust anchor (either pinned certificates or an EUDI PID
 * trust list) must be configured.
 *
 * <p>Supported policy types:
 * <ul>
 *     <li>{@link TrustPolicy#X5C} — uses the parsed {@code anchors} certificates as
 *     trust roots.</li>
 *     <li>{@link TrustPolicy#EUDI_PID_TRUST_LIST} — fetches service certificates from
 *     the configured EUDI PID trust list and uses them as trust roots.</li>
 * </ul>
 */
public final class TrustedProviderResolver {

    private static final Logger logger = Logger.getLogger(TrustedProviderResolver.class);

    private TrustedProviderResolver() {}

    public static TrustAnchorProvider resolve(KeycloakSession session, CredentialRequirement credential)
            throws VerificationException {
        if (credential.getTrust() == null || credential.getTrust().isEmpty()) {
            throw new IllegalStateException(String.format(
                    "Credential '%s' does not configure any trust policy. Self-trust is not supported for mDoc.",
                    credential.getId()));
        }

        List<X509Certificate> trustAnchors = new ArrayList<>();
        for (TrustPolicy trust : credential.getTrust()) {
            switch (trust.getType()) {
                case TrustPolicy.X5C -> trustAnchors.addAll(resolveX5cAnchors(trust, credential.getId()));
                case TrustPolicy.EUDI_PID_TRUST_LIST ->
                    trustAnchors.addAll(resolveEudiPidTrustList(session, trust, credential.getId()));
                default ->
                    throw new IllegalStateException(String.format(
                            "Credential '%s' uses an unsupported trust policy: %s",
                            credential.getId(), trust.getType()));
            }
        }
        return new StaticTruststoreProvider(trustAnchors);
    }

    private static List<X509Certificate> resolveX5cAnchors(TrustPolicy trust, String credentialId) {
        if (trust.getAnchors() == null || trust.getAnchors().isEmpty()) {
            throw new IllegalStateException(
                    String.format("Credential '%s' uses x5c trust but declares no anchors.", credentialId));
        }

        return trust.getAnchors();
    }

    private static List<X509Certificate> resolveEudiPidTrustList(
            KeycloakSession session, TrustPolicy trust, String credentialId) throws VerificationException {
        try {
            return new EudiPidTrustListProvider(session).resolve(trust).trustedIssuerCertificates();
        } catch (EudiPidTrustException e) {
            throw new VerificationException(
                    String.format("Credential '%s' could not resolve EUDI PID trust list", credentialId), e);
        }
    }
}
