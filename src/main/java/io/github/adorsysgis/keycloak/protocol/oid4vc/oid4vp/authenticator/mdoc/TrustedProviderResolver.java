package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.mdoc;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.TrustPolicy;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.EudiPidTrustException;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.EudiPidTrustListProvider;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.EudiPidTrustListProvider.TrustedPidProvider;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.StaticTruststoreProvider;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.TrustAnchorProvider;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;

/**
 * Resolves the trust policy configured on a {@link CredentialRequirement} into a
 * {@link TrustAnchorProvider} suitable for mDoc issuer PKIX verification.
 *
 * <p>Supported policy types:
 * <ul>
 *     <li>{@link TrustPolicy#SELF} — pins the leaf certificates of the realm's enabled
 *     signing keys, allowing mDocs issued by this Keycloak realm.</li>
 *     <li>{@link TrustPolicy#X5C} — uses the parsed {@code anchors} certificates as
 *     trust roots.</li>
 *     <li>{@link TrustPolicy#EUDI_PID_TRUST_LIST} — for a primary login credential,
 *     resolves the configured PID Provider entry and uses only that entity's PID
 *     issuance-service certificates as trust roots.</li>
 * </ul>
 */
public final class TrustedProviderResolver {

    private TrustedProviderResolver() {}

    public static ResolvedMdocTrust resolve(KeycloakSession session, CredentialRequirement credential)
            throws VerificationException {
        if (credential.getTrust() == null || credential.getTrust().isEmpty()) {
            return new ResolvedMdocTrust(
                    new StaticTruststoreProvider(resolveSelfAnchors(session, credential.getId())), null);
        }

        if (requiresIssuerEnforcement(credential)) {
            return resolvePrimaryIssuer(session, credential);
        }

        List<X509Certificate> trustAnchors = new ArrayList<>();
        for (TrustPolicy trust : credential.getTrust()) {
            if (TrustPolicy.EUDI_PID_TRUST_LIST.equals(trust.getType())) {
                trustAnchors.addAll(resolveEudiPidTrustList(session, trust, credential.getId()));
            } else {
                trustAnchors.addAll(resolveStaticAnchors(session, trust, credential.getId()));
            }
        }
        return new ResolvedMdocTrust(
                new StaticTruststoreProvider(trustAnchors), commonPinnedIssuerNamespace(credential.getTrust()));
    }

    private static boolean requiresIssuerEnforcement(CredentialRequirement credential) {
        return credential.isPrimary() && !credential.isSessionIdentity();
    }

    private static String commonPinnedIssuerNamespace(List<TrustPolicy> trustPolicies) {
        String issuerNamespace = null;
        for (TrustPolicy trust : trustPolicies) {
            if (!TrustPolicy.X5C.equals(trust.getType())) {
                return null;
            }

            String configuredNamespace = trust.issuerNamespace();
            if (configuredNamespace == null
                    || (issuerNamespace != null && !issuerNamespace.equals(configuredNamespace))) {
                return null;
            }
            issuerNamespace = configuredNamespace;
        }
        return issuerNamespace;
    }

    private static ResolvedMdocTrust resolvePrimaryIssuer(KeycloakSession session, CredentialRequirement credential)
            throws VerificationException {
        if (credential.getTrust().size() != 1) {
            throw new IllegalStateException(String.format(
                    "Primary credential '%s' must configure exactly one mDoc trust policy.", credential.getId()));
        }

        TrustPolicy trust = credential.getTrust().getFirst();
        return switch (trust.getType()) {
            case TrustPolicy.SELF ->
                new ResolvedMdocTrust(
                        new StaticTruststoreProvider(resolveSelfAnchors(session, credential.getId())), null);
            case TrustPolicy.X5C ->
                new ResolvedMdocTrust(
                        new StaticTruststoreProvider(resolveX5cAnchors(trust, credential.getId())),
                        trust.issuerNamespace());
            case TrustPolicy.EUDI_PID_TRUST_LIST -> resolvePrimaryEudiPidTrust(session, trust, credential.getId());
            default ->
                throw new IllegalStateException(String.format(
                        "Primary mDoc credential '%s' uses an unsupported trust policy: %s",
                        credential.getId(), trust.getType()));
        };
    }

    private static ResolvedMdocTrust resolvePrimaryEudiPidTrust(
            KeycloakSession session, TrustPolicy trust, String credentialId) throws VerificationException {
        try {
            EudiPidTrustListProvider.TrustListSnapshot snapshot = new EudiPidTrustListProvider(session).resolve(trust);
            TrustedPidProvider provider = snapshot.resolveIssuer(trust.getIssuer());
            return new ResolvedMdocTrust(
                    new StaticTruststoreProvider(provider.trustedCertificates()), trust.getIssuer());
        } catch (EudiPidTrustException e) {
            throw new VerificationException(
                    String.format("Credential '%s' could not resolve its configured PID Provider", credentialId), e);
        }
    }

    private static List<X509Certificate> resolveStaticAnchors(
            KeycloakSession session, TrustPolicy trust, String credentialId) {
        return switch (trust.getType()) {
            case TrustPolicy.SELF -> resolveSelfAnchors(session, credentialId);
            case TrustPolicy.X5C -> resolveX5cAnchors(trust, credentialId);
            default ->
                throw new IllegalStateException(String.format(
                        "Credential '%s' uses an unsupported trust policy: %s", credentialId, trust.getType()));
        };
    }

    private static List<X509Certificate> resolveSelfAnchors(KeycloakSession session, String credentialId) {
        List<X509Certificate> anchors = session.keys()
                .getKeysStream(session.getContext().getRealm())
                .filter(key -> KeyUse.SIG.equals(key.getUse()))
                .filter(key -> key.getStatus() != null && key.getStatus().isEnabled())
                .map(TrustedProviderResolver::leafCertificate)
                .filter(Objects::nonNull)
                .distinct()
                .toList();

        if (anchors.isEmpty()) {
            throw new IllegalStateException(String.format(
                    "Credential '%s' uses self trust but the realm has no enabled signing key with a certificate.",
                    credentialId));
        }
        return anchors;
    }

    private static X509Certificate leafCertificate(KeyWrapper key) {
        if (key.getCertificateChain() != null && !key.getCertificateChain().isEmpty()) {
            return key.getCertificateChain().getFirst();
        }
        return key.getCertificate();
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

    /** Resolved trust anchors and the stable issuer namespace, when the configured trust identifies one. */
    public record ResolvedMdocTrust(TrustAnchorProvider trustAnchors, String issuerNamespace) {}
}
