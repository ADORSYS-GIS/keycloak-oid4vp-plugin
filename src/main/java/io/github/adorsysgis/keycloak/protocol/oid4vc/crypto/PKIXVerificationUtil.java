package io.github.adorsysgis.keycloak.protocol.oid4vc.crypto;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.TrustAnchorProvider;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import javax.security.auth.x500.X500Principal;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Time;

public class PKIXVerificationUtil {

    private static final int MAX_CHAIN_LENGTH = 5;

    private PKIXVerificationUtil() {}

    public static X509Certificate[] validateBase64Chain(List<String> certs, TrustAnchorProvider trustAnchorProvider)
            throws VerificationException {
        return validateChain(parseX509Certificates(certs), trustAnchorProvider);
    }

    public static X509Certificate[] validateBase64Chain(
            List<String> certs, Collection<X509Certificate> rootCertificates) throws VerificationException {
        return validateChain(parseX509Certificates(certs), rootCertificates, List.of());
    }

    public static X509Certificate[] validateChain(List<X509Certificate> certs, TrustAnchorProvider trustAnchorProvider)
            throws VerificationException {
        List<X509Certificate> roots = Optional.ofNullable(trustAnchorProvider)
                .map(TrustAnchorProvider::getRootCertificates)
                .map(PKIXVerificationUtil::collectCerts)
                .orElse(null);

        List<X509Certificate> intermediates = Optional.ofNullable(trustAnchorProvider)
                .map(TrustAnchorProvider::getIntermediateCertificates)
                .map(PKIXVerificationUtil::collectCerts)
                .orElse(null);

        return validateChain(certs, roots, intermediates);
    }

    public static X509Certificate[] validateChain(
            List<X509Certificate> certs,
            Collection<X509Certificate> rootCertificates,
            Collection<X509Certificate> intermediateCertificates)
            throws VerificationException {
        try {
            if (certs == null || certs.isEmpty()) {
                throw new VerificationException("Certificate chain is empty");
            }

            if (certs.size() > MAX_CHAIN_LENGTH) {
                throw new VerificationException(
                        String.format("Certificate chain too long: %d (max %d)", certs.size(), MAX_CHAIN_LENGTH));
            }

            if (rootCertificates == null || rootCertificates.isEmpty()) {
                throw new VerificationException("No trusted root certificates available for validation");
            }

            // The PKIX path builder verifies certificates along the path it builds, but silently
            // ignores the rest of the presented chain, so a bogus certificate presented beyond a
            // trusted root (one that does not sign it) would slip through unnoticed. The
            // presented chain itself must therefore be coherent.
            validatePresentedChain(certs);

            // Certificates passed as roots are trusted as roots - self-signed or not;
            // intermediates only bridge chains and never provide trust themselves.
            Set<TrustAnchor> trustAnchors = rootCertificates.stream()
                    .map(cert -> new TrustAnchor(cert, null))
                    .collect(Collectors.toSet());

            // The presented chain plus the intermediates form the certificate store the path
            // builder uses to bridge the leaf up to a trusted root.
            Set<X509Certificate> store = new LinkedHashSet<>(certs);
            Optional.ofNullable(intermediateCertificates).orElse(List.of()).stream()
                    .filter(Objects::nonNull)
                    .forEach(store::add);

            X509CertSelector targetSelector = new X509CertSelector();
            targetSelector.setCertificate(certs.getFirst());

            PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, targetSelector);
            // TODO: Revocation checking is currently disabled to avoid blocking network I/O during validation.
            // For production-grade revocation, set to true and configure a PKIXRevocationChecker or
            // provide a CRL cert store via params.addCertStore().
            params.setRevocationEnabled(false);
            // Sync with Keycloak offset time for testing (and production time consistency)
            params.setDate(new Date(Time.currentTimeMillis()));
            params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(store)));

            // The PKIX path builder enforces the remaining constraints (signatures, basic
            // constraints, key usage, validity of bridged certificates) along the path it
            // builds, so no separate validation run is needed afterwards.
            CertPathBuilder.getInstance("PKIX").build(params);
            return certs.toArray(new X509Certificate[0]);
        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationException("Certificate chain validation failed", e);
        }
    }

    /**
     * Validates the presented chain as an application-level invariant on top of PKIX path
     * building: each presented certificate must be in date, issued by - and genuinely signed
     * with the key of - the next one.
     *
     * <p>This is deliberately not done by the path builder, which verifies only the
     * certificates along the path it builds. Certificates presented beyond a trusted root
     * are consequently validated here by this weaker property (validity, issuer DN,
     * signature) only - before the trust anchor PKIX performs its full validation.
     */
    private static void validatePresentedChain(List<X509Certificate> certs)
            throws VerificationException, GeneralSecurityException {
        for (int i = 0; i < certs.size(); i++) {
            X509Certificate cert = certs.get(i);
            // Fail fast on expired certificates so callers observe a CertificateExpiredException
            // instead of the path builder's generic "unable to find valid certification path".
            cert.checkValidity(new Date(Time.currentTimeMillis()));
            if (i == certs.size() - 1) {
                break;
            }

            X509Certificate next = certs.get(i + 1);
            if (!cert.getIssuerX500Principal().equals(next.getSubjectX500Principal())) {
                throw new VerificationException("Certificate chain is not in order");
            }

            try {
                cert.verify(next.getPublicKey());
            } catch (Exception e) {
                throw new VerificationException("Certificate chain signature validation failed", e);
            }
        }
    }

    private static List<X509Certificate> parseX509Certificates(List<String> base64Certs) throws VerificationException {
        if (base64Certs == null || base64Certs.isEmpty()) {
            throw new VerificationException("Certificate chain is empty");
        }

        try {
            List<X509Certificate> certs = new ArrayList<>();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (String base64Cert : base64Certs) {
                byte[] bytes = Base64.getDecoder().decode(base64Cert);
                certs.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes)));
            }
            return certs;
        } catch (CertificateException e) {
            throw new VerificationException("Failed to parse X.509 certificate", e);
        }
    }

    private static List<X509Certificate> collectCerts(Map<X500Principal, List<X509Certificate>> anchorMap) {
        return Optional.ofNullable(anchorMap).orElse(Map.of()).values().stream()
                .filter(Objects::nonNull)
                .flatMap(List::stream)
                .filter(Objects::nonNull)
                .toList();
    }
}
