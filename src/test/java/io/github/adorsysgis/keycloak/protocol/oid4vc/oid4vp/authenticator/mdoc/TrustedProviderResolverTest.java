package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.mdoc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocBaseTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRole;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.TrustPolicy;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

class TrustedProviderResolverTest {

    private final KeycloakSession session = mock(KeycloakSession.class);
    private final KeycloakContext context = mock(KeycloakContext.class);
    private final KeyManager keyManager = mock(KeyManager.class);
    private final RealmModel realm = mock(RealmModel.class);

    private List<KeyWrapper> realmKeys = List.of();

    @BeforeEach
    void setUp() {
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        when(session.keys()).thenReturn(keyManager);
        when(keyManager.getKeysStream(realm)).thenAnswer(ignored -> realmKeys.stream());
    }

    @Test
    void shouldTrustEnabledRealmSigningCertificatesForPrimaryMdoc() throws Exception {
        X509Certificate activeCertificate = MdocBaseTest.getIssuerCertRef1();
        X509Certificate passiveCertificate = MdocBaseTest.getIssuerCertRef2();
        realmKeys = List.of(
                key(KeyStatus.ACTIVE, KeyUse.SIG, activeCertificate, false),
                key(KeyStatus.PASSIVE, KeyUse.SIG, passiveCertificate, true),
                key(KeyStatus.DISABLED, KeyUse.SIG, MdocBaseTest.getIssuerCertRef1(), false),
                key(KeyStatus.ACTIVE, KeyUse.ENC, MdocBaseTest.getIssuerCertRef1(), false),
                key(KeyStatus.ACTIVE, KeyUse.SIG, null, false));

        Set<X509Certificate> anchors = new HashSet<>(
                TrustedProviderResolver.resolve(session, primaryCredential())
                        .trustAnchors()
                        .getRootCertificates()
                        .values()
                        .stream()
                        .flatMap(List::stream)
                        .toList());

        assertEquals(Set.of(activeCertificate, passiveCertificate), anchors);
    }

    @Test
    void shouldResolveSelfTrustForSupportingMdoc() throws Exception {
        X509Certificate certificate = MdocBaseTest.getIssuerCertRef1();
        realmKeys = List.of(key(KeyStatus.ACTIVE, KeyUse.SIG, certificate, false));

        var resolved = TrustedProviderResolver.resolve(session, supportingCredential());

        assertTrue(resolved.trustAnchors().getRootCertificates().values().stream()
                .flatMap(List::stream)
                .anyMatch(certificate::equals));
    }

    @Test
    void shouldRejectSelfTrustWhenRealmHasNoEnabledSigningCertificate() {
        realmKeys = List.of(key(KeyStatus.ACTIVE, KeyUse.SIG, null, false));

        IllegalStateException error = assertThrows(
                IllegalStateException.class, () -> TrustedProviderResolver.resolve(session, primaryCredential()));

        assertTrue(error.getMessage().contains("no enabled signing key with a certificate"));
    }

    private static CredentialRequirement primaryCredential() {
        return credential().setRole(CredentialRole.PRIMARY);
    }

    private static CredentialRequirement supportingCredential() {
        return credential();
    }

    private static CredentialRequirement credential() {
        return new CredentialRequirement()
                .setId("identity")
                .setTrust(List.of(new TrustPolicy().setType(TrustPolicy.SELF)));
    }

    private static KeyWrapper key(
            KeyStatus status, KeyUse use, X509Certificate certificate, boolean useCertificateChain) {
        KeyWrapper key = new KeyWrapper();
        key.setStatus(status);
        key.setUse(use);
        if (useCertificateChain && certificate != null) {
            key.setCertificateChain(List.of(certificate));
        } else {
            key.setCertificate(certificate);
        }
        return key;
    }
}
