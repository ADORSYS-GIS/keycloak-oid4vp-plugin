package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocBaseTest;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sdjwt.IssuerSignedJWT;

class CredentialOriginResolverTest {

    private KeycloakSession session;
    private KeyManager keyManager;
    private RealmModel realm;
    private KeyWrapper realmKey;

    @BeforeEach
    void setUp() {
        session = mock(KeycloakSession.class);
        keyManager = mock(KeyManager.class);
        realm = mock(RealmModel.class);
        KeycloakContext context = mock(KeycloakContext.class);
        realmKey = mock(KeyWrapper.class);

        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);
        when(session.keys()).thenReturn(keyManager);
        when(realmKey.getUse()).thenReturn(KeyUse.SIG);
        when(realmKey.getKid()).thenReturn("realm-key");
        when(realmKey.getAlgorithmOrDefault()).thenReturn("ES256");
    }

    @Test
    void sdJwtOriginDependsOnSignatureVerificationNotIssuerOrTrustPolicy() throws Exception {
        IssuerSignedJWT jwt = mock(IssuerSignedJWT.class);
        JWSHeader header = mock(JWSHeader.class);
        SignatureProvider provider = mock(SignatureProvider.class);
        SignatureVerifierContext verifier = mock(SignatureVerifierContext.class);
        when(jwt.getJwsHeader()).thenReturn(header);
        when(header.getKeyId()).thenReturn("overridden-credential-kid");
        when(keyManager.getKeysStream(realm)).thenReturn(Stream.of(realmKey));
        when(session.getProvider(SignatureProvider.class, "ES256")).thenReturn(provider);
        when(provider.verifier(realmKey)).thenReturn(verifier);

        assertEquals(CredentialOrigin.CURRENT_REALM, CredentialOriginResolver.forSdJwt(session, jwt));

        doThrow(new VerificationException("wrong signature")).when(jwt).verifySignature(any());
        when(keyManager.getKeysStream(realm)).thenReturn(Stream.of(realmKey));
        assertEquals(CredentialOrigin.EXTERNAL, CredentialOriginResolver.forSdJwt(session, jwt));
    }

    @Test
    void mdocOriginDependsOnValidatedLeafPublicKey() {
        var certificate = MdocBaseTest.getIssuerCertRef1();
        when(realmKey.getPublicKey()).thenReturn(certificate.getPublicKey());
        when(keyManager.getKeysStream(realm)).thenReturn(Stream.of(realmKey));

        assertEquals(CredentialOrigin.CURRENT_REALM, CredentialOriginResolver.forMdoc(session, certificate));

        when(realmKey.getPublicKey())
                .thenReturn(MdocBaseTest.getIssuerCertRef2().getPublicKey());
        when(keyManager.getKeysStream(realm)).thenReturn(Stream.of(realmKey));
        assertEquals(CredentialOrigin.EXTERNAL, CredentialOriginResolver.forMdoc(session, certificate));
    }
}
