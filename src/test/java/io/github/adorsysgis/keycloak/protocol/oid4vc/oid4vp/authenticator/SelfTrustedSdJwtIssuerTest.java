package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyStatus;
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
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for {@link SelfTrustedSdJwtIssuer} key filtering behavior.
 *
 * @author <a href="mailto:Bertrand.Ogen@adorsys.com">Bertrand Ogen</a>
 */
@ExtendWith(MockitoExtension.class)
public class SelfTrustedSdJwtIssuerTest {

    @Mock
    AuthenticationFlowContext context;

    @Mock
    KeycloakSession session;

    @Mock
    KeycloakContext keycloakContext;

    @Mock
    KeyManager keyManager;

    @Mock
    RealmModel realm;

    @Mock
    SignatureProvider signatureProvider;

    @Mock
    SignatureVerifierContext verifierContext;

    private KeyWrapper activeKey;
    private KeyWrapper disabledKey;

    @BeforeEach
    void setUp() throws VerificationException {
        Mockito.lenient().when(context.getSession()).thenReturn(session);
        Mockito.lenient().when(session.getContext()).thenReturn(keycloakContext);
        Mockito.lenient().when(keycloakContext.getRealm()).thenReturn(realm);
        Mockito.lenient().when(session.keys()).thenReturn(keyManager);

        activeKey = buildKey("active-kid", KeyStatus.ACTIVE);
        disabledKey = buildKey("disabled-kid", KeyStatus.DISABLED);

        Mockito.lenient()
                .when(keyManager.getKeysStream(realm))
                .thenAnswer(invocation -> Stream.of(activeKey, disabledKey));
        Mockito.lenient()
                .when(session.getProvider(SignatureProvider.class, Algorithm.RS256))
                .thenReturn(signatureProvider);
        Mockito.lenient()
                .doReturn(verifierContext)
                .when(signatureProvider)
                .verifier(Mockito.any(KeyWrapper.class));
    }

    @Test
    void shouldRejectDisabledSigningKeys() {
        List<SignatureVerifierContext> disabledKeyVerifiers = new SelfTrustedSdJwtIssuer(context)
                .resolveIssuerVerifyingKeys(issuerSignedJwtWithKid("disabled-kid"));
        assertTrue(disabledKeyVerifiers.isEmpty(), "Disabled keys must not be used for verification");

        List<SignatureVerifierContext> activeKeyVerifiers = new SelfTrustedSdJwtIssuer(context)
                .resolveIssuerVerifyingKeys(issuerSignedJwtWithKid("active-kid"));
        assertEquals(1, activeKeyVerifiers.size(), "Enabled keys should still be eligible for verification");
    }

    private static KeyWrapper buildKey(String kid, KeyStatus status) {
        KeyWrapper key = new KeyWrapper();
        key.setKid(kid);
        key.setUse(KeyUse.SIG);
        key.setStatus(status);
        key.setAlgorithm(Algorithm.RS256);
        return key;
    }

    private static IssuerSignedJWT issuerSignedJwtWithKid(String kid) {
        JWSHeader header = new JWSHeader();
        header.setKeyId(kid);
        ObjectNode payload = JsonNodeFactory.instance.objectNode();
        return new IssuerSignedJWT(header, payload);
    }
}
