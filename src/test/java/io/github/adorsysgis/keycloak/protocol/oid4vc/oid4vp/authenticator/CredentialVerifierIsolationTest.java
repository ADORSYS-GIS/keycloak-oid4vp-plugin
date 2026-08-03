package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocBaseTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocVerificationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.mdoc.MdocCredentialVerifier;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.sdjwt.SdJwtCredentialVerifier;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Verifies the per-session verifier isolation introduced through {@link CredentialVerifier#copy()}.
 *
 * <p>{@code OID4VPAuthenticator#resolveVerifiers} clones the registered template verifier for each
 * credential so that mutable per-verification state is never shared across concurrent sessions.
 */
class CredentialVerifierIsolationTest {

    @ParameterizedTest
    @MethodSource("formats")
    void resolveVerifiers_isolatesInstancePerCredentialAndSession(CredentialFormat format) {
        CredentialVerifier template = newVerifier(format);
        OID4VPAuthenticator authenticator = new OID4VPAuthenticator(Map.of(format.getValue(), template));
        AuthorizationContext authContext = authContext(format.getValue(), "cred-a", "cred-b");

        Map<String, CredentialVerifier> sessionOne = authenticator.resolveVerifiers(authContext);
        Map<String, CredentialVerifier> sessionTwo = authenticator.resolveVerifiers(authContext);

        // Set.of rejects duplicates: this fails if any resolved verifier aliases another or the template.
        Set.of(
                template,
                sessionOne.get("cred-a"),
                sessionOne.get("cred-b"),
                sessionTwo.get("cred-a"),
                sessionTwo.get("cred-b"));
    }

    @Test
    void mdocCopies_DoNotShareVerificationContext() throws Exception {
        MdocCredentialVerifier template = new MdocCredentialVerifier(mock(StatusListJwtFetcher.class));
        MdocCredentialVerifier copyOne = template.copy();
        MdocCredentialVerifier copyTwo = template.copy();

        assertNull(verificationContextOf(copyOne));

        // Simulate a first session's verifyCredential() caching context on its own copy only.
        String mdoc = MdocBaseTest.buildDeviceResponse(
                        MdocBaseTest.getDefaultMdocVerificationOpts().build(),
                        Map.of(MdocBaseTest.NAMESPACE, Map.of("c", "v")),
                        MdocBaseTest.DOC_TYPE)
                .encodeToBase64Url();
        MdocVerificationContext firstSessionState = new MdocVerificationContext(mdoc);
        setVerificationContext(copyOne, firstSessionState);

        assertSame(firstSessionState, verificationContextOf(copyOne));
        assertNull(verificationContextOf(template), "template must stay pristine");
        assertNull(verificationContextOf(copyTwo), "other session copy must not see the state");
    }

    private static Stream<CredentialFormat> formats() {
        return Stream.of(CredentialFormat.MSO_MDOC, CredentialFormat.SD_JWT_VC);
    }

    private static CredentialVerifier newVerifier(CredentialFormat format) {
        StatusListJwtFetcher fetcher = mock(StatusListJwtFetcher.class);
        return switch (format) {
            case SD_JWT_VC -> new SdJwtCredentialVerifier(fetcher);
            case MSO_MDOC -> new MdocCredentialVerifier(fetcher);
        };
    }

    private static AuthorizationContext authContext(String format, String... credentialIds) {
        DcqlQuery query = new DcqlQuery();
        List<Credential> credentials =
                Arrays.stream(credentialIds).map(id -> credential(id, format)).toList();
        query.setCredentials(credentials);

        RequestObject requestObject = mock(RequestObject.class);
        when(requestObject.getDcqlQuery()).thenReturn(query);

        AuthorizationContext authContext = mock(AuthorizationContext.class);
        when(authContext.getRequestObject()).thenReturn(requestObject);
        return authContext;
    }

    private static Credential credential(String id, String format) {
        Credential credential = new Credential();
        credential.setId(id);
        credential.setFormat(format);
        return credential;
    }

    private static MdocVerificationContext verificationContextOf(MdocCredentialVerifier verifier) throws Exception {
        return (MdocVerificationContext) verificationContextField().get(verifier);
    }

    private static void setVerificationContext(MdocCredentialVerifier verifier, MdocVerificationContext value)
            throws Exception {
        verificationContextField().set(verifier, value);
    }

    private static Field verificationContextField() throws Exception {
        Field field = MdocCredentialVerifier.class.getDeclaredField("verificationContext");
        field.setAccessible(true);
        return field;
    }
}
