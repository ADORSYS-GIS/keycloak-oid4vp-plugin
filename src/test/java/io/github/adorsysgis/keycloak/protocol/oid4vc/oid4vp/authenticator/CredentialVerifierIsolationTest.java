package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocVerificationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.mdoc.MdocCredentialVerifier;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.sdjwt.SdJwtCredentialVerifier;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import java.lang.reflect.Field;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Verifies the per-session verifier isolation introduced through {@link CredentialVerifier#copy()}.
 *
 * <p>{@code OID4VPAuthenticator#resolveVerifiers} clones the registered template verifier for each
 * credential so that mutable per-verification state is never shared across concurrent sessions.
 */
class CredentialVerifierIsolationTest {

    private static SdJwtCredentialVerifier sdJwtTemplate;
    private static MdocCredentialVerifier mdocTemplate;
    private static OID4VPAuthenticator authenticator;
    private static AuthorizationContext authContext;

    @BeforeAll
    static void setUp() {
        StatusListJwtFetcher statusListJwtFetcher = mock(StatusListJwtFetcher.class);
        sdJwtTemplate = new SdJwtCredentialVerifier(statusListJwtFetcher);
        mdocTemplate = new MdocCredentialVerifier(statusListJwtFetcher);
        Map<String, CredentialVerifier> handlers = Map.of(
                CredentialFormat.SD_JWT_VC.getValue(), sdJwtTemplate,
                CredentialFormat.MSO_MDOC.getValue(), mdocTemplate);
        authenticator = new OID4VPAuthenticator(handlers);

        var credentialReqs = (List.of(
                credential("sdjwt-a", CredentialFormat.SD_JWT_VC.getValue()),
                credential("sdjwt-b", CredentialFormat.SD_JWT_VC.getValue()),
                credential("mdoc-a", CredentialFormat.MSO_MDOC.getValue()),
                credential("mdoc-b", CredentialFormat.MSO_MDOC.getValue())));

        DcqlQuery query = new DcqlQuery();
        query.setCredentials(credentialReqs);

        RequestObject requestObject = mock(RequestObject.class);
        when(requestObject.getDcqlQuery()).thenReturn(query);

        authContext = mock(AuthorizationContext.class);
        when(authContext.getRequestObject()).thenReturn(requestObject);
    }

    private static Credential credential(String id, String format) {
        Credential credential = new Credential();
        credential.setId(id);
        credential.setFormat(format);
        return credential;
    }

    @Test
    void resolveVerifiers_isolatesInstancePerCredential() {
        Map<String, CredentialVerifier> verifiers = authenticator.resolveVerifiers(authContext);

        Set<CredentialVerifier> resolved = new HashSet<>(List.of(
                sdJwtTemplate,
                mdocTemplate,
                verifiers.get("sdjwt-a"),
                verifiers.get("sdjwt-b"),
                verifiers.get("mdoc-a"),
                verifiers.get("mdoc-b")));

        assertEquals(6, resolved.size(), "Each resolved verifier must be distinct from the templates and one another");
    }

    @Test
    void copy_DropsCachedVerificationContext() throws Exception {
        MdocCredentialVerifier verifier1 = mdocTemplate.copy();

        MdocVerificationContext cached = mock(MdocVerificationContext.class);
        field("verificationContext").set(verifier1, cached);

        MdocCredentialVerifier verifier2 = verifier1.copy();

        assertSame(cached, field("verificationContext").get(verifier1), "verifier1 keeps its cached state");
        assertNull(field("verificationContext").get(verifier2), "a copy must not carry over the cached state");

        assertSame(
                field("tokenStatusValidator").get(mdocTemplate),
                field("tokenStatusValidator").get(verifier2),
                "the configuration-only token status validator is preserved across copies");
    }

    private static Field field(String name) throws Exception {
        Field field = MdocCredentialVerifier.class.getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }
}
