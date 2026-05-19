package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import org.junit.jupiter.api.Test;

class HolderBindingAudienceResolverTest {

    @Test
    void usesFullClientIdentifierIncludingPrefix() {
        RequestObject request = new RequestObject().setClientId("redirect_uri:https://verifier.example.org/cb");

        assertEquals("redirect_uri:https://verifier.example.org/cb", HolderBindingAudienceResolver.resolve(request));
    }

    @Test
    void preservesOriginPrefixedClientIdentifier() {
        RequestObject request =
                new RequestObject().setClientId("origin:https://verifier.example.org");

        assertEquals("origin:https://verifier.example.org", HolderBindingAudienceResolver.resolve(request));
    }

    @Test
    void derivesOriginAudienceFromResponseUriWhenClientIdMissing() {
        RequestObject request = new RequestObject().setResponseUri("https://verifier.example.org/openid4vp/response");

        assertEquals("origin:https://verifier.example.org", HolderBindingAudienceResolver.resolve(request));
    }
}
