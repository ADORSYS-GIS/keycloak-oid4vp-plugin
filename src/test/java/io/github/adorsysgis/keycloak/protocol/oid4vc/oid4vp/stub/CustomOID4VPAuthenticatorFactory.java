package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.stub;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialFormat;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialVerifier;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.mdoc.MdocCredentialVerifier;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.sdjwt.SdJwtCredentialVerifier;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.TrustedStatusListJwtFetcher;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;

/**
 * This class overrides the default behavior of the {@link OID4VPAuthenticatorFactory} to use a mock
 * {@link TrustedStatusListJwtFetcher} that fetches status list JWTs from local resources instead of
 * making actual HTTP calls. This is useful for testing purposes.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class CustomOID4VPAuthenticatorFactory extends OID4VPAuthenticatorFactory {

    @Override
    public int order() {
        // Ensure this factory is used instead of the default one
        return super.order() + 10;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        Map<String, CredentialVerifier> handlers = new LinkedHashMap<>();
        StatusListJwtFetcher httpFetcher = new MockTrustedStatusListJwtFetcher(session);
        handlers.put(CredentialFormat.SD_JWT_VC.getValue(), new SdJwtCredentialVerifier(httpFetcher));
        handlers.put(CredentialFormat.MSO_MDOC.getValue(), new MdocCredentialVerifier(httpFetcher));
        return new OID4VPAuthenticator(handlers);
    }

    public static class MockTrustedStatusListJwtFetcher extends TrustedStatusListJwtFetcher {

        public MockTrustedStatusListJwtFetcher(KeycloakSession session) {
            super(session);
        }

        @Override
        public String fetchStatusListJwt(String uri) throws ReferencedTokenValidationException {
            String originalJwt = super.fetchStatusListJwt(uri);
            String[] parts = originalJwt.split("\\.");
            if (parts.length != 3) {
                throw new ReferencedTokenValidationException("Malformed JWT: expected 3 parts");
            }
            byte[] decodedPayload = Base64.getUrlDecoder().decode(parts[1]);
            String payloadJson = new String(decodedPayload, StandardCharsets.UTF_8);
            try {
                ObjectNode payload = (ObjectNode) JsonSerialization.mapper.readTree(payloadJson);
                payload.put("sub", uri);
                String newPayload = payload.toString();
                String encodedPayload = Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(newPayload.getBytes(StandardCharsets.UTF_8));
                return parts[0] + "." + encodedPayload + "." + parts[2];
            } catch (IOException e) {
                throw new ReferencedTokenValidationException("Failed to modify status list JWT payload", e);
            }
        }

        @Override
        protected String fetchStatusListFromUri(String uri) {
            String path;

            try {
                path = new URI(uri).getPath();
            } catch (URISyntaxException e) {
                throw new IllegalArgumentException("Invalid URI: " + uri, e);
            }

            if (path == null || path.isEmpty()) {
                throw new IllegalArgumentException("Empty resource");
            }

            String resource = path.substring(path.lastIndexOf('/') + 1);
            return exampleStatusListJwt(String.format("/tokenstatus/%s.txt", resource));
        }

        public static String exampleStatusListJwt(String filename) {
            try (InputStream stream = CustomOID4VPAuthenticatorFactory.class.getResourceAsStream(filename)) {
                if (stream == null) {
                    throw new IllegalArgumentException("Resource not found: " + filename);
                }

                return new String(stream.readAllBytes(), StandardCharsets.UTF_8).replaceAll("\\R", "");
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
