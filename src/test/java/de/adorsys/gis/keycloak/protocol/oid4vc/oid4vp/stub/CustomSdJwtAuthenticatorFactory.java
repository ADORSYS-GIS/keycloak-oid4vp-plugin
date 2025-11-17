package de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.stub;

import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticator;
import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory;
import de.adorsys.gis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import de.adorsys.gis.keycloak.protocol.oid4vc.tokenstatus.http.TrustedStatusListJwtFetcher;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;

/**
 * This class overrides the default behavior of the {@link SdJwtAuthenticatorFactory} to use a mock
 * {@link TrustedStatusListJwtFetcher} that fetches status list JWTs from local resources instead of
 * making actual HTTP calls. This is useful for testing purposes.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class CustomSdJwtAuthenticatorFactory extends SdJwtAuthenticatorFactory {

    @Override
    public int order() {
        // Ensure this factory is used instead of the default one
        return super.order() + 10;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        StatusListJwtFetcher httpFetcher = new MockTrustedStatusListJwtFetcher(session);
        return new SdJwtAuthenticator(httpFetcher);
    }

    public static class MockTrustedStatusListJwtFetcher extends TrustedStatusListJwtFetcher {

        public MockTrustedStatusListJwtFetcher(KeycloakSession session) {
            super(session);
        }

        @Override
        protected String _fetchStatusListJwt(String uri) {
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

        static String exampleStatusListJwt(String filename) {
            try (InputStream stream = CustomSdJwtAuthenticatorFactory.class.getResourceAsStream(filename)) {
                if (stream == null) {
                    throw new IllegalArgumentException("Resource not found: " + filename);
                }

                return new String(stream.readAllBytes(), StandardCharsets.UTF_8)
                        .replaceAll("\\R", "");
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
