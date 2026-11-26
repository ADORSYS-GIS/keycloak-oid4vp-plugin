package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import java.net.URI;
import org.keycloak.provider.Provider;

/** Performs HTTP operations against the EUDI Hub Organization API. */
public interface EudiHubClientProvider extends Provider {

    <T> T get(String token, URI uri, Class<T> responseType);

    <T> T post(String token, URI uri, Object body, Class<T> responseType);

    byte[] download(String token, URI uri);
}
