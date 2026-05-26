package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import java.net.URI;
import org.keycloak.utils.StringUtil;

/**
 * Resolves the holder-binding audience for replay protection (OpenID4VP §14.1, §14.8, Appendix A.4).
 *
 * <p>Uses the full {@code client_id} (including any Client Identifier Prefix). For Digital
 * Credentials API flows the audience is {@code origin:}<i>origin</i> and may already be reflected
 * in {@code client_id}.
 */
public final class HolderBindingAudienceResolver {

    private HolderBindingAudienceResolver() {}

    public static String resolve(RequestObject requestObject) {
        String clientId = requestObject.getClientId();
        if (!StringUtil.isBlank(clientId)) {
            if (clientId.startsWith("origin:")) {
                return clientId;
            }
            return clientId;
        }

        String originAudience = originAudienceFromResponseUri(requestObject.getResponseUri());
        if (originAudience != null) {
            return originAudience;
        }

        return clientId;
    }

    private static String originAudienceFromResponseUri(String responseUri) {
        if (StringUtil.isBlank(responseUri)) {
            return null;
        }
        try {
            URI uri = URI.create(responseUri);
            if (uri.getScheme() == null || uri.getHost() == null) {
                return null;
            }
            int port = uri.getPort();
            String origin = port > 0
                    ? String.format("%s://%s:%d", uri.getScheme(), uri.getHost(), port)
                    : String.format("%s://%s", uri.getScheme(), uri.getHost());
            return "origin:" + origin;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
