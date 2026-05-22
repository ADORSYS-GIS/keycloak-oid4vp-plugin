package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

import com.apicatalog.jsonld.StringUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.util.List;

/**
 * Validates OpenID4VP response {@code state} against the request binding value (§5.3).
 */
public final class ResponseStateValidator {

    private ResponseStateValidator() {}

    /**
     * When any DCQL credential has {@code require_cryptographic_holder_binding=false}, {@code state} is
     * mandatory and must equal {@code requestId}. The SD-JWT login flow currently issues one credential;
     * all credentials are scanned so multi-credential queries remain correct when added later.
     */
    public static void validate(ResponseObject responseObject, DcqlQuery dcqlQuery, String requestId) {
        if (anyCredentialWithoutHolderBinding(dcqlQuery.getCredentials())) {
            String parsedState = responseObject.getState();
            if (StringUtils.isBlank(parsedState) || !requestId.equals(parsedState)) {
                throw new IllegalArgumentException(String.format(
                        "State param is required and must match requestId when holder binding is not required. requestId: %s, state: %s",
                        requestId, parsedState));
            }
            return;
        }

        String parsedState = responseObject.getState();
        if (StringUtils.isNotBlank(parsedState) && !requestId.equals(parsedState)) {
            throw new IllegalArgumentException(String.format(
                    "State param must match requestId. requestId: %s, state: %s", requestId, parsedState));
        }
    }

    private static boolean anyCredentialWithoutHolderBinding(List<Credential> credentials) {
        return credentials.stream().anyMatch(c -> Boolean.FALSE.equals(c.getRequireCryptographicHolderBinding()));
    }
}
