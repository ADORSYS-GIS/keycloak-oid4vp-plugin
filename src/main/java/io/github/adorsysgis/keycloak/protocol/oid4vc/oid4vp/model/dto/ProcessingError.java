package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Arrays;

/**
 * Potential errors as authorization responses are processed.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public enum ProcessingError {
    AUTH_CONTEXT_CLOSED("auth_context_closed"),
    INVALID_VP_TOKEN("invalid_vp_token"),
    VP_TOKEN_AUTH_ERROR("vp_token_auth_error"),
    INVALID_REQUEST("invalid_request"),
    INVALID_SCOPE("invalid_scope"),
    INVALID_CLIENT("invalid_client"),
    ACCESS_DENIED("access_denied"),
    UNAUTHORIZED_CLIENT("unauthorized_client"),
    UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type"),
    SERVER_ERROR("server_error"),
    TEMPORARILY_UNAVAILABLE("temporarily_unavailable"),
    VP_FORMATS_NOT_SUPPORTED("vp_formats_not_supported"),
    INVALID_REQUEST_URI_METHOD("invalid_request_uri_method"),
    INVALID_TRANSACTION_DATA("invalid_transaction_data"),
    WALLET_UNAVAILABLE("wallet_unavailable"),
    WALLET_ERROR("wallet_error");

    private final String error;

    ProcessingError(String error) {
        this.error = error;
    }

    @JsonValue
    public String getErrorString() {
        return error;
    }

    @JsonCreator
    public static ProcessingError fromErrorString(String error) {
        return Arrays.stream(values())
                .filter(processingError -> processingError.error.equals(error))
                .findFirst()
                .orElse(WALLET_ERROR);
    }
}
