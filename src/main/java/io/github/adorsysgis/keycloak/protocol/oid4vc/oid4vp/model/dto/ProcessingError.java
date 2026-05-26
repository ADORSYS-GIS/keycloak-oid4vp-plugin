package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Errors issued by the plugin while processing a wallet authorization response.
 * Wallet-posted OAuth/OID4VP error codes are not mirrored here; use {@link #WALLET_ERROR}
 * and carry the wallet's {@code error} / {@code error_description} in the context's
 * {@code error_description} field instead.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public enum ProcessingError {
    AUTH_CONTEXT_CLOSED("auth_context_closed"),
    INVALID_VP_TOKEN("invalid_vp_token"),
    VP_TOKEN_AUTH_ERROR("vp_token_auth_error"),
    WALLET_ERROR("wallet_error");

    private final String error;

    ProcessingError(String error) {
        this.error = error;
    }

    @JsonValue
    public String getErrorString() {
        return error;
    }
}
