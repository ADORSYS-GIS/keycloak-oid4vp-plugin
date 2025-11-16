package de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model.dto;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Potential errors as authorization responses are processed.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public enum ProcessingError {

    AUTH_CONTEXT_CLOSED("auth_context_closed"),
    INVALID_PRESENTATION_SUBMISSION("invalid_presentation_submission"),
    INVALID_VP_TOKEN("invalid_vp_token"),
    VP_TOKEN_AUTH_ERROR("vp_token_auth_error");

    private final String error;

    ProcessingError(String error) {
        this.error = error;
    }

    @JsonValue
    public String getErrorString() {
        return error;
    }
}
