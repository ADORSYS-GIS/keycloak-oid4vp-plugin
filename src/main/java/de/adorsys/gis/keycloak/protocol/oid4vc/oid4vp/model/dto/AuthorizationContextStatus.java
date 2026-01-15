package de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model.dto;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Statuses of an OpenID4VP authorization context, either OPEN or CLOSED.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public enum AuthorizationContextStatus {
    PENDING("pending"),
    SUCCESS("success"),
    ERROR("error");

    private final String status;

    AuthorizationContextStatus(String status) {
        this.status = status;
    }

    @JsonValue
    public String getStatus() {
        return status;
    }
}
