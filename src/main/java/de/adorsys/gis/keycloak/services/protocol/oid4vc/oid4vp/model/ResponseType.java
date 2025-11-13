package de.adorsys.gis.keycloak.services.protocol.oid4vc.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * OpenID4VP Response Types
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#name-response">
 * Authorization Response</a>
 */
public enum ResponseType {

    CODE("code"),
    VP_TOKEN("vp_token"),
    ID_TOKEN("id_token"),
    VP_TOKEN_ID_TOKEN("vp_token id_token");

    private final String value;

    ResponseType(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }
}
