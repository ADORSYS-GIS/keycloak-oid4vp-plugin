package de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * OpenID4VP Response Modes
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#name-authorization-request">
 * Authorization Request</a>
 */
public enum ResponseMode {
    FRAGMENT("fragment"),
    FORM_POST("form_post"),
    DIRECT_POST("direct_post"),
    DIRECT_POST_JWT("direct_post.jwt"),
    QUERY("query");

    private final String value;

    ResponseMode(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }
}
