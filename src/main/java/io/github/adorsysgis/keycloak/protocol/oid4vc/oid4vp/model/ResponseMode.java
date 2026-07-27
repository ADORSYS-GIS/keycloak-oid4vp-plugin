package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * OpenID4VP Response Modes
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-authorization-request">
 * Authorization Request</a>
 */
public enum ResponseMode {
    FRAGMENT("fragment"),
    FORM_POST("form_post"),
    DIRECT_POST("direct_post"),
    DIRECT_POST_JWT("direct_post.jwt"),
    IA_POST("ia_post"),
    IA_POST_JWT("ia_post.jwt"),
    QUERY("query");

    private final String value;

    ResponseMode(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    /**
     * Whether this response mode requires the OpenID4VP Authorization Response to be encrypted
     * (the {@code .jwt} variants {@code direct_post.jwt} and {@code ia_post.jwt}).
     */
    public boolean isEncrypted() {
        return this == DIRECT_POST_JWT || this == IA_POST_JWT;
    }

    public static ResponseMode fromValue(String value) {
        for (ResponseMode mode : ResponseMode.values()) {
            if (mode.value.equalsIgnoreCase(value)) {
                return mode;
            }
        }

        throw new IllegalArgumentException("Unknown response mode: " + value);
    }
}
