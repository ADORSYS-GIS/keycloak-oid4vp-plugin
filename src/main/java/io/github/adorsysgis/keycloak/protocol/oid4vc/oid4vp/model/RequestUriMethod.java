package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Arrays;

/**
 * Request URI retrieval method.
 */
public enum RequestUriMethod {
    GET("get"),
    POST("post");

    private final String value;

    RequestUriMethod(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    public static RequestUriMethod fromValue(String value) {
        return Arrays.stream(RequestUriMethod.values())
                .filter(m -> m.getValue().equals(value))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown request_uri_method: " + value));
    }
}
