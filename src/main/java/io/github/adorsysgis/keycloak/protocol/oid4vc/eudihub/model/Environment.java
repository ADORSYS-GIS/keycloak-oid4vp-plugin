package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model;

import com.fasterxml.jackson.annotation.JsonValue;

/** An environment for which an organization can request EUDI Hub certificates. */
public enum Environment {
    SANDBOX("sandbox"),
    LIVE("live");

    private final String value;

    Environment(String value) {
        this.value = value;
    }

    @JsonValue
    public String value() {
        return value;
    }
}
