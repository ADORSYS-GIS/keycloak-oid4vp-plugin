package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum CredentialRole {
    PRIMARY("primary"),
    SUPPORTING("supporting");

    private final String value;

    CredentialRole(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    @JsonCreator
    public static CredentialRole fromValue(String value) {
        if (value == null) {
            return SUPPORTING;
        }

        for (CredentialRole role : values()) {
            if (role.value.equalsIgnoreCase(value)) {
                return role;
            }
        }

        throw new IllegalArgumentException("Unsupported credential role: " + value);
    }
}
