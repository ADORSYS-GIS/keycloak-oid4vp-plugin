package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Locale;

/** Lifecycle status the EUDI Hub reports for an access certificate. */
public enum AccessCertificateStatus {
    VALID("valid"),
    EXPIRED("expired"),
    REVOKED("revoked");

    private final String value;

    AccessCertificateStatus(String value) {
        this.value = value;
    }

    /** The value used by the EUDI Hub API. */
    @JsonValue
    public String value() {
        return value;
    }

    @JsonCreator
    public static AccessCertificateStatus from(String value) {
        if (value == null) {
            return null;
        }

        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "valid" -> VALID;
            case "expired" -> EXPIRED;
            case "revoked" -> REVOKED;
            default -> throw new IllegalArgumentException("Unknown EUDI Hub access certificate status: " + value);
        };
    }
}
