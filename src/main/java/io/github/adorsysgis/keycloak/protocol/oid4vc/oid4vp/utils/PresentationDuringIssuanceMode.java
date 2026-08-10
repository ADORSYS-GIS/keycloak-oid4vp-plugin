package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

import java.util.Locale;

/**
 * The ways a credential can require a Verifiable Presentation prior to issuance (OID4VCI Interactive
 * Authorization). A credential configuration selects which of these it supports through the
 * {@code vc.requires_presentation} client-scope attribute, whose value may be a single mode, a list,
 * or the legacy boolean {@code true} (meaning every mode).
 */
public enum PresentationDuringIssuanceMode {

    /** Wallet-/protocol-driven interactive authorization (OID4VCI §6, Authorization Challenge Endpoint). */
    INTERACTIVE_AUTHORIZATION("interactive_authorization"),

    /** Browser-/IdP-driven nested OpenID4VP flow triggered from the OIDC authorization request. */
    NESTED_OID4VP_FLOW("nested_oid4vp_flow");

    private final String wireValue;

    PresentationDuringIssuanceMode(String wireValue) {
        this.wireValue = wireValue;
    }

    public String wireValue() {
        return wireValue;
    }

    @Override
    public String toString() {
        return wireValue;
    }

    /**
     * Parses a single wire value into its mode, or {@code null} when the value matches no known mode.
     * Both the wire value and the enum constant name (case-insensitive) are accepted.
     */
    public static PresentationDuringIssuanceMode fromWireValue(String value) {
        if (value == null) {
            return null;
        }
        String candidate = value.trim();
        if (candidate.isEmpty()) {
            return null;
        }
        for (PresentationDuringIssuanceMode mode : values()) {
            if (mode.wireValue.equalsIgnoreCase(candidate)
                    || mode.name().toLowerCase(Locale.ROOT).equals(candidate.toLowerCase(Locale.ROOT))) {
                return mode;
            }
        }
        return null;
    }
}
