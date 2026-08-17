package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Arrays;

/**
 * Supported flows for presentation during issuance.
 */
public enum PresentationDuringIssuanceMode {

    /**
     * By means of interactive authorization as defined by OpenID4VCI draft 1.1.
     *
     * @see <a href="https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-1_1-wg-draft.html#name-interactive-authorization">
     * Interactive Authorization</a>
     */
    INTERACTIVE_AUTHORIZATION("interactive_authorization"),

    /**
     * By achieving user authentication through OpenID4VP authentication on the Authorization Code Flow.
     * Compatible with OpenID4VCI 1.0.
     *
     * @see <a href="https://bmi.usercontent.opencode.de/eudi-wallet/wallet-development-documentation-public/latest/architecture-concept/03-data-flows/31-eaa-issuance.html#presentation-during-issuance">
     * EAA Issuance - Presentation during Issuance</a>
     * @see <a href="https://github.com/openid/OpenID4VCI/issues/730">
     * Best Practices for Credential Presentation during Issuance with VCI 1.0</a>
     */
    NESTED_OID4VP_FLOW("nested_oid4vp_flow");

    private final String value;

    PresentationDuringIssuanceMode(String value) {
        this.value = value;
    }

    public static PresentationDuringIssuanceMode fromValue(String value) {
        return Arrays.stream(PresentationDuringIssuanceMode.values())
                .filter(m -> m.getValue().equals(value))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        String.format("Unknown PresentationDuringIssuanceMode: %s", value)));
    }

    @JsonValue
    public String getValue() {
        return value;
    }
}
