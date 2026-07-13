package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import com.fasterxml.jackson.annotation.JsonValue;
import org.keycloak.VCFormat;

/**
 * Credential format identifiers supported by the OpenID4VP authenticator.
 *
 * <p>Each constant carries the wire-format string used in DCQL credential queries
 * and as the key in the {@link CredentialVerifier} handler map.
 */
public enum CredentialFormat {

    /** SD-JWT VC — {@code dc+sd-jwt}. */
    SD_JWT_VC(VCFormat.SD_JWT_VC),

    /** ISO/IEC 18013-5 mDoc — {@code mso_mdoc}. */
    MSO_MDOC("mso_mdoc");

    private final String value;

    CredentialFormat(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    /**
     * Resolves the enum constant for the given wire-format identifier.
     *
     * @param value the format string (e.g. {@code "dc+sd-jwt"}, {@code "mso_mdoc"})
     * @return the matching constant
     * @throws IllegalArgumentException if no constant matches
     */
    public static CredentialFormat fromValue(String value) {
        for (CredentialFormat format : values()) {
            if (format.value.equals(value)) {
                return format;
            }
        }
        throw new IllegalArgumentException(String.format("Unsupported credential format: %s", value));
    }
}
