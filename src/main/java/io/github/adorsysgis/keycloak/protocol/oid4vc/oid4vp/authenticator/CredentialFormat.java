package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

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

    private final String identifier;

    CredentialFormat(String identifier) {
        this.identifier = identifier;
    }

    public String getIdentifier() {
        return identifier;
    }

    /**
     * Resolves the enum constant for the given wire-format identifier.
     *
     * @param identifier the format string (e.g. {@code "dc+sd-jwt"}, {@code "mso_mdoc"})
     * @return the matching constant
     * @throws IllegalArgumentException if no constant matches
     */
    public static CredentialFormat fromIdentifier(String identifier) {
        for (CredentialFormat format : values()) {
            if (format.identifier.equals(identifier)) {
                return format;
            }
        }
        throw new IllegalArgumentException(String.format("Unsupported credential format: %s", identifier));
    }
}
