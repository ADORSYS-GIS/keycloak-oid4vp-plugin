package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

/**
 * Shared OpenID4VP constants used across request building and validation utilities.
 */
public final class OpenId4VpConstants {

    public static final String REGISTRATION_CERT_FORMAT = "registration_cert";

    /**
     * User-session note set once a Verifiable Presentation has been successfully verified for the
     * session (OID4VCI Interactive Authorization, "presentation during issuance"). Its value is the
     * {@link PresentationDuringIssuanceMode#wireValue() wire value} of the mode through which the
     * presentation was obtained, e.g. {@code interactive_authorization} or {@code nested_oid4vp_flow}.
     * It proves the authorization was obtained via a presentation, annotates the exact mode, and
     * survives the authorization-code &rarr; access-token exchange up to the credential endpoint.
     */
    public static final String PRESENTATION_VERIFIED_NOTE = "oid4vp.presentation_verified";

    private OpenId4VpConstants() {}
}
