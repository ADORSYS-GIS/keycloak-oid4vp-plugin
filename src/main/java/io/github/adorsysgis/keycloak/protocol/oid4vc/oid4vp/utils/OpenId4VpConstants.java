package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

/**
 * Shared OpenID4VP constants used across request building and validation utilities.
 */
public final class OpenId4VpConstants {

    public static final String REGISTRATION_CERT_FORMAT = "registration_cert";

    /**
     * User-session note set once a Verifiable Presentation has been successfully verified for the
     * session (OID4VCI Interactive Authorization, "presentation during issuance"). It is the carrier
     * that proves the authorization was obtained via a presentation and survives the
     * authorization-code &rarr; access-token exchange up to the credential endpoint.
     */
    public static final String PRESENTATION_VERIFIED_NOTE = "oid4vp.presentation_verified";

    /**
     * Credential-configuration (client-scope) attribute. When {@code true}, the credential MUST NOT
     * be issued unless the session carries {@link #PRESENTATION_VERIFIED_NOTE}. This enforces that the
     * authorization code was obtained via presentation and excludes the pre-authorized code path for
     * such credentials.
     */
    public static final String VC_REQUIRES_PRESENTATION_ATTR = "vc.requires_presentation";

    /**
     * Credential-configuration (client-scope) attribute naming the OpenID4VP authentication profile that
     * MUST be enforced when a presentation is requested during issuance of this credential. When present,
     * it overrides any client-supplied {@code profile_id} at the Authorization Challenge Endpoint so the
     * wallet cannot pick a profile without binding rules and thereby bypass the identity match.
     */
    public static final String VC_PRESENTATION_PROFILE_ID_ATTR = "vc.presentation_profile_id";

    private OpenId4VpConstants() {}
}
