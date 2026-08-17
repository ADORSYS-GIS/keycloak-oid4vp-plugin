package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode;

/**
 * Shared OpenID4VP constants used across request building and validation utilities.
 */
public final class OpenId4VpConstants {

    public static final String REGISTRATION_CERT_FORMAT = "registration_cert";

    /**
     * User-session note set once a Verifiable Presentation has been successfully verified
     * as part of user authentication. The note is the {@link PresentationDuringIssuanceMode}
     * through which the presentation was obtained. Checks for enforcing the requirement of
     * presentation during issuance at the credential endpoint rely on this user-session note.
     */
    public static final String PRESENTATION_VERIFIED_NOTE = "oid4vp.presentation_verified";

    private OpenId4VpConstants() {}
}
