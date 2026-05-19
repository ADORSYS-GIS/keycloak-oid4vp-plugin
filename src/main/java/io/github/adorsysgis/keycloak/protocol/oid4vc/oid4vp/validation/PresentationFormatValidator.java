package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import org.keycloak.sdjwt.vp.SdJwtVP;

/**
 * Format-specific verifier checks for one DCQL credential query (OpenID4VP §8.6 step 1–5).
 */
public interface PresentationFormatValidator {

    boolean supports(Credential credentialQuery);

    ValidatedPresentation validate(
            String encodedPresentation, Credential credentialQuery, VpTokenValidationContext context)
            throws VpTokenValidationException;

    /** Normalized presentation encoding and parsed form. */
    record ValidatedPresentation(String presentationString, SdJwtVP presentation) {}
}
