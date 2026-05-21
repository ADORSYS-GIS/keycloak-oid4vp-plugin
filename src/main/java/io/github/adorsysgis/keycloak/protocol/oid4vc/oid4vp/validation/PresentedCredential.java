package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import org.keycloak.sdjwt.vp.SdJwtVP;

/**
 * A presentation bound to its DCQL credential query after format validation.
 */
public record PresentedCredential(
        String credentialQueryId, Credential credentialQuery, String encodedPresentation, SdJwtVP presentation) {}
