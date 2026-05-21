package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import org.keycloak.models.KeycloakSession;

/**
 * Inputs required to validate a returned {@code vp_token} for one authorization request.
 */
public record VpTokenValidationContext(
        KeycloakSession session,
        RequestObject requestObject,
        SdJwtAuthRequirements authRequirements,
        String nonce,
        String audience) {}
