package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import java.util.List;

/**
 * Resolves the format validator for a DCQL credential query.
 */
final class PresentationFormatValidators {

    private final List<PresentationFormatValidator> validators;

    PresentationFormatValidators(List<PresentationFormatValidator> validators) {
        this.validators = List.copyOf(validators);
    }

    PresentationFormatValidator requireValidatorFor(Credential credentialQuery) throws VpTokenValidationException {
        return validators.stream()
                .filter(validator -> validator.supports(credentialQuery))
                .findFirst()
                .orElseThrow(() -> new VpTokenValidationException(
                        VpTokenValidationException.Phase.FORMAT,
                        "Unsupported credential format: " + credentialQuery.getFormat()));
    }
}
