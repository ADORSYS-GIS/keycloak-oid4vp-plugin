package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import java.util.List;

/**
 * Outcome of a successful {@link VpTokenValidationPipeline} run.
 */
public record VpTokenValidationResult(List<PresentedCredential> presentations) {

    /**
     * Returns the sole presentation for user-login flows that authenticate with one SD-JWT VP.
     *
     * @throws VpTokenValidationException when more than one credential was presented after validation
     */
    public PresentedCredential requireSinglePresentation() throws VpTokenValidationException {
        if (presentations.size() != 1) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.STRUCTURE,
                    "User authentication requires exactly one presented credential, found: " + presentations.size());
        }
        return presentations.getFirst();
    }
}
