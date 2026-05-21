package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import java.util.List;

/**
 * Outcome of a successful {@link VpTokenValidationPipeline} run.
 */
public record VpTokenValidationResult(List<PresentedCredential> presentations) {

    /**
     * Returns the sole presentation when the pipeline validated exactly one.
     *
     * @throws IllegalStateException when multiple credentials were presented
     */
    public PresentedCredential requireSinglePresentation() {
        if (presentations.size() != 1) {
            throw new IllegalStateException(
                    "Expected exactly one presented credential, found: " + presentations.size());
        }
        return presentations.getFirst();
    }

    /**
     * @deprecated use {@link #requireSinglePresentation()}
     */
    @Deprecated
    public PresentedCredential singlePresentation() {
        return requireSinglePresentation();
    }
}
