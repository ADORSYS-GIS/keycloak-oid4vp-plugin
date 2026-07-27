package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import java.util.List;
import org.keycloak.common.VerificationException;

/**
 * Format-specific DCQL support for presentation pre-validation and verifier metadata.
 *
 * <p>Each capability owns VP format metadata advertisement and DCQL presentation validation
 * for responses keyed by credential query id.
 */
public interface DcqlCredentialCapability {

    /**
     * Returns the DCQL credential format identifier handled by this capability.
     *
     * <p>The identifier must be non-blank and unique within {@link DcqlCredentialCapabilities}.
     */
    String format();

    /**
     * Indicates whether this capability implements the optional quick presentation check.
     *
     * <p>When this returns {@code false}, callers skip {@link #validatePresentation(Credential, String)}
     * and continue with the full credential verification pipeline.
     */
    boolean supportsPresentationPreValidation();

    /**
     * Checks whether a presented token satisfies its matching credential query.
     *
     * <p>This method is called only when {@link #supportsPresentationPreValidation()} returns {@code true}.
     * It is an early query-satisfaction check and does not replace cryptographic or trust verification.
     *
     * @param credential the matching credential query generated for the authorization request
     * @param presentedToken token in the representation expected by this credential format
     * @throws VerificationException when the presentation does not satisfy the credential query
     * @throws IllegalArgumentException when the presented token cannot be parsed
     */
    void validatePresentation(Credential credential, String presentedToken) throws VerificationException;

    /**
     * Adds the supported algorithms for this credential format to the supplied verifier metadata aggregate.
     *
     * @param vpFormat mutable VP-format metadata to which this capability contributes
     * @param signatureAlgorithms signature algorithm identifiers supported by the verifier
     */
    void contributeVpFormatsSupported(ClientMetadata.VpFormat vpFormat, List<String> signatureAlgorithms);
}
