package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.AuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.VerificationException;

/**
 * Format-specific verification entry point for credentials presented via OpenID4VP.
 *
 * <p>An authenticator orchestrator consults the registered verifiers to verify presented
 * credentials, read identifying claims, and apply supporting credential binding rules.
 * Verifiers are keyed by their supported {@link #format() format identifier}.
 */
public interface CredentialVerifier {

    /**
     * Returns the credential format identifier this verifier supports
     * (e.g. {@code dc+sd-jwt}, {@code mso_mdoc}).
     */
    CredentialFormat format();

    /**
     * Verifies a credential presentation and returns the verified claims.
     *
     * <p>The orchestrator uses the returned claims for binding-rule evaluation and
     * subject/username extraction.
     *
     * @return the verified claims (fully disclosed if needed)
     * @throws VerificationException if cryptographic verification, claim requirements, or trust
     *         policy validation fails
     */
    JsonNode verifyCredential(
            AuthenticationFlowContext context,
            AuthorizationContext authorizationContext,
            AuthRequirements authRequirements,
            CredentialRequirement credential,
            String token)
            throws VerificationException;

    /**
     * Reads claims according to format-specific rules.
     */
    String readClaim(JsonNode claims, String claimName);

    /**
     * Validates {@code transaction_data_hashes} from the presented credential
     * against the verifier's {@code transaction_data} request, if any.
     *
     * <p>Override when the credential format supports embedding transaction data
     * hashes independently of {@link #verifyCredential} (e.g. SD-JWT KB-JWT).
     * Formats where validation depends on verification state (e.g. mso_mdoc)
     * handle this inside {@link #verifyCredential} instead.
     *
     * @param authorizationContext  context containing the request object
     * @param token                 raw credential presentation token
     * @throws VerificationException if the hashes do not match the request
     */
    default void validateTransactionData(AuthorizationContext authorizationContext, String token)
            throws VerificationException {
        // no-op: format does not support standalone transaction data validation
    }
}
