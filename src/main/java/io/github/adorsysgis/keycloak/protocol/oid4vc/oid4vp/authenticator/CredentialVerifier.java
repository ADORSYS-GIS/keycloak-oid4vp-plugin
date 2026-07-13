package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import com.fasterxml.jackson.databind.JsonNode;
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
            CredentialRequirement credential,
            String token,
            boolean requireCryptographicHolderBinding)
            throws VerificationException;

    /**
     * Reads claims according to format-specific rules.
     */
    String readClaim(JsonNode claims, String claimName);
}
