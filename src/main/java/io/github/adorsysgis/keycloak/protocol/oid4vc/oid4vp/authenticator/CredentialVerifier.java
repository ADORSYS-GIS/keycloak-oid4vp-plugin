package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
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
     * Returns a fresh, independent verifier for a single authentication run so that
     * per-verification state is not shared across sessions.
     */
    CredentialVerifier copy();

    /**
     * Verifies a credential presentation and returns its verified issuer and claims.
     *
     * <p>The orchestrator uses the returned claims for binding-rule evaluation and
     * subject extraction.
     *
     * @return the verified credential result
     * @throws VerificationException if cryptographic verification, claim requirements, or trust
     *         policy validation fails
     */
    VerifiedCredential verifyCredential(
            OID4VPAuthenticator.Context context, CredentialRequirement credentialReq, String token)
            throws VerificationException;

    /**
     * Validates {@code transaction_data_hashes} from the presented credential
     * against the verifier's {@code transaction_data} request, if any.
     *
     * <p>Called by the authenticator after {@link #verifyCredential} succeeds.
     * The verifier may use state cached during {@link #verifyCredential} to
     * perform the validation (e.g. a post-verification {@code MdocVerificationContext}).
     *
     * @param context  authenticator context for accessing transaction data
     * @param token    raw credential presentation token
     * @throws VerificationException if the hashes do not match the request
     */
    void validateTransactionData(OID4VPAuthenticator.Context context, String token) throws VerificationException;

    /**
     * Reads claims according to format-specific rules.
     */
    String readClaim(JsonNode claims, String claimName);
}
