package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.utils.StringUtil;

/**
 * Access configurations that modulate the verification of presented credentials.
 * <p></p>
 * Read full descriptions of configurations in {@link OID4VPAuthenticatorFactory}.
 * <p></p>
 * This class is the verification-side counterpart to {@link VerifierConfig}: it loads
 * the subset of authenticator config properties that drive credential-format-specific
 * authentication requirements (e.g. holder-binding proof age, nbf/exp enforcement,
 * issuer-claim verification, mDoc session-transcript fallback, revocation status).
 */
public class AuthRequirements {

    private static final Logger logger = Logger.getLogger(AuthRequirements.class);

    private final List<String> credentialTypes;
    private final int holderBindingProofMaxAge;
    private final boolean requireNotBeforeClaim;
    private final boolean requireExpirationClaim;
    private final boolean verifyIssuerClaim;
    private final boolean fallbackToIsoSpecSessionTranscript;
    private final boolean enforceRevocationStatus;
    private final boolean requireCryptographicHolderBinding;

    public AuthRequirements(AuthenticatorConfigModel authConfig) {
        logger.debugf("Collecting authentication requirement properties");

        Map<String, String> config =
                (authConfig != null && authConfig.getConfig() != null) ? authConfig.getConfig() : Map.of();

        this.credentialTypes = parseMultiStr(config.getOrDefault(
                OID4VPAuthenticatorFactory.CREDENTIAL_TYPES_CONFIG,
                OID4VPAuthenticatorFactory.CREDENTIAL_TYPES_CONFIG_DEFAULT));

        this.requireCryptographicHolderBinding = Boolean.parseBoolean(config.getOrDefault(
                OID4VPAuthenticatorFactory.REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING_CONFIG,
                String.valueOf(OID4VPAuthenticatorFactory.REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING_CONFIG_DEFAULT)));

        this.holderBindingProofMaxAge = Integer.parseInt(config.getOrDefault(
                OID4VPAuthenticatorFactory.HOLDER_BINDING_PROOF_MAX_AGE_CONFIG,
                String.valueOf(OID4VPAuthenticatorFactory.HOLDER_BINDING_PROOF_MAX_AGE_CONFIG_DEFAULT)));

        this.requireNotBeforeClaim = Boolean.parseBoolean(config.getOrDefault(
                OID4VPAuthenticatorFactory.REQUIRE_NBF_CLAIM_CONFIG,
                String.valueOf(OID4VPAuthenticatorFactory.REQUIRE_NBF_CLAIM_CONFIG_DEFAULT)));

        this.requireExpirationClaim = Boolean.parseBoolean(config.getOrDefault(
                OID4VPAuthenticatorFactory.REQUIRE_EXP_CLAIM_CONFIG,
                String.valueOf(OID4VPAuthenticatorFactory.REQUIRE_EXP_CLAIM_CONFIG_DEFAULT)));

        this.verifyIssuerClaim = Boolean.parseBoolean(config.getOrDefault(
                OID4VPAuthenticatorFactory.VERIFY_ISSUER_CLAIM_CONFIG,
                String.valueOf(OID4VPAuthenticatorFactory.VERIFY_ISSUER_CLAIM_CONFIG_DEFAULT)));

        this.fallbackToIsoSpecSessionTranscript = Boolean.parseBoolean(config.getOrDefault(
                OID4VPAuthenticatorFactory.FALLBACK_TO_ISO_SPEC_SESSION_TRANSCRIPT_CONFIG,
                String.valueOf(OID4VPAuthenticatorFactory.FALLBACK_TO_ISO_SPEC_SESSION_TRANSCRIPT_CONFIG_DEFAULT)));

        this.enforceRevocationStatus = Boolean.parseBoolean(config.getOrDefault(
                OID4VPAuthenticatorFactory.ENFORCE_REVOCATION_STATUS_CONFIG,
                String.valueOf(OID4VPAuthenticatorFactory.ENFORCE_REVOCATION_STATUS_CONFIG_DEFAULT)));
    }

    public List<String> getCredentialTypes() {
        return credentialTypes;
    }

    public boolean shouldRequireCryptographicHolderBinding() {
        return requireCryptographicHolderBinding;
    }

    public int getHolderBindingProofMaxAge() {
        return holderBindingProofMaxAge;
    }

    public boolean shouldRequireNotBeforeClaim() {
        return requireNotBeforeClaim;
    }

    public boolean shouldRequireExpirationClaim() {
        return requireExpirationClaim;
    }

    public boolean shouldVerifyIssuerClaim() {
        return verifyIssuerClaim;
    }

    public boolean shouldFallbackToIsoSpecSessionTranscript() {
        return fallbackToIsoSpecSessionTranscript;
    }

    public boolean shouldEnforceRevocationStatus() {
        return enforceRevocationStatus;
    }

    private static List<String> parseMultiStr(String str) {
        return StringUtil.isBlank(str) ? List.of() : List.of(str.split("\\s*,\\s*"));
    }
}
