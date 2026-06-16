package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import static org.keycloak.OID4VCConstants.CLAIM_NAME_ISSUER;
import static org.keycloak.OID4VCConstants.CLAIM_NAME_VCT;
import static org.keycloak.sdjwt.ClaimVerifier.ClaimCheck;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql.SdJwtCredentialConstrainer.QuerySpec;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.TrustPolicy;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.sdjwt.IssuerSignedJwtVerificationOpts;
import org.keycloak.sdjwt.consumer.PresentationRequirements;
import org.keycloak.sdjwt.consumer.SimplePresentationDefinition;
import org.keycloak.sdjwt.vp.KeyBindingJwtVerificationOpts;
import org.keycloak.services.Urls;
import org.keycloak.utils.StringUtil;

/**
 * Predefined presentation requirements on the SD-JWT VP token for
 * authentication.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtAuthRequirements {

    private static final Logger logger = Logger.getLogger(SdJwtAuthRequirements.class);

    private List<String> expectedVcts;
    private List<String> requiredClaims;
    private String expectedVctsPattern;
    private final String keycloakIssuerURI;

    private final int kbJwtMaxAllowedAge;
    private final boolean requireNotBeforeClaim;
    private final boolean requireExpirationClaim;
    private boolean verifyIssuerClaim;
    private final boolean enforceRevocationStatus;
    private final boolean requireCryptographicHolderBinding;

    public SdJwtAuthRequirements(KeycloakContext context, AuthenticatorConfigModel authConfig) {
        logger.debugf("Collecting authentication requirements");

        // Reading authenticator configs
        Map<String, String> config =
                (authConfig != null && authConfig.getConfig() != null) ? authConfig.getConfig() : Map.of();

        this.expectedVcts = parseMultiStr(config.getOrDefault(
                SdJwtAuthenticatorFactory.VCT_CONFIG, SdJwtAuthenticatorFactory.VCT_CONFIG_DEFAULT));
        this.requiredClaims = List.of(JsonWebToken.SUBJECT, OAuth2Constants.USERNAME);

        this.kbJwtMaxAllowedAge = Integer.parseInt(config.getOrDefault(
                SdJwtAuthenticatorFactory.KBJWT_MAX_AGE_CONFIG,
                String.valueOf(SdJwtAuthenticatorFactory.KBJWT_MAX_AGE_CONFIG_DEFAULT)));

        this.requireNotBeforeClaim = Boolean.parseBoolean(config.getOrDefault(
                SdJwtAuthenticatorFactory.REQUIRE_NBF_CLAIM_CONFIG,
                String.valueOf(SdJwtAuthenticatorFactory.REQUIRE_NBF_CLAIM_CONFIG_DEFAULT)));

        this.requireExpirationClaim = Boolean.parseBoolean(config.getOrDefault(
                SdJwtAuthenticatorFactory.REQUIRE_EXP_CLAIM_CONFIG,
                String.valueOf(SdJwtAuthenticatorFactory.REQUIRE_EXP_CLAIM_CONFIG_DEFAULT)));

        this.verifyIssuerClaim = Boolean.parseBoolean(config.getOrDefault(
                SdJwtAuthenticatorFactory.VERIFY_ISSUER_CLAIM_CONFIG,
                String.valueOf(SdJwtAuthenticatorFactory.VERIFY_ISSUER_CLAIM_CONFIG_DEFAULT)));

        this.enforceRevocationStatus = Boolean.parseBoolean(config.getOrDefault(
                SdJwtAuthenticatorFactory.ENFORCE_REVOCATION_STATUS_CONFIG,
                String.valueOf(SdJwtAuthenticatorFactory.ENFORCE_REVOCATION_STATUS_CONFIG_DEFAULT)));

        this.requireCryptographicHolderBinding = Boolean.parseBoolean(config.getOrDefault(
                SdJwtAuthenticatorFactory.REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING_CONFIG,
                String.valueOf(SdJwtAuthenticatorFactory.REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING_CONFIG_DEFAULT)));

        this.keycloakIssuerURI = Urls.realmIssuer(
                context.getUri().getBaseUri(), context.getRealm().getName());

        this.expectedVctsPattern = buildExpectedVctsPattern(expectedVcts);
    }

    public SdJwtAuthRequirements(
            KeycloakContext context, AuthenticatorConfigModel authConfig, CredentialRequirement credentialRequirement) {
        this(context, authConfig);
        this.expectedVcts = credentialRequirement.getCredentialTypes();
        this.requiredClaims = credentialRequirement.getClaims();
        if (usesExternalIssuerTrust(credentialRequirement)) {
            this.verifyIssuerClaim = false;
        }
        this.expectedVctsPattern = buildExpectedVctsPattern(expectedVcts);
    }

    public List<String> getExpectedVcts() {
        return expectedVcts;
    }

    public List<String> getRequiredClaims() {
        return requiredClaims;
    }

    public boolean shouldEnforceRevocationStatus() {
        return enforceRevocationStatus;
    }

    public boolean requireCryptographicHolderBinding() {
        return requireCryptographicHolderBinding;
    }

    public PresentationRequirements getPresentationRequirements() {
        var requirements = SimplePresentationDefinition.builder();
        getRequiredClaims().forEach(claim -> requirements.addClaimRequirement(claim, ".*"));

        requirements.addClaimRequirement(CLAIM_NAME_VCT, expectedVctsPattern);
        if (verifyIssuerClaim) {
            requirements.addClaimRequirement(CLAIM_NAME_ISSUER, Pattern.quote("\"%s\"".formatted(keycloakIssuerURI)));
        }
        return requirements.build();
    }

    public QuerySpec getSdJwtQuerySpec() {
        return getSdJwtQuerySpec(requireCryptographicHolderBinding);
    }

    public QuerySpec getSdJwtQuerySpec(boolean requireHolderBinding) {
        return QuerySpec.of(getExpectedVcts(), getRequiredClaims(), requireHolderBinding);
    }

    public IssuerSignedJwtVerificationOpts getIssuerSignedJwtVerificationOpts() {
        return IssuerSignedJwtVerificationOpts.builder()
                .withIatCheck(Integer.MAX_VALUE, true)
                .withNbfCheck(!requireNotBeforeClaim)
                .withExpCheck(!requireExpirationClaim)
                .build();
    }

    public KeyBindingJwtVerificationOpts getKeyBindingJwtVerificationOpts(String nonce, String aud) {
        return buildKeyBindingJwtVerificationOpts(nonce, aud, requireCryptographicHolderBinding);
    }

    public KeyBindingJwtVerificationOpts getKeyBindingJwtVerificationOpts(
            String nonce, String aud, boolean requireCryptographicHolderBinding) {
        return buildKeyBindingJwtVerificationOpts(nonce, aud, requireCryptographicHolderBinding);
    }

    private KeyBindingJwtVerificationOpts buildKeyBindingJwtVerificationOpts(
            String nonce, String aud, boolean requireKeyBinding) {
        ClaimCheck kbJwtAudCheck = buildAudClaimCheck(aud);
        var builder = KeyBindingJwtVerificationOpts.builder()
                .withKeyBindingRequired(requireKeyBinding)
                .withIatCheck(kbJwtMaxAllowedAge)
                .withNbfCheck(!requireNotBeforeClaim)
                .withExpCheck(!requireExpirationClaim)
                .addContentVerifiers(List.of(kbJwtAudCheck));

        if (requireKeyBinding) {
            builder.withNonceCheck(nonce);
        }

        return builder.build();
    }

    private static ClaimCheck buildAudClaimCheck(String expectedKbJwtAud) {
        // Final 1.0 requires using the full Client Identifier, including prefix, in proof bindings.
        return new ClaimCheck(JsonWebToken.AUD, expectedKbJwtAud, String::equals);
    }

    private String buildExpectedVctsPattern(List<String> expectedVcts) {
        return expectedVcts.stream()
                .map(vct -> Pattern.quote("\"" + vct + "\""))
                .collect(Collectors.joining("|", "(", ")"));
    }

    private boolean usesExternalIssuerTrust(CredentialRequirement credentialRequirement) {
        return credentialRequirement.getTrust() != null
                && credentialRequirement.getTrust().stream()
                        .anyMatch(trust -> !TrustPolicy.SELF.equals(trust.getType()));
    }

    private List<String> parseMultiStr(String str) {
        return StringUtil.isBlank(str) ? List.of() : List.of(str.split("\\s*,\\s*"));
    }
}
