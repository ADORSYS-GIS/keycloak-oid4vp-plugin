package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import static org.keycloak.OID4VCConstants.CLAIM_NAME_ISSUER;
import static org.keycloak.OID4VCConstants.CLAIM_NAME_VCT;
import static org.keycloak.sdjwt.ClaimVerifier.ClaimCheck;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
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

    private final List<String> expectedVcts;
    private final String expectedVctsPattern;
    private final String keycloakIssuerURI;

    private final int kbJwtMaxAllowedAge;
    private final boolean requireNotBeforeClaim;
    private final boolean requireExpirationClaim;
    private final boolean verifyIssuerClaim;
    private final boolean enforceRevocationStatus;

    public SdJwtAuthRequirements(KeycloakContext context, AuthenticatorConfigModel authConfig) {
        logger.debugf("Collecting authentication requirements");

        // Reading authenticator configs
        Map<String, String> config =
                (authConfig != null && authConfig.getConfig() != null) ? authConfig.getConfig() : Map.of();

        this.expectedVcts = parseMultiStr(config.getOrDefault(
                SdJwtAuthenticatorFactory.VCT_CONFIG, SdJwtAuthenticatorFactory.VCT_CONFIG_DEFAULT));

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

        this.keycloakIssuerURI = Urls.realmIssuer(
                context.getUri().getBaseUri(), context.getRealm().getName());

        this.expectedVctsPattern = expectedVcts.stream()
                .map(vct -> Pattern.quote("\"" + vct + "\""))
                .collect(Collectors.joining("|", "(", ")"));
    }

    public List<String> getExpectedVcts() {
        return expectedVcts;
    }

    public List<String> getRequiredClaims() {
        // A subject is required so we can recover the user by stable identifier
        // A username is required so we can cross-check the presented user
        return List.of(JsonWebToken.SUBJECT, OAuth2Constants.USERNAME);
    }

    public boolean shouldEnforceRevocationStatus() {
        return enforceRevocationStatus;
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

    /**
     * Builds presentation requirements from the issued DCQL credential query (OpenID4VP §8.6).
     */
    public PresentationRequirements getPresentationRequirementsForCredential(Credential credentialQuery) {
        var requirements = SimplePresentationDefinition.builder();

        getRequiredClaims().forEach(claim -> requirements.addClaimRequirement(claim, ".*"));

        if (credentialQuery.getClaims() != null) {
            for (Claim claim : credentialQuery.getClaims()) {
                if (claim.getPath() == null || claim.getPath().isEmpty()) {
                    continue;
                }
                String claimName = claim.getPath().getLast();
                requirements.addClaimRequirement(claimName, ".*");
            }
        }

        String vctPattern = vctPatternFromMeta(credentialQuery.getMeta());
        if (vctPattern != null) {
            requirements.addClaimRequirement(CLAIM_NAME_VCT, vctPattern);
        } else {
            requirements.addClaimRequirement(CLAIM_NAME_VCT, expectedVctsPattern);
        }

        if (verifyIssuerClaim) {
            requirements.addClaimRequirement(CLAIM_NAME_ISSUER, Pattern.quote("\"%s\"".formatted(keycloakIssuerURI)));
        }

        return requirements.build();
    }

    private String vctPatternFromMeta(Meta meta) {
        if (meta == null || meta.getVctValues() == null || meta.getVctValues().isEmpty()) {
            return null;
        }
        return meta.getVctValues().stream()
                .map(vct -> Pattern.quote("\"" + vct + "\""))
                .collect(Collectors.joining("|", "(", ")"));
    }

    public SdJwtCredentialConstrainer.QueryMap getSdJwtQueryMap() {
        return new SdJwtCredentialConstrainer.QueryMap(getExpectedVcts(), getRequiredClaims());
    }

    public IssuerSignedJwtVerificationOpts getIssuerSignedJwtVerificationOpts() {
        return IssuerSignedJwtVerificationOpts.builder()
                .withIatCheck(Integer.MAX_VALUE, true)
                .withNbfCheck(!requireNotBeforeClaim)
                .withExpCheck(!requireExpirationClaim)
                .build();
    }

    public KeyBindingJwtVerificationOpts getKeyBindingJwtVerificationOpts(String nonce, String aud) {
        ClaimCheck kbJwtAudCheck = buildAudClaimCheck(aud);
        return KeyBindingJwtVerificationOpts.builder()
                .withKeyBindingRequired(true)
                .withIatCheck(kbJwtMaxAllowedAge)
                .withNonceCheck(nonce)
                .withNbfCheck(!requireNotBeforeClaim)
                .withExpCheck(!requireExpirationClaim)
                .addContentVerifiers(List.of(kbJwtAudCheck))
                .build();
    }

    private static ClaimCheck buildAudClaimCheck(String expectedKbJwtAud) {
        // Final 1.0 requires using the full Client Identifier, including prefix, in proof bindings.
        return new ClaimCheck(JsonWebToken.AUD, expectedKbJwtAud, String::equals);
    }

    private List<String> parseMultiStr(String str) {
        return StringUtil.isBlank(str) ? List.of() : List.of(str.split("\\s*,\\s*"));
    }
}
