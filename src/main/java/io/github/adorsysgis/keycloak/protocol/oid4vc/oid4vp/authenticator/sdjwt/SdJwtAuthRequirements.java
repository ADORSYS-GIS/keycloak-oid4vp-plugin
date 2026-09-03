package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.sdjwt;

import static org.keycloak.OID4VCConstants.CLAIM_NAME_ISSUER;
import static org.keycloak.OID4VCConstants.CLAIM_NAME_VCT;
import static org.keycloak.sdjwt.ClaimVerifier.ClaimCheck;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.AuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.TrustPolicy;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakContext;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.sdjwt.IssuerSignedJwtVerificationOpts;
import org.keycloak.sdjwt.consumer.PresentationRequirements;
import org.keycloak.sdjwt.consumer.SimplePresentationDefinition;
import org.keycloak.sdjwt.vp.KeyBindingJwtVerificationOpts;
import org.keycloak.services.Urls;

/**
 * Presentation requirements on SD-JWT VP tokens for authentication
 */
public class SdJwtAuthRequirements {

    private static final Logger logger = Logger.getLogger(SdJwtAuthRequirements.class);

    private final AuthRequirements authRequirements;

    private final List<String> expectedVcts;
    private final List<String> requiredClaims;
    private final String expectedVctsPattern;
    private final String keycloakIssuerURI;

    private final CredentialRequirement credentialRequirement;

    public SdJwtAuthRequirements(
            KeycloakContext context, AuthRequirements authRequirements, CredentialRequirement credentialRequirement) {
        logger.debugf("Collecting SD-JWT authentication requirements");

        this.authRequirements = authRequirements;
        this.credentialRequirement = credentialRequirement;
        this.requiredClaims = credentialRequirement.getClaims();

        this.expectedVcts = credentialRequirement.getCredentialTypes();
        this.expectedVctsPattern = buildExpectedVctsPattern(expectedVcts);
        this.keycloakIssuerURI = Urls.realmIssuer(
                context.getUri().getBaseUri(), context.getRealm().getName());
    }

    public boolean shouldRequireCryptographicHolderBinding() {
        return authRequirements.shouldRequireCryptographicHolderBinding();
    }

    public List<String> getExpectedVcts() {
        return expectedVcts;
    }

    public List<String> getRequiredClaims() {
        return requiredClaims;
    }

    public boolean shouldEnforceRevocationStatus() {
        return authRequirements.shouldEnforceRevocationStatus();
    }

    public boolean shouldAllowMissingStatusClaim() {
        return authRequirements.shouldAllowMissingStatusClaim();
    }

    private boolean shouldVerifyIssuerClaim() {
        return authRequirements.shouldVerifyIssuerClaim() && !usesExternalIssuerTrust(credentialRequirement);
    }

    public PresentationRequirements getPresentationRequirements() {
        var requirements = SimplePresentationDefinition.builder();
        getRequiredClaims().forEach(claim -> requirements.addClaimRequirement(claim, ".*"));

        requirements.addClaimRequirement(CLAIM_NAME_VCT, expectedVctsPattern);
        if (shouldVerifyIssuerClaim()) {
            requirements.addClaimRequirement(CLAIM_NAME_ISSUER, Pattern.quote("\"%s\"".formatted(keycloakIssuerURI)));
        }
        return requirements.build();
    }

    public IssuerSignedJwtVerificationOpts getIssuerSignedJwtVerificationOpts() {
        return IssuerSignedJwtVerificationOpts.builder()
                .withIatCheck(Integer.MAX_VALUE, true)
                .withNbfCheck(!authRequirements.shouldRequireNotBeforeClaim())
                .withExpCheck(!authRequirements.shouldRequireExpirationClaim())
                .build();
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
                .withIatCheck(authRequirements.getHolderBindingProofMaxAge())
                .withNbfCheck(!authRequirements.shouldRequireNotBeforeClaim())
                .withExpCheck(!authRequirements.shouldRequireExpirationClaim())
                .addContentVerifiers(List.of(kbJwtAudCheck));

        if (requireKeyBinding) {
            builder.withNonceCheck(nonce);
        }

        return builder.build();
    }

    private static ClaimCheck buildAudClaimCheck(String expectedKbJwtAud) {
        // TODO: Strict matching is disabled for compatibility with the German wallet
        // Final 1.0 requires using the full Client Identifier, including prefix, in proof bindings.
        // return new ClaimCheck(JsonWebToken.AUD, expectedKbJwtAud, String::equals);

        // Regex matching for aud claim check.
        // Tolerates prefix duplication for compatibility with German wallet.

        int colonIndex = expectedKbJwtAud.indexOf(':');
        String regex;
        if (colonIndex > 0) {
            String prefix = expectedKbJwtAud.substring(0, colonIndex);
            // Accept: prefix:aud or prefix:prefix:aud
            regex = String.format("(%s:)?%s", Pattern.quote(prefix), Pattern.quote(expectedKbJwtAud));
        } else {
            // No prefix, accept as is
            regex = Pattern.quote(expectedKbJwtAud);
        }

        Pattern expectedPattern = Pattern.compile(regex);

        return new ClaimCheck(JsonWebToken.AUD, expectedKbJwtAud, (expectedAud, aud) -> expectedPattern
                .matcher(aud)
                .matches());
    }

    private String buildExpectedVctsPattern(List<String> expectedVcts) {
        return expectedVcts.stream()
                .map(vct -> Pattern.quote("\"" + vct + "\""))
                .collect(Collectors.joining("|", "(", ")"));
    }

    private boolean usesExternalIssuerTrust(CredentialRequirement credentialRequirement) {
        return Optional.ofNullable(credentialRequirement)
                .map(CredentialRequirement::getTrust)
                .map(trusts -> trusts.stream().anyMatch(t -> !TrustPolicy.SELF.equals(t.getType())))
                .orElse(false);
    }
}
