package de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationDefinition;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.SdJwtCredentialBuilder;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.sdjwt.IssuerSignedJwtVerificationOpts;
import org.keycloak.sdjwt.consumer.PresentationRequirements;
import org.keycloak.sdjwt.consumer.SimplePresentationDefinition;
import org.keycloak.sdjwt.vp.KeyBindingJwtVerificationOpts;
import org.keycloak.utils.StringUtil;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.keycloak.sdjwt.ClaimVerifier.ClaimCheck;

/**
 * Predefined presentation requirements on the SD-JWT VP token for
 * authentication.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtAuthRequirements {

        private static final Logger logger = Logger.getLogger(SdJwtAuthRequirements.class);

        private final SdJwtCredentialConstrainer sdJwtCredentialConstrainer;
        private final String keycloakIssuerURI;
        private final ClaimCheck kbJwtAudCheck;

        private final List<String> expectedVcts;
        private final String expectedVctsPattern;

        private final int kbJwtMaxAllowedAge;
        private final boolean requireNotBeforeClaim;
        private final boolean requireExpirationClaim;
        private final boolean enforceRevocationStatus;

        public SdJwtAuthRequirements(KeycloakContext context, AuthenticatorConfigModel authConfig) {
                logger.debugf("Collecting authentication requirements");
                this.sdJwtCredentialConstrainer = new SdJwtCredentialConstrainer();

                // We'll need to enforce that only credentials produced by and for this audience
                // pass through.
                // The audience is the client ID of the verifier, but some wallets prepend a
                // scheme.
                this.keycloakIssuerURI = OID4VCIssuerWellKnownProvider.getIssuer(context);
                String kbJwtAud = context.getUri().getBaseUri().getHost();
                this.kbJwtAudCheck = buildAudClaimCheck(kbJwtAud);

                // Reading authenticator configs
                Map<String, String> config = (authConfig != null && authConfig.getConfig() != null)
                                ? authConfig.getConfig()
                                : Map.of();

                this.expectedVcts = parseMultiStr(config.getOrDefault(
                                SdJwtAuthenticatorFactory.VCT_CONFIG,
                                SdJwtAuthenticatorFactory.VCT_CONFIG_DEFAULT));

                this.kbJwtMaxAllowedAge = Integer.parseInt(config.getOrDefault(
                                SdJwtAuthenticatorFactory.KBJWT_MAX_AGE_CONFIG,
                                String.valueOf(SdJwtAuthenticatorFactory.KBJWT_MAX_AGE_CONFIG_DEFAULT)));

                this.requireNotBeforeClaim = Boolean.parseBoolean(config.getOrDefault(
                                SdJwtAuthenticatorFactory.REQUIRE_NBF_CLAIM_CONFIG,
                                String.valueOf(SdJwtAuthenticatorFactory.REQUIRE_NBF_CLAIM_CONFIG_DEFAULT)));

                this.requireExpirationClaim = Boolean.parseBoolean(config.getOrDefault(
                                SdJwtAuthenticatorFactory.REQUIRE_EXP_CLAIM_CONFIG,
                                String.valueOf(SdJwtAuthenticatorFactory.REQUIRE_EXP_CLAIM_CONFIG_DEFAULT)));

                this.enforceRevocationStatus = Boolean.parseBoolean(config.getOrDefault(
                                SdJwtAuthenticatorFactory.ENFORCE_REVOCATION_STATUS_CONFIG,
                                String.valueOf(SdJwtAuthenticatorFactory.ENFORCE_REVOCATION_STATUS_CONFIG_DEFAULT)));

                this.expectedVctsPattern = expectedVcts.stream()
                                .map(vct -> Pattern.quote("\"" + vct + "\""))
                                .collect(Collectors.joining("|", "(", ")"));
        }

        public List<String> getExpectedVcts() {
                return expectedVcts;
        }

        public List<String> getRequiredClaims() {
                // A username field is required so as to reliably recover
                // the user associated with the presented credential
                return List.of(OAuth2Constants.USERNAME);
        }

        public boolean shouldEnforceRevocationStatus() {
                return enforceRevocationStatus;
        }

        /**
         * Constructs presentation definition as supported by keycloak-core.
         */
        public PresentationRequirements getPresentationDefinition() {
                var definition = SimplePresentationDefinition.builder();
                getRequiredClaims().forEach(claim -> definition.addClaimRequirement(claim, ".*"));

                return definition
                                .addClaimRequirement(
                                                SdJwtCredentialBuilder.VERIFIABLE_CREDENTIAL_TYPE_CLAIM,
                                                expectedVctsPattern)
                                .addClaimRequirement(
                                                SdJwtCredentialBuilder.ISSUER_CLAIM,
                                                Pattern.quote("\"%s\"".formatted(keycloakIssuerURI)))
                                .build();
        }

        /**
         * Constructs presentation definition in the DIF presentation exchange format.
         */
        public PresentationDefinition getDIFPresentationDefinition() {
                return sdJwtCredentialConstrainer.generatePresentationDefinition(
                                getExpectedVcts(),
                                getRequiredClaims());
        }

        public IssuerSignedJwtVerificationOpts getIssuerSignedJwtVerificationOpts() {
                return IssuerSignedJwtVerificationOpts.builder()
                                .withIatCheck(Integer.MAX_VALUE, true)
                                .withNbfCheck(!requireNotBeforeClaim)
                                .withExpCheck(!requireExpirationClaim)
                                .build();
        }

        public KeyBindingJwtVerificationOpts getKeyBindingJwtVerificationOpts(String nonce) {
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
                // Some wallets prepend a scheme to the expected audience. We accept any such
                // scheme.
                String regex = String.format("([^:]+:)?%s", Pattern.quote(expectedKbJwtAud));
                Pattern expectedPattern = Pattern.compile(regex);
                return new ClaimCheck(JsonWebToken.AUD, expectedKbJwtAud,
                                (expectedAud, aud) -> expectedPattern.matcher(aud).matches());
        }

        private List<String> parseMultiStr(String str) {
                return StringUtil.isBlank(str)
                                ? List.of()
                                : List.of(str.split("\\s*,\\s*"));
        }
}
