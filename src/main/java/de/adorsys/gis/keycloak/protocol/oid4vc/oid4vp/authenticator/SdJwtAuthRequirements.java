package de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model.ClientIdScheme;
import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationDefinition;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.SdJwtCredentialBuilder;
import org.keycloak.sdjwt.IssuerSignedJwtVerificationOpts;
import org.keycloak.sdjwt.consumer.PresentationRequirements;
import org.keycloak.sdjwt.consumer.SimplePresentationDefinition;
import org.keycloak.sdjwt.vp.KeyBindingJwtVerificationOpts;
import org.keycloak.utils.StringUtil;

import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Predefined presentation requirements on the SD-JWT VP token for authentication.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtAuthRequirements {

    private static final Logger logger = Logger.getLogger(SdJwtAuthRequirements.class);

    private final SdJwtCredentialConstrainer sdJwtCredentialConstrainer;
    private final String keycloakIssuerURI;
    private final String expectedKbJwtAud;

    private final List<String> expectedVcts;
    private final String expectedVctsPattern;

    private final int kbJwtMaxAllowedAge;
    private final boolean validateNotBeforeClaim;
    private final boolean validateExpirationClaim;
    private final boolean enforceRevocationStatus;

    public SdJwtAuthRequirements(KeycloakContext context, AuthenticatorConfigModel authConfig) {
        logger.debugf("Collecting authentication requirements");
        this.sdJwtCredentialConstrainer = new SdJwtCredentialConstrainer();

        // We'll need to enforce that only credentials produced by and for this audience pass through.
        // The audience is the client ID of the verifier, but some wallets prepend a scheme.
        this.keycloakIssuerURI = OID4VCIssuerWellKnownProvider.getIssuer(context);
        // String kbJwtAud = Pattern.quote(context.getUri().getBaseUri().getHost());
        // this.expectedKbJwtAud = Pattern.compile("(.*:)?%s".formatted(kbJwtAud));

        // FIXME!!! This module must not know anything about OpenID4VP but because the SD-JWT API
        //  is so far rigid for aud claim verification with pattern matching, we hardcode the client
        //  scheme for compatibility with the Lissi wallet. Once made flexible, uncomment the logic
        //  above.
        String kbJwtAud = context.getUri().getBaseUri().getHost();
        String clientIdScheme = ClientIdScheme.X509_SAN_DNS.getValue().toLowerCase();
        this.expectedKbJwtAud = String.format("%s:%s", clientIdScheme, kbJwtAud);

        // Reading authenticator configs
        Map<String, String> config = (authConfig != null && authConfig.getConfig() != null)
                ? authConfig.getConfig()
                : Map.of();

        this.expectedVcts = parseMultiStr(config.getOrDefault(
                SdJwtAuthenticatorFactory.VCT_CONFIG,
                SdJwtAuthenticatorFactory.VCT_CONFIG_DEFAULT
        ));

        this.kbJwtMaxAllowedAge = Integer.parseInt(config.getOrDefault(
                SdJwtAuthenticatorFactory.KBJWT_MAX_AGE_CONFIG,
                String.valueOf(SdJwtAuthenticatorFactory.KBJWT_MAX_AGE_CONFIG_DEFAULT)
        ));

        this.validateNotBeforeClaim = Boolean.parseBoolean(config.getOrDefault(
                SdJwtAuthenticatorFactory.ENFORCE_NBF_CLAIM_CONFIG,
                String.valueOf(SdJwtAuthenticatorFactory.ENFORCE_NBF_CLAIM_CONFIG_DEFAULT)
        ));

        this.validateExpirationClaim = Boolean.parseBoolean(config.getOrDefault(
                SdJwtAuthenticatorFactory.ENFORCE_EXP_CLAIM_CONFIG,
                String.valueOf(SdJwtAuthenticatorFactory.ENFORCE_EXP_CLAIM_CONFIG_DEFAULT)
        ));

        this.enforceRevocationStatus = Boolean.parseBoolean(config.getOrDefault(
                SdJwtAuthenticatorFactory.ENFORCE_REVOCATION_STATUS_CONFIG,
                String.valueOf(SdJwtAuthenticatorFactory.ENFORCE_REVOCATION_STATUS_CONFIG_DEFAULT)
        ));

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
        getRequiredClaims().forEach(claim ->
                definition.addClaimRequirement(claim, ".*")
        );

        return definition
                .addClaimRequirement(
                        SdJwtCredentialBuilder.VERIFIABLE_CREDENTIAL_TYPE_CLAIM,
                        expectedVctsPattern
                )
                .addClaimRequirement(
                        SdJwtCredentialBuilder.ISSUER_CLAIM,
                        Pattern.quote("\"%s\"".formatted(keycloakIssuerURI))
                )
                .build();
    }

    /**
     * Constructs presentation definition in the DIF presentation exchange format.
     */
    public PresentationDefinition getDIFPresentationDefinition() {
        return sdJwtCredentialConstrainer.generatePresentationDefinition(
                getExpectedVcts(),
                getRequiredClaims()
        );
    }

    public IssuerSignedJwtVerificationOpts getIssuerSignedJwtVerificationOpts() {
        // TODO: Update time claim options naming and config keys to denote requirement
        //  on the presence of claims. Following a recent update to Keycloak upstream,
        //  validation will always be performed if claims are present.
        return IssuerSignedJwtVerificationOpts.builder()
                .withIatCheck(true)
                .withNbfCheck(!validateNotBeforeClaim)
                .withExpCheck(!validateExpirationClaim)
                .build();
    }

    public KeyBindingJwtVerificationOpts getKeyBindingJwtVerificationOpts(String nonce) {
        // TODO: Update time claim options naming and config keys to denote requirement
        //  on the presence of claims. Following a recent update to Keycloak upstream,
        //  validation will always be performed if claims are present.
        return KeyBindingJwtVerificationOpts.builder()
                .withKeyBindingRequired(true)
                .withIatCheck(kbJwtMaxAllowedAge)
                .withNonceCheck(nonce)
                .withAudCheck(expectedKbJwtAud)
                .withNbfCheck(!validateNotBeforeClaim)
                .withExpCheck(!validateExpirationClaim)
                .build();
    }

    private List<String> parseMultiStr(String str) {
        return StringUtil.isBlank(str)
                ? List.of()
                : List.of(str.split("\\s*,\\s*"));
    }
}
