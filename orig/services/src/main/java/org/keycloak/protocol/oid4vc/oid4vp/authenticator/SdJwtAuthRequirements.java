/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.protocol.oid4vc.oid4vp.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.SdJwtCredentialBuilder;
import org.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationDefinition;
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
    private final Pattern expectedKbJwtAud;

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
        String kbJwtAud = Pattern.quote(context.getUri().getBaseUri().getHost());
        this.expectedKbJwtAud = Pattern.compile("(.*:)?%s".formatted(kbJwtAud));

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
        return IssuerSignedJwtVerificationOpts.builder()
                .withValidateNotBeforeClaim(validateNotBeforeClaim)
                .withValidateExpirationClaim(validateExpirationClaim)
                .build();
    }

    public KeyBindingJwtVerificationOpts getKeyBindingJwtVerificationOpts(String nonce) {
        return KeyBindingJwtVerificationOpts.builder()
                .withKeyBindingRequired(true)
                .withAllowedMaxAge(kbJwtMaxAllowedAge)
                .withNonce(nonce)
                .withAud(expectedKbJwtAud)
                .withValidateNotBeforeClaim(validateNotBeforeClaim)
                .withValidateExpirationClaim(validateExpirationClaim)
                .build();
    }

    private List<String> parseMultiStr(String str) {
        return StringUtil.isBlank(str)
                ? List.of()
                : List.of(str.split("\\s*,\\s*"));
    }
}
