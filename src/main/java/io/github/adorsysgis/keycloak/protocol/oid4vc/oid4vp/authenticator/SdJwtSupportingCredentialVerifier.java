package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.BindingRule;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;
import java.util.List;
import java.util.Map;
import org.keycloak.common.VerificationException;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.sdjwt.consumer.SdJwtPresentationConsumer;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.utils.StringUtil;

class SdJwtSupportingCredentialVerifier {

    private final KeycloakSession session;
    private final SdJwtPresentationConsumer consumer;
    private final ReferencedTokenValidator tokenStatusValidator;

    SdJwtSupportingCredentialVerifier(
            KeycloakSession session,
            SdJwtPresentationConsumer consumer,
            ReferencedTokenValidator tokenStatusValidator) {
        this.session = session;
        this.consumer = consumer;
        this.tokenStatusValidator = tokenStatusValidator;
    }

    void verify(
            AuthenticationProfile profile,
            Map<String, String> sdJwtVpTokens,
            SdJwtVP primarySdJwt,
            UserModel user,
            AuthenticatorConfigModel authConfig,
            String nonce,
            String aud,
            boolean requireCryptographicHolderBinding)
            throws VerificationException {
        CredentialRequirement primaryCredential = profile.getPrimaryCredential();
        for (CredentialRequirement credential : profile.getCredentials()) {
            if (credential.getId().equals(primaryCredential.getId())) {
                continue;
            }

            SdJwtVP supportingSdJwt = verifySupportingCredential(
                    credential,
                    sdJwtVpTokens.get(credential.getId()),
                    authConfig,
                    nonce,
                    aud,
                    requireCryptographicHolderBinding);
            applyBindingRules(credential, supportingSdJwt, primarySdJwt, user);
        }
    }

    private SdJwtVP verifySupportingCredential(
            CredentialRequirement credential,
            String sdJwtVpToken,
            AuthenticatorConfigModel authConfig,
            String nonce,
            String aud,
            boolean requireCryptographicHolderBinding)
            throws VerificationException {
        if (!credential.isSelfTrusted()) {
            // TODO: Route external trust policies to dedicated issuer validators when those profiles are enabled.
            throw new VerificationException(
                    "Credential '%s' uses an unsupported trust policy".formatted(credential.getId()));
        }
        if (StringUtil.isBlank(sdJwtVpToken)) {
            throw new VerificationException(
                    "Supporting credential '%s' is missing from the presentation".formatted(credential.getId()));
        }

        SdJwtVP sdJwt;
        try {
            sdJwt = SdJwtVP.of(sdJwtVpToken);
        } catch (IllegalArgumentException e) {
            throw new VerificationException(
                    "Supporting credential '%s' could not be parsed".formatted(credential.getId()), e);
        }

        SdJwtAuthRequirements authReqs = new SdJwtAuthRequirements(session.getContext(), authConfig, credential);
        consumer.verifySdJwtPresentation(
                sdJwt,
                authReqs.getPresentationRequirements(),
                List.of(new SelfTrustedSdJwtIssuer(session)),
                authReqs.getIssuerSignedJwtVerificationOpts(),
                authReqs.getKeyBindingJwtVerificationOpts(nonce, aud, requireCryptographicHolderBinding));

        if (authReqs.shouldEnforceRevocationStatus()) {
            try {
                tokenStatusValidator.validate(sdJwt.getIssuerSignedJWT().getPayload());
            } catch (ReferencedTokenValidationException e) {
                throw new VerificationException(
                        "Supporting credential '%s' token status verification failed".formatted(credential.getId()), e);
            }
        }
        return sdJwt;
    }

    private void applyBindingRules(
            CredentialRequirement credential, SdJwtVP supportingSdJwt, SdJwtVP primarySdJwt, UserModel user)
            throws VerificationException {
        for (BindingRule rule : credential.getBinding()) {
            String supportingValue = SdJwtCredentialClaims.readClaim(supportingSdJwt, rule.getCredentialClaim());
            String expectedValue =
                    switch (rule.getType()) {
                        case BindingRule.CLAIM_EQUALS_PRIMARY_CLAIM ->
                            SdJwtCredentialClaims.readClaim(primarySdJwt, rule.getPrimaryCredentialClaim());
                        case BindingRule.CLAIM_EQUALS_USER_ATTRIBUTE ->
                            readUserAttribute(user, rule.getUserAttribute());
                        default -> throw new IllegalStateException("Unsupported binding rule type: " + rule.getType());
                    };

            if (StringUtil.isBlank(supportingValue) || !supportingValue.equals(expectedValue)) {
                throw new VerificationException("Supporting credential '%s' failed binding rule '%s'"
                        .formatted(credential.getId(), rule.getType()));
            }
        }
    }

    private String readUserAttribute(UserModel user, String userAttribute) {
        return switch (userAttribute) {
            case "given_name", "firstName" -> user.getFirstName();
            case "family_name", "lastName" -> user.getLastName();
            case "username", "preferred_username" -> user.getUsername();
            default -> user.getFirstAttribute(userAttribute);
        };
    }
}
