package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SelfTrustedSdJwtIssuer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import java.util.List;
import org.keycloak.VCFormat;
import org.keycloak.common.VerificationException;
import org.keycloak.sdjwt.consumer.SdJwtPresentationConsumer;
import org.keycloak.sdjwt.vp.KeyBindingJwtVerificationOpts;
import org.keycloak.sdjwt.vp.SdJwtVP;

/**
 * Format-specific validation for {@code dc+sd-jwt} presentations (OpenID4VP §8.6, Appendix B).
 */
public class SdJwtPresentationValidator implements PresentationFormatValidator {

    private final SdJwtPresentationConsumer consumer;
    private final ReferencedTokenValidator tokenStatusValidator;

    public SdJwtPresentationValidator(StatusListJwtFetcher statusListJwtFetcher) {
        this.consumer = new SdJwtPresentationConsumer();
        this.tokenStatusValidator = new ReferencedTokenValidator(statusListJwtFetcher);
    }

    @Override
    public boolean supports(Credential credentialQuery) {
        String format = credentialQuery.getFormat();
        return VCFormat.SD_JWT_VC.equals(format) || "dc+sd-jwt".equals(format);
    }

    @Override
    public ValidatedPresentation validate(
            String encodedPresentation, Credential credentialQuery, VpTokenValidationContext context)
            throws VpTokenValidationException {
        if (!supports(credentialQuery)) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.FORMAT,
                    "Unsupported credential format: " + credentialQuery.getFormat());
        }

        final SdJwtVP presentation;
        final String normalizedPresentation;
        try {
            normalizedPresentation = VpTokenPresentationDecoder.decodeIfBase64Url(encodedPresentation);
            presentation = SdJwtVP.of(normalizedPresentation);
        } catch (IllegalArgumentException e) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.STRUCTURE,
                    "Could not parse SD-JWT VP token contained in `vp_token`",
                    e);
        }

        SdJwtAuthRequirements authRequirements = context.authRequirements();
        try {
            KeyBindingJwtVerificationOpts kbJwtOpts =
                    buildKeyBindingOptions(credentialQuery, authRequirements, context.nonce(), context.audience());

            consumer.verifySdJwtPresentation(
                    presentation,
                    SdJwtPresentationRequirements.forCredential(authRequirements, credentialQuery),
                    List.of(new SelfTrustedSdJwtIssuer(context.session())),
                    authRequirements.getIssuerSignedJwtVerificationOpts(),
                    kbJwtOpts);
        } catch (VerificationException e) {
            throw new VpTokenValidationException(VpTokenValidationException.Phase.FORMAT, e.getMessage(), e);
        }

        if (authRequirements.shouldEnforceRevocationStatus()) {
            try {
                tokenStatusValidator.validate(presentation.getIssuerSignedJWT().getPayload());
            } catch (ReferencedTokenValidationException e) {
                throw new VpTokenValidationException(
                        VpTokenValidationException.Phase.FORMAT, "Token status verification failed", e);
            }
        }

        return new ValidatedPresentation(normalizedPresentation, presentation);
    }

    private static KeyBindingJwtVerificationOpts buildKeyBindingOptions(
            Credential credentialQuery, SdJwtAuthRequirements authRequirements, String nonce, String audience)
            throws VpTokenValidationException {
        if (!credentialQuery.requiresCryptographicHolderBinding()) {
            return KeyBindingJwtVerificationOpts.builder()
                    .withKeyBindingRequired(false)
                    .build();
        }
        if (nonce == null || nonce.isBlank()) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.FORMAT,
                    "Authorization request nonce is required for cryptographic holder binding");
        }
        if (audience == null || audience.isBlank()) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.FORMAT,
                    "Authorization request client_id is required for cryptographic holder binding");
        }
        return authRequirements.getKeyBindingJwtVerificationOpts(nonce, audience);
    }
}
