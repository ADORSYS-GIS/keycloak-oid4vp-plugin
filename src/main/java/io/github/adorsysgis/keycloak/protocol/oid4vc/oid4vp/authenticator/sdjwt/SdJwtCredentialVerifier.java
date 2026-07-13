package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.sdjwt;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialFormat;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialVerifier;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.TransactionDataValidator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.VerificationException;
import org.keycloak.sdjwt.consumer.PresentationRequirements;
import org.keycloak.sdjwt.consumer.SdJwtPresentationConsumer;
import org.keycloak.sdjwt.vp.KeyBindingJWT;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * {@link CredentialVerifier} implementation backing verification of {@code dc+sd-jwt}
 * (SD-JWT VC) credentials presented via OpenID4VP.
 */
public class SdJwtCredentialVerifier implements CredentialVerifier {

    private static final Logger logger = Logger.getLogger(SdJwtCredentialVerifier.class);

    private final SdJwtPresentationConsumer consumer;
    private final ReferencedTokenValidator tokenStatusValidator;

    public SdJwtCredentialVerifier(StatusListJwtFetcher statusListJwtFetcher) {
        this.consumer = new SdJwtPresentationConsumer();
        this.tokenStatusValidator = new ReferencedTokenValidator(statusListJwtFetcher);
    }

    @Override
    public CredentialFormat format() {
        return CredentialFormat.SD_JWT_VC;
    }

    @Override
    public JsonNode verifyCredential(
            AuthenticationFlowContext context,
            AuthorizationContext authorizationContext,
            CredentialRequirement credential,
            String token,
            boolean requireCryptographicHolderBinding)
            throws VerificationException {

        RequestObject requestObject = authorizationContext.getRequestObject();
        String nonce = requestObject.getNonce();
        String audience = requestObject.getClientId();

        SdJwtVP sdJwt = parseSdJwt(token);

        SdJwtAuthRequirements authReqs = new SdJwtAuthRequirements(
                context.getSession().getContext(), context.getAuthenticatorConfig(), credential);

        AtomicReference<JsonNode> payloadRef = new AtomicReference<>();
        PresentationRequirements requirements = payload -> {
            payloadRef.set(payload);
            authReqs.getPresentationRequirements().checkIfSatisfiedBy(payload);
        };

        consumer.verifySdJwtPresentation(
                sdJwt,
                requirements,
                SdJwtTrustedIssuerResolver.resolve(context.getSession(), credential),
                authReqs.getIssuerSignedJwtVerificationOpts(),
                authReqs.getKeyBindingJwtVerificationOpts(nonce, audience, requireCryptographicHolderBinding));

        if (authReqs.shouldEnforceRevocationStatus()) {
            try {
                tokenStatusValidator.validate(sdJwt.getIssuerSignedJWT().getPayload());
            } catch (ReferencedTokenValidationException e) {
                throw new VerificationException(
                        String.format(
                                "Token status verification failed for credential to requirement '%s'",
                                credential.getId()),
                        e);
            }
        }

        if (credential.isPrimary()) {
            validateTransactionData(context.getAuthenticationSession(), token);
        }

        return payloadRef.get();
    }

    @Override
    public String readClaim(JsonNode claims, String claimName) {
        return Optional.ofNullable(claims.get(claimName)).map(JsonNode::asText).orElse(null);
    }

    void validateTransactionData(AuthenticationSessionModel authSession, String presentedToken) {
        String wireJson = authSession.getAuthNote(OID4VPAuthenticator.TRANSACTION_DATA_WIRE_KEY);
        if (StringUtil.isBlank(wireJson)) {
            return;
        }

        List<String> transactionDataWire;
        try {
            transactionDataWire = JsonSerialization.readValue(wireJson, new TypeReference<>() {});
        } catch (IOException e) {
            throw new IllegalArgumentException("Invalid transaction_data session state", e);
        }

        SdJwtVP sdJwt = parseSdJwt(presentedToken);
        Optional<KeyBindingJWT> keyBindingJwt = sdJwt.getKeyBindingJWT();
        if (keyBindingJwt.isEmpty()) {
            throw new IllegalArgumentException("Key Binding JWT required when transaction_data is requested");
        }

        ObjectNode kbPayload = keyBindingJwt.get().getPayload();
        TransactionDataValidator.validate(transactionDataWire, kbPayload);
    }

    private static SdJwtVP parseSdJwt(String presentedToken) {
        if (StringUtil.isBlank(presentedToken)) {
            throw new IllegalStateException("Missing credential presentation for credential");
        }

        try {
            return SdJwtVP.of(presentedToken);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Credential presentation could not be parsed", e);
        }
    }
}
