package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.VerifierConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.SdGenericFormat;
import java.util.List;
import org.keycloak.VCFormat;
import org.keycloak.common.VerificationException;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

/** Production DCQL path for {@code dc+sd-jwt} user authentication. */
public final class SdJwtDcqlCredentialCapability implements DcqlCredentialCapability {

    private final SdJwtCredentialConstrainer constrainer = new SdJwtCredentialConstrainer();

    @Override
    public String format() {
        return VCFormat.SD_JWT_VC;
    }

    @Override
    public boolean supports(VerifierConfig config) {
        // TODO: Gate on verifier format/authenticator selection once additional DCQL capabilities exist.
        return true;
    }

    @Override
    public DcqlQuery buildAuthorizationQuery(VerifierConfig config) {
        return constrainer.buildQuery(config.buildSdJwtQuerySpec());
    }

    @Override
    public void validatePresentation(DcqlQuery query, String presentedToken) throws VerificationException {
        DcqlPresentationValidator.validatePresentation(query, presentedToken);
    }

    @Override
    public void setupAuthenticationSession(
            AuthenticationSessionModel authenticationSession,
            String presentedToken,
            AuthorizationContext authorizationContext) {
        String nonce = authorizationContext.getRequestObject().getNonce();
        String aud = authorizationContext.getRequestObject().getClientId();
        authenticationSession.setAuthNote(SdJwtAuthenticator.SDJWT_TOKEN_KEY, presentedToken);
        authenticationSession.setAuthNote(SdJwtAuthenticator.CHALLENGE_NONCE_KEY, nonce);
        authenticationSession.setAuthNote(SdJwtAuthenticator.CHALLENGE_AUD_KEY, aud);

        boolean requireCryptographicHolderBinding = isCryptographicHolderBindingRequired(
                authorizationContext.getRequestObject().getDcqlQuery().getCredentials());
        authenticationSession.setAuthNote(
                SdJwtAuthenticator.REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING_KEY,
                String.valueOf(requireCryptographicHolderBinding));

        var transactionData = authorizationContext.getRequestObject().getTransactionData();
        if (transactionData != null && !transactionData.isEmpty()) {
            try {
                authenticationSession.setAuthNote(
                        SdJwtAuthenticator.TRANSACTION_DATA_WIRE_KEY,
                        JsonSerialization.writeValueAsString(transactionData));
            } catch (Exception e) {
                throw new IllegalStateException("Failed to persist transaction_data for validation", e);
            }
        }
    }

    @Override
    public void contributeVpFormatsSupported(ClientMetadata.VpFormat vpFormat, List<String> signatureAlgorithms) {
        SdGenericFormat format = new SdGenericFormat();
        format.setSdJwtAlgValues(signatureAlgorithms);
        format.setKbJwtAlgValues(signatureAlgorithms);
        vpFormat.setDcSdJwt(format);
    }

    private static boolean isCryptographicHolderBindingRequired(List<Credential> credentials) {
        return credentials.stream().noneMatch(c -> Boolean.FALSE.equals(c.getRequireCryptographicHolderBinding()));
    }
}
