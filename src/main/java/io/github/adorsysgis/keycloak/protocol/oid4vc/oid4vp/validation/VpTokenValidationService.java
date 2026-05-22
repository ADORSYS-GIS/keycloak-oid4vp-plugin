package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorConfigResolver;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactories;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.utils.StringUtil;

/**
 * Facade for running the verifier-side {@code vp_token} validation pipeline.
 */
public class VpTokenValidationService {

    private final KeycloakSession session;
    private final AuthenticatorConfigModel authConfig;
    private final VpTokenValidationPipeline pipeline;

    private VpTokenValidationService(
            KeycloakSession session, AuthenticatorConfigModel authConfig, StatusListJwtFetcher statusListJwtFetcher) {
        this.session = session;
        this.authConfig = authConfig;
        this.pipeline = new VpTokenValidationPipeline(statusListJwtFetcher);
    }

    public static VpTokenValidationService create(KeycloakSession session) {
        return new VpTokenValidationService(
                session,
                SdJwtAuthenticatorConfigResolver.resolve(session),
                SdJwtAuthenticatorFactories.createStatusListJwtFetcher(session));
    }

    public VpTokenValidationResult validate(ResponseObject responseObject, RequestObject requestObject)
            throws VpTokenValidationException {
        SdJwtAuthRequirements authRequirements = new SdJwtAuthRequirements(session.getContext(), authConfig);

        String audience = HolderBindingAudienceResolver.resolve(requestObject);
        validateReplayBindingInputs(requestObject, audience);

        VpTokenValidationContext context = new VpTokenValidationContext(
                session, requestObject, authRequirements, requestObject.getNonce(), audience);

        return pipeline.validate(responseObject, context);
    }

    private static void validateReplayBindingInputs(RequestObject requestObject, String audience)
            throws VpTokenValidationException {
        if (!requiresHolderBinding(requestObject)) {
            return;
        }
        if (StringUtil.isBlank(requestObject.getNonce())) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.STRUCTURE,
                    "Authorization request nonce is required for cryptographic holder binding");
        }
        if (StringUtil.isBlank(audience)) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.STRUCTURE,
                    "Authorization request client_id is required for cryptographic holder binding");
        }
    }

    private static boolean requiresHolderBinding(RequestObject requestObject) {
        if (requestObject.getDcqlQuery() == null || requestObject.getDcqlQuery().getCredentials() == null) {
            return true;
        }
        return requestObject.getDcqlQuery().getCredentials().stream()
                .anyMatch(Credential::requiresCryptographicHolderBinding);
    }
}
