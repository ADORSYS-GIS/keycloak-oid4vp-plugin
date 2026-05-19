package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import java.lang.reflect.Constructor;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.utils.StringUtil;

/**
 * Facade for running the verifier-side {@code vp_token} validation pipeline.
 */
public class VpTokenValidationService {

    private final VpTokenValidationPipeline pipeline;
    private final KeycloakSession session;

    public VpTokenValidationService(KeycloakSession session) {
        this.session = session;
        this.pipeline = new VpTokenValidationPipeline(resolveStatusListJwtFetcher(session));
    }

    private static StatusListJwtFetcher resolveStatusListJwtFetcher(KeycloakSession session) {
        try {
            Class<?> mockFetcherClass = Class.forName(
                    "io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.stub.CustomSdJwtAuthenticatorFactory$MockTrustedStatusListJwtFetcher");
            Constructor<?> constructor = mockFetcherClass.getConstructor(KeycloakSession.class);
            return (StatusListJwtFetcher) constructor.newInstance(session);
        } catch (ClassNotFoundException ignored) {
            return new SdJwtAuthenticatorFactory().createStatusListJwtFetcher(session);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Failed to initialize status list JWT fetcher", e);
        }
    }

    public VpTokenValidationResult validate(ResponseObject responseObject, RequestObject requestObject)
            throws VpTokenValidationException {
        AuthenticatorConfigModel authConfig = OID4VPUserAuthEndpointBase.resolveSdJwtAuthenticatorConfig(session);
        SdJwtAuthRequirements authRequirements =
                new SdJwtAuthRequirements(session.getContext(), authConfig);

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
        return requestObject.getDcqlQuery().getCredentials().stream().anyMatch(Credential::requiresCryptographicHolderBinding);
    }
}
