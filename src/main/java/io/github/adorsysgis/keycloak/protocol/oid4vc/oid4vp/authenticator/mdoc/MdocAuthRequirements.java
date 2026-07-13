package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.mdoc;

import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocVerificationOpts;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.AuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement.ClaimReference;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.sdjwt.consumer.PresentationRequirements;

/**
 * Configured presentation requirements on mDoc device responses for authentication.
 */
public class MdocAuthRequirements {

    private static final Logger logger = Logger.getLogger(MdocAuthRequirements.class);

    private final AuthRequirements authRequirements;

    private List<String> expectedDocTypes;
    private List<ClaimReference> requiredClaims;

    public MdocAuthRequirements(AuthenticatorConfigModel authConfig) {
        logger.debugf("Collecting mDoc authentication requirements");
        this.authRequirements = new AuthRequirements(authConfig);
        this.expectedDocTypes = authRequirements.getCredentialTypes();
        this.requiredClaims = List.of();
    }

    public MdocAuthRequirements(AuthenticatorConfigModel authConfig, CredentialRequirement credentialRequirement) {
        this(authConfig);
        this.expectedDocTypes = credentialRequirement.getCredentialTypes();
        this.requiredClaims = credentialRequirement.getClaimReferences();
    }

    public boolean shouldEnforceRevocationStatus() {
        return authRequirements.shouldEnforceRevocationStatus();
    }

    public PresentationRequirements getPresentationRequirements() {
        return new SimpleMdocPresentationDefinition(expectedDocTypes, requiredClaims);
    }

    public MdocVerificationOpts getMdocVerificationOpts(
            String clientId, String oid4vpNonce, String responseUri, byte[] jwkThumbprint, String mdocGeneratedNonce) {
        return MdocVerificationOpts.builder()
                .withClientId(clientId)
                .withOid4vpNonce(oid4vpNonce)
                .withResponseUri(responseUri)
                .withJwkThumbprint(jwkThumbprint)
                .withMdocGeneratedNonce(mdocGeneratedNonce)
                .withFallbackToIsoSpecSessionTranscript(authRequirements.shouldFallbackToIsoSpecSessionTranscript())
                .withAllowedMaxAge(authRequirements.getHolderBindingProofMaxAge())
                .build();
    }
}
