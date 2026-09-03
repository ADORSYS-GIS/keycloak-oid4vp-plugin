package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.issuance;

import static org.keycloak.protocol.oid4vc.model.AuthorizationCodeGrant.AUTH_CODE_GRANT_TYPE;

import java.util.List;
import java.util.Objects;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oid4vc.issuance.credentialoffer.CredentialOfferProvider;
import org.keycloak.protocol.oid4vc.issuance.credentialoffer.CredentialOfferState;

/**
 * Temporary backport that prevents authorization-code credential offers from being bound to the
 * client that created the offer.
 *
 * <p>Pre-authorized-code offers retain their client binding. Remove this decorator once the
 * corresponding fix is available in the supported Keycloak release.
 */
public final class PatchedCredentialOfferProvider implements CredentialOfferProvider {

    private final CredentialOfferProvider delegate;

    public PatchedCredentialOfferProvider(CredentialOfferProvider delegate) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
    }

    @Override
    public CredentialOfferState createCredentialOffer(
            UserModel user,
            String grantType,
            List<String> credentialConfigurationIds,
            String targetClientId,
            String targetUserId,
            Integer expireAt) {
        String effectiveTargetClientId = AUTH_CODE_GRANT_TYPE.equals(grantType) ? null : targetClientId;
        return delegate.createCredentialOffer(
                user, grantType, credentialConfigurationIds, effectiveTargetClientId, targetUserId, expireAt);
    }

    @Override
    public void close() {
        delegate.close();
    }
}
