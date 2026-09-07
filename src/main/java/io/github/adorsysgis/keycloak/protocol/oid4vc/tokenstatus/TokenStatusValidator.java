package io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;

/** Policy-aware entry point for referenced token status validation. */
public final class TokenStatusValidator {

    private final ReferencedTokenValidator delegate;

    public TokenStatusValidator(StatusListJwtFetcher statusListJwtFetcher) {
        this.delegate = new ReferencedTokenValidator(statusListJwtFetcher);
    }

    /**
     * Validates the referenced token's status if the credential carries one.
     *
     * <p>When {@code allowMissingStatusClaim} is {@code true}, credentials without
     * a {@code status} claim are accepted for revocation purposes. Such credentials
     * cannot later be revoked via the Token Status List mechanism because they have
     * no status to update.
     *
     * <p>This validator does not revoke credentials. It only decides whether a
     * credential without any status claim should still be treated as valid for
     * revocation purposes.
     */
    public void validate(JsonNode tokenPayload, boolean allowMissingStatusClaim)
            throws ReferencedTokenValidationException {
        if (tokenPayload.get(ReferencedTokenValidator.STATUS_FIELD) == null && allowMissingStatusClaim) {
            return;
        }
        delegate.validate(tokenPayload);
    }
}
