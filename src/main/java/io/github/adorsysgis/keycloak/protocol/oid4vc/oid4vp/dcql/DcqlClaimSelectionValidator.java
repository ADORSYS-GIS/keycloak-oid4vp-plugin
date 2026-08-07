package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.keycloak.common.VerificationException;

/** Applies the format-neutral DCQL {@code claims}/{@code claim_sets} selection rules. */
final class DcqlClaimSelectionValidator {

    private DcqlClaimSelectionValidator() {}

    static void validate(
            Credential credential,
            Function<Claim, ClaimValidationResult> claimEvaluator,
            String unsatisfiedClaimSetsMessage)
            throws VerificationException {
        List<Claim> claims = credential.getClaims();
        if (claims == null || claims.isEmpty()) {
            return;
        }

        List<List<String>> claimSets = credential.getClaimSets();
        if (claimSets == null || claimSets.isEmpty()) {
            for (Claim claim : claims) {
                ClaimValidationResult result = claimEvaluator.apply(claim);
                if (!result.satisfied()) {
                    throw new VerificationException(result.errorMessage());
                }
            }
            return;
        }

        Map<String, Boolean> claimSatisfactionById = new HashMap<>();
        for (Claim claim : claims) {
            claimSatisfactionById.put(claim.getId(), claimEvaluator.apply(claim).satisfied());
        }

        boolean satisfiesAnyClaimSet = claimSets.stream().anyMatch(option -> option.stream()
                .allMatch(claimId -> Boolean.TRUE.equals(claimSatisfactionById.get(claimId))));
        if (!satisfiesAnyClaimSet) {
            throw new VerificationException(unsatisfiedClaimSetsMessage);
        }
    }

    record ClaimValidationResult(boolean satisfied, String errorMessage) {
        static ClaimValidationResult ok() {
            return new ClaimValidationResult(true, null);
        }

        static ClaimValidationResult failed(String errorMessage) {
            return new ClaimValidationResult(false, errorMessage);
        }
    }
}
