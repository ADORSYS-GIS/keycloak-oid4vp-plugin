package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import static org.keycloak.OID4VCConstants.CLAIM_NAME_ISSUER;
import static org.keycloak.OID4VCConstants.CLAIM_NAME_VCT;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.keycloak.common.VerificationException;
import org.keycloak.sdjwt.consumer.PresentationRequirements;

/**
 * Presentation requirements for SD-JWT format validation (OpenID4VP §8.6) using the same
 * DCQL §7.1 path resolution as {@link DcqlSatisfactionValidator}.
 */
public final class SdJwtPresentationRequirements implements PresentationRequirements {

    private static final Pattern ANY_VALUE = Pattern.compile(".*");

    private final List<List<String>> requiredPaths;
    private final Pattern vctPattern;
    private final Pattern issPattern;

    private SdJwtPresentationRequirements(List<List<String>> requiredPaths, Pattern vctPattern, Pattern issPattern) {
        this.requiredPaths = List.copyOf(requiredPaths);
        this.vctPattern = vctPattern;
        this.issPattern = issPattern;
    }

    public static PresentationRequirements forCredential(
            SdJwtAuthRequirements authRequirements, Credential credentialQuery) {
        List<List<String>> paths = new ArrayList<>();
        authRequirements.getRequiredClaims().stream().map(List::of).forEach(paths::add);

        if (credentialQuery.getClaims() != null) {
            for (Claim claim : credentialQuery.getClaims()) {
                if (claim.getPath() != null && !claim.getPath().isEmpty()) {
                    paths.add(List.copyOf(claim.getPath()));
                }
            }
        }

        Pattern vctPattern = Pattern.compile(authRequirements.getVctPatternForCredential(credentialQuery));
        Pattern issPattern =
                authRequirements.isVerifyIssuerClaim() ? Pattern.compile(authRequirements.getIssuerPattern()) : null;

        return new SdJwtPresentationRequirements(paths, vctPattern, issPattern);
    }

    @Override
    public void checkIfSatisfiedBy(JsonNode claimsRoot) throws VerificationException {
        for (List<String> path : requiredPaths) {
            requireClaimMatches(claimsRoot, path, ANY_VALUE);
        }
        requireClaimMatches(claimsRoot, List.of(CLAIM_NAME_VCT), vctPattern);
        if (issPattern != null) {
            requireClaimMatches(claimsRoot, List.of(CLAIM_NAME_ISSUER), issPattern);
        }
    }

    private static void requireClaimMatches(JsonNode claimsRoot, List<String> path, Pattern pattern)
            throws VerificationException {
        List<JsonNode> resolved;
        try {
            resolved = SdJwtClaimReader.resolveClaimPath(claimsRoot, path);
        } catch (VpTokenValidationException e) {
            throw new VerificationException(e.getMessage(), e);
        }

        if (resolved.isEmpty()) {
            throw new VerificationException("A required field was not presented: `%s`".formatted(formatPath(path)));
        }

        for (JsonNode value : resolved) {
            String presented = value.toString();
            if (!pattern.matcher(presented).matches()) {
                throw new VerificationException(String.format(
                        "Pattern matching failed for required field: `%s`. Expected pattern: /%s/, but got: %s",
                        formatPath(path), pattern.pattern(), presented));
            }
        }
    }

    private static String formatPath(List<String> path) {
        return String.join(".", path);
    }
}
