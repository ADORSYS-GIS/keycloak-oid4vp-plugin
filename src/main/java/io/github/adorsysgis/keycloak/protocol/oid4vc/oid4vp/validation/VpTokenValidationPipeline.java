package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Verifier-side validation pipeline for returned {@code vp_token} values.
 *
 * <p>Order: structure → per-format checks → DCQL satisfaction (OpenID4VP §8.6).
 */
public class VpTokenValidationPipeline {

    private final VpTokenStructureValidator structureValidator = new VpTokenStructureValidator();
    private final PresentationFormatValidators formatValidators;
    private final DcqlSatisfactionValidator dcqlSatisfactionValidator = new DcqlSatisfactionValidator();

    public VpTokenValidationPipeline(StatusListJwtFetcher statusListJwtFetcher) {
        this(new SdJwtPresentationValidator(statusListJwtFetcher));
    }

    VpTokenValidationPipeline(PresentationFormatValidator... validators) {
        this.formatValidators = new PresentationFormatValidators(List.of(validators));
    }

    public VpTokenValidationResult validate(ResponseObject responseObject, VpTokenValidationContext context)
            throws VpTokenValidationException {
        DcqlQuery dcqlQuery = context.requestObject().getDcqlQuery();
        Map<String, List<String>> vpTokenMap = structureValidator.validate(responseObject.getVpToken(), dcqlQuery);

        Map<String, Credential> credentialsById = dcqlQuery.getCredentials().stream()
                .collect(Collectors.toMap(Credential::getId, Function.identity()));

        List<PresentedCredential> presentations = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : vpTokenMap.entrySet()) {
            Credential credentialQuery = credentialsById.get(entry.getKey());
            if (credentialQuery == null) {
                throw new VpTokenValidationException(
                        VpTokenValidationException.Phase.STRUCTURE,
                        "vp_token contains unexpected credential query id: " + entry.getKey());
            }

            PresentationFormatValidator formatValidator = formatValidators.requireValidatorFor(credentialQuery);
            for (String encodedPresentation : entry.getValue()) {
                PresentationFormatValidator.ValidatedPresentation validated =
                        formatValidator.validate(encodedPresentation, credentialQuery, context);
                presentations.add(new PresentedCredential(
                        credentialQuery.getId(),
                        credentialQuery,
                        validated.presentationString(),
                        validated.presentation()));
            }
        }

        dcqlSatisfactionValidator.validate(presentations, dcqlQuery);
        return new VpTokenValidationResult(presentations);
    }
}
