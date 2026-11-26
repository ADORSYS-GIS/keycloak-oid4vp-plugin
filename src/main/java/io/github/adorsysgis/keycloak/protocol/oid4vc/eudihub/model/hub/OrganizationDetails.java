package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/** Response of {@code GET /v1/organizations/{id}}. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OrganizationDetails(ContactInformation contactInformation, List<String> environments) {

    /** Contact information of an organization. */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ContactInformation(List<String> supportUris) {}
}
