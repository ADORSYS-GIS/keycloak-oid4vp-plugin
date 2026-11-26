package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/** Response of {@code GET /v1/me}: the organizations the token's user belongs to. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OrganizationPage(List<OrganizationSummary> organizations) {}
