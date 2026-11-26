package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Organization entry of {@code GET /v1/me}. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record OrganizationSummary(String id, String name) {}
