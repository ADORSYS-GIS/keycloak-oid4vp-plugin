package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

/**
 * Page of access certificates.
 * Response of {@code GET /v1/organizations/{id}/access-certificates}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AccessCertificatePage(List<AccessCertificate> items) {}
