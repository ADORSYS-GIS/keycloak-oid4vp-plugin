package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Model for an access certificate.
 * Response of {@code POST /v1/organizations/{id}/access-certificates}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AccessCertificate(
        String id, String name, AccessCertificateStatus status, String environment, String expirationDate) {}
