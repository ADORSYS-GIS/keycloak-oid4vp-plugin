package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub;

/** Request body of {@code POST /v1/organizations/{id}/access-certificates}. */
public record AccessCertificateCreationRequest(String name, String csr, String environment, String supportUri) {}
