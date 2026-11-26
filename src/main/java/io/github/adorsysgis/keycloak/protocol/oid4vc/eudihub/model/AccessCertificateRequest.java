package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model;

/** Request body of the access certificate request. */
public record AccessCertificateRequest(
        String token, String organizationId, String environment, String supportUri, String name) {}
