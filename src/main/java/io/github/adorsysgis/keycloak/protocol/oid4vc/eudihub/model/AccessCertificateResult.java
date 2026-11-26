package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model;

import com.fasterxml.jackson.annotation.JsonInclude;

/** The certificate returned to the admin UI and the name the EUDI Hub knows it by. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AccessCertificateResult(String accessCertificate, String name) {}
