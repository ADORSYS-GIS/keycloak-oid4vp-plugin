package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** RFC 9457 problem detail returned by the EUDI Hub. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ProblemDetail(String detail, String title) {}
