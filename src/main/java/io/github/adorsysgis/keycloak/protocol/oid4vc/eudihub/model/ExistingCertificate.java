package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model;

import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub.AccessCertificate;

/** A listed certificate that holds the signing key and its DER bytes. */
public record ExistingCertificate(AccessCertificate certificate, byte[] der) {}
