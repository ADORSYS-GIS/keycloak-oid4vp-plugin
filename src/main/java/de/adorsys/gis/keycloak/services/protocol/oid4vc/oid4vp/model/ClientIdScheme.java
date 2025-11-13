package de.adorsys.gis.keycloak.services.protocol.oid4vc.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * OpenID4VP Client ID Schemes
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#name-authorization-request">
 * Authorization Request</a>
 */
public enum ClientIdScheme {

    PRE_REGISTERED("pre-registered"),
    REDIRECT_URI("redirect_uri"),
    ENTITY_ID("entity_id"),
    DID("did"),
    VERIFIER_ATTESTATION("verifier_attestation"),
    X509_SAN_DNS("x509_san_dns"),
    X509_SAN_URI("x509_san_uri");

    private final String value;

    ClientIdScheme(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }
}
