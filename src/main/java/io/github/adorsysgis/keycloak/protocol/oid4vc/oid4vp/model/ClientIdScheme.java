package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Client Identifier Prefix values used when building prefixed {@code client_id} strings.
 * <p>
 * This is a deployment/configuration concept for {@link io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.VerifierDiscoveryService};
 * it is not serialized as a draft-era {@code client_id_scheme} authorization request parameter.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public enum ClientIdScheme {
    PRE_REGISTERED("pre-registered"),
    REDIRECT_URI("redirect_uri"),
    ENTITY_ID("entity_id"),
    DID("did"),
    VERIFIER_ATTESTATION("verifier_attestation"),
    X509_SAN_DNS("x509_san_dns"),
    X509_SAN_URI("x509_san_uri"),
    X509_HASH("x509_hash");

    private final String value;

    ClientIdScheme(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    public static ClientIdScheme fromValue(String value) {
        for (ClientIdScheme scheme : ClientIdScheme.values()) {
            if (scheme.value.equalsIgnoreCase(value)) {
                return scheme;
            }
        }

        throw new IllegalArgumentException("Unknown client ID scheme: " + value);
    }
}
