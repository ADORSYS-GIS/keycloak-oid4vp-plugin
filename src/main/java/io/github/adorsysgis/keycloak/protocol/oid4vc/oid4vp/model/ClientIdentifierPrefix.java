package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * Client Identifier Prefix values defined by OpenID4VP Final 1.0.
 * <p>
 * Authorization requests carry the prefix as part of {@code client_id}.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-defined-client-identifier-p">Defined Client Identifier Prefixes</a>
 */
public enum ClientIdentifierPrefix {
    REDIRECT_URI("redirect_uri"),
    OPENID_FEDERATION("openid_federation"),
    DECENTRALIZED_IDENTIFIER("decentralized_identifier"),
    VERIFIER_ATTESTATION("verifier_attestation"),
    X509_SAN_DNS("x509_san_dns"),
    X509_HASH("x509_hash"),
    ORIGIN("origin");

    private final String value;

    ClientIdentifierPrefix(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }

    public static ClientIdentifierPrefix fromValue(String value) {
        for (ClientIdentifierPrefix prefix : ClientIdentifierPrefix.values()) {
            if (prefix.value.equalsIgnoreCase(value)) {
                return prefix;
            }
        }

        throw new IllegalArgumentException("Unknown client identifier prefix: " + value);
    }
}
