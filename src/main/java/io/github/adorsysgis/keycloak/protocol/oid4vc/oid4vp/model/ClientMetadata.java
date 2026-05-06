package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.ClaimFormat;
import java.util.List;
import org.keycloak.jose.jwk.JSONWebKeySet;

/**
 * Model for Client Metadata.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#name-verifier-metadata-client-me">
 * Verifier Metadata (Client Metadata)</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ClientMetadata {

    @JsonProperty("vp_formats_supported")
    private VpFormat vpFormat;

    @JsonProperty("jwks")
    private JSONWebKeySet jwks;

    @JsonProperty("encrypted_response_enc_values_supported")
    private List<String> encryptedResponseEncValuesSupported;

    @JsonProperty("encrypted_response_alg_values_supported")
    private List<String> encryptedResponseAlgValuesSupported;

    public VpFormat getVpFormat() {
        return vpFormat;
    }

    public ClientMetadata setVpFormat(VpFormat vpFormat) {
        this.vpFormat = vpFormat;
        return this;
    }

    public JSONWebKeySet getJwks() {
        return jwks;
    }

    public ClientMetadata setJwks(JSONWebKeySet jwks) {
        this.jwks = jwks;
        return this;
    }

    public List<String> getEncryptedResponseEncValuesSupported() {
        return encryptedResponseEncValuesSupported;
    }

    public ClientMetadata setEncryptedResponseEncValuesSupported(List<String> encryptedResponseEncValuesSupported) {
        this.encryptedResponseEncValuesSupported = encryptedResponseEncValuesSupported;
        return this;
    }

    public List<String> getEncryptedResponseAlgValuesSupported() {
        return encryptedResponseAlgValuesSupported;
    }

    public ClientMetadata setEncryptedResponseAlgValuesSupported(List<String> encryptedResponseAlgValuesSupported) {
        this.encryptedResponseAlgValuesSupported = encryptedResponseAlgValuesSupported;
        return this;
    }

    public static class VpFormat extends ClaimFormat {}
}
