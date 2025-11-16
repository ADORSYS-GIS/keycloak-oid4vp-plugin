package de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model.prex.ClaimFormat;

/**
 * Model for Client Metadata.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#name-verifier-metadata-client-me">
 * Verifier Metadata (Client Metadata)</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ClientMetadata {

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("vp_formats")
    private VpFormat vpFormat;

    public String getClientId() {
        return clientId;
    }

    public ClientMetadata setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public VpFormat getVpFormat() {
        return vpFormat;
    }

    public ClientMetadata setVpFormat(VpFormat vpFormat) {
        this.vpFormat = vpFormat;
        return this;
    }

    public static class VpFormat extends ClaimFormat {
    }
}
