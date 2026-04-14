package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * VerifierInfo for OpenID4VP Authorization Request
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class VerifierInfo {

    @JsonProperty("format")
    private String format;

    @JsonProperty("data")
    private String data;

    @JsonProperty("credential_ids")
    private List<String> credentialIds;

    public String getFormat() {
        return format;
    }

    public VerifierInfo setFormat(String format) {
        this.format = format;
        return this;
    }

    public String getData() {
        return data;
    }

    public VerifierInfo setData(String data) {
        this.data = data;
        return this;
    }

    public List<String> getCredentialIds() {
        return credentialIds;
    }

    public VerifierInfo setCredentialIds(List<String> credentialIds) {
        this.credentialIds = credentialIds;
        return this;
    }
}
