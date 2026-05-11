package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response payload to wallet upon successful authentication.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ResponseToWallet {

    @JsonProperty("redirect_uri")
    private String redirectUri;

    public ResponseToWallet() {}

    public ResponseToWallet(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }
}
