package io.github.adorsysgis.keycloak.protocol.oid4vc.presentation;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

/**
 * RFC 9470 authorization challenge response returned when an interactive
 * presentation is still required before issuance can proceed.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthorizationChallengeResponse {

    @JsonProperty("error")
    private String error;

    @JsonProperty("auth_session")
    private String authSession;

    @JsonProperty("interaction_type_required")
    private String interactionTypeRequired;

    @JsonProperty("openid4vp_request")
    private JsonNode openid4vpRequest;

    @JsonProperty("authorization_code")
    private String authorizationCode;

    public AuthorizationChallengeResponse() {}

    public AuthorizationChallengeResponse(String error, String authSession) {
        this.error = error;
        this.authSession = authSession;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getAuthSession() {
        return authSession;
    }

    public void setAuthSession(String authSession) {
        this.authSession = authSession;
    }

    public String getInteractionTypeRequired() {
        return interactionTypeRequired;
    }

    public AuthorizationChallengeResponse setInteractionTypeRequired(String interactionTypeRequired) {
        this.interactionTypeRequired = interactionTypeRequired;
        return this;
    }

    public JsonNode getOpenid4vpRequest() {
        return openid4vpRequest;
    }

    public AuthorizationChallengeResponse setOpenid4vpRequest(JsonNode openid4vpRequest) {
        this.openid4vpRequest = openid4vpRequest;
        return this;
    }

    public String getAuthorizationCode() {
        return authorizationCode;
    }

    public AuthorizationChallengeResponse setAuthorizationCode(String authorizationCode) {
        this.authorizationCode = authorizationCode;
        return this;
    }
}
