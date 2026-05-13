package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;

/**
 * Data context for an OpenID4VP authorization session.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthorizationContext {

    /**
     * The status of the authorization attempt.
     */
    @JsonProperty("status")
    private AuthorizationContextStatus status;

    /**
     * The authorization request as a link.
     * In cross-device flows, a QR code is generated from this link.
     */
    @JsonProperty("authorization_request")
    private String authorizationRequest;

    /**
     * The transaction ID associated with the authorization request.
     * Use this ID to inquire the status of any response to the request.
     * Must not be known beyond the authenticating party.
     */
    @JsonProperty("transaction_id")
    private String transactionId;

    /**
     * The request ID associated with the authorization request.
     * Unlike the transaction ID, it should not enable status inquiries.
     * Matches the state parameter in the request object.
     */
    @JsonProperty("request_id")
    private String requestId;

    /**
     * Yet another unguessable code associated with the authorization request.
     * In same-device flows, prompt the wallet to redirect to a URI embedding
     * this code upon successful OpenID4VP authentication.
     */
    @JsonProperty("response_code")
    private String responseCode;

    /**
     * Reference parent authentication session if any. This is used to link the
     * authorization context to an existing authentication session, for example
     * in the case of an OIDC login.
     */
    @JsonProperty("parent_auth_session_id")
    private String parentAuthSessionId;

    /**
     * Form action URL connecting back to parent authentication session.
     * Handy for completing redirection in same-device flows.
     */
    @JsonProperty("login_action_url")
    private String loginActionUrl;

    /**
     * Code challenge bound to API-driven authorization code redemption.
     */
    @JsonProperty("code_challenge")
    private String codeChallenge;

    /**
     * Code challenge method bound to API-driven authorization code redemption.
     */
    @JsonProperty("code_challenge_method")
    private String codeChallengeMethod;

    /**
     * The request object.
     */
    @JsonProperty("request_object")
    private RequestObject requestObject;

    /**
     * The request object as a JWT.
     */
    @JsonProperty("request_object_jwt")
    private String requestObjectJwt;

    /**
     * Ephemeral response-encryption key material for {@code direct_post.jwt}. Unwrapped in JSON so
     * {@code ephemeral_key} and {@code expected_encryption_kid} remain at the same level as other context fields.
     */
    @JsonUnwrapped
    private ResponseEncryptionContext responseEncryption;

    /**
     * An authorization code upon successful authorization.
     */
    @JsonProperty("authorization_code")
    private String authorizationCode;

    /**
     * An error category if the authorization attempt failed.
     */
    @JsonProperty("error")
    private ProcessingError error;

    /**
     * An error description if the authorization attempt failed.
     */
    @JsonProperty("error_description")
    private String errorDescription;

    public AuthorizationContextStatus getStatus() {
        return status;
    }

    public AuthorizationContext setStatus(AuthorizationContextStatus status) {
        this.status = status;
        return this;
    }

    public String getAuthorizationRequest() {
        return authorizationRequest;
    }

    public AuthorizationContext setAuthorizationRequest(String authorizationRequest) {
        this.authorizationRequest = authorizationRequest;
        return this;
    }

    public String getTransactionId() {
        return transactionId;
    }

    public AuthorizationContext setTransactionId(String transactionId) {
        this.transactionId = transactionId;
        return this;
    }

    public String getRequestId() {
        return requestId;
    }

    public AuthorizationContext setRequestId(String requestId) {
        this.requestId = requestId;
        return this;
    }

    public String getResponseCode() {
        return responseCode;
    }

    public AuthorizationContext setResponseCode(String responseCode) {
        this.responseCode = responseCode;
        return this;
    }

    public String getParentAuthSessionId() {
        return parentAuthSessionId;
    }

    public AuthorizationContext setParentAuthSessionId(String parentAuthSessionId) {
        this.parentAuthSessionId = parentAuthSessionId;
        return this;
    }

    public String getLoginActionUrl() {
        return loginActionUrl;
    }

    public AuthorizationContext setLoginActionUrl(String loginActionUrl) {
        this.loginActionUrl = loginActionUrl;
        return this;
    }

    public String getCodeChallenge() {
        return codeChallenge;
    }

    public AuthorizationContext setCodeChallenge(String codeChallenge) {
        this.codeChallenge = codeChallenge;
        return this;
    }

    public String getCodeChallengeMethod() {
        return codeChallengeMethod;
    }

    public AuthorizationContext setCodeChallengeMethod(String codeChallengeMethod) {
        this.codeChallengeMethod = codeChallengeMethod;
        return this;
    }

    public RequestObject getRequestObject() {
        return requestObject;
    }

    public AuthorizationContext setRequestObject(RequestObject requestObject) {
        this.requestObject = requestObject;
        return this;
    }

    public String getRequestObjectJwt() {
        return requestObjectJwt;
    }

    public AuthorizationContext setRequestObjectJwt(String requestObjectJwt) {
        this.requestObjectJwt = requestObjectJwt;
        return this;
    }

    public String getEphemeralKey() {
        return responseEncryption == null ? null : responseEncryption.getEphemeralKey();
    }

    public AuthorizationContext setEphemeralKey(String ephemeralKey) {
        if (ephemeralKey == null && emptyEncryptionKid()) {
            responseEncryption = null;
        } else {
            ensureResponseEncryption().setEphemeralKey(ephemeralKey);
        }
        return this;
    }

    public String getExpectedEncryptionKid() {
        return responseEncryption == null ? null : responseEncryption.getExpectedEncryptionKid();
    }

    public AuthorizationContext setExpectedEncryptionKid(String expectedEncryptionKid) {
        if (expectedEncryptionKid == null && emptyEphemeralKey()) {
            responseEncryption = null;
        } else {
            ensureResponseEncryption().setExpectedEncryptionKid(expectedEncryptionKid);
        }
        return this;
    }

    private boolean emptyEphemeralKey() {
        return responseEncryption == null || responseEncryption.getEphemeralKey() == null;
    }

    private boolean emptyEncryptionKid() {
        return responseEncryption == null || responseEncryption.getExpectedEncryptionKid() == null;
    }

    private ResponseEncryptionContext ensureResponseEncryption() {
        if (responseEncryption == null) {
            responseEncryption = new ResponseEncryptionContext();
        }
        return responseEncryption;
    }

    public String getAuthorizationCode() {
        return authorizationCode;
    }

    public AuthorizationContext setAuthorizationCode(String authorizationCode) {
        this.authorizationCode = authorizationCode;
        return this;
    }

    public ProcessingError getError() {
        return error;
    }

    public AuthorizationContext setError(ProcessingError error) {
        this.error = error;
        return this;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public AuthorizationContext setErrorDescription(String errorDescription) {
        this.errorDescription = errorDescription;
        return this;
    }
}
