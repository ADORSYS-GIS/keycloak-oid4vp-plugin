/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.protocol.oid4vc.oid4vp.model.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;

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
