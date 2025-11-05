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

package org.keycloak.protocol.oid4vc.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationDefinition;
import org.keycloak.representations.JsonWebToken;

/**
 * Request object payload for OpenID4VP Authorization Request.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#name-authorization-request">
 * Authorization Request</a>
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class RequestObject extends JsonWebToken {

    @JsonProperty("state")
    private String state;

    @JsonProperty("response_type")
    private ResponseType responseType;

    @JsonProperty("response_mode")
    private ResponseMode responseMode;

    @JsonProperty("redirect_uri")
    private String redirectUri;

    @JsonProperty("response_uri")
    private String responseUri;

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("client_id_scheme")
    private ClientIdScheme clientIdScheme;

    @JsonProperty("nonce")
    private String nonce;

    @JsonProperty("scope")
    private String scope;

    @JsonProperty("presentation_definition")
    private PresentationDefinition presentationDefinition;

    @JsonProperty("client_metadata")
    private ClientMetadata clientMetadata;

    public String getState() {
        return state;
    }

    public RequestObject setState(String state) {
        this.state = state;
        return this;
    }

    public ResponseType getResponseType() {
        return responseType;
    }

    public RequestObject setResponseType(ResponseType responseType) {
        this.responseType = responseType;
        return this;
    }

    public ResponseMode getResponseMode() {
        return responseMode;
    }

    public RequestObject setResponseMode(ResponseMode responseMode) {
        this.responseMode = responseMode;
        return this;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public RequestObject setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
        return this;
    }

    public String getResponseUri() {
        return responseUri;
    }

    public RequestObject setResponseUri(String responseUri) {
        this.responseUri = responseUri;
        return this;
    }

    public String getClientId() {
        return clientId;
    }

    public RequestObject setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public ClientIdScheme getClientIdScheme() {
        return clientIdScheme;
    }

    public RequestObject setClientIdScheme(ClientIdScheme clientIdScheme) {
        this.clientIdScheme = clientIdScheme;
        return this;
    }

    public String getNonce() {
        return nonce;
    }

    public RequestObject setNonce(String nonce) {
        this.nonce = nonce;
        return this;
    }

    public String getScope() {
        return scope;
    }

    public RequestObject setScope(String scope) {
        this.scope = scope;
        return this;
    }

    public PresentationDefinition getPresentationDefinition() {
        return presentationDefinition;
    }

    public RequestObject setPresentationDefinition(PresentationDefinition presentationDefinition) {
        this.presentationDefinition = presentationDefinition;
        return this;
    }

    public ClientMetadata getClientMetadata() {
        return clientMetadata;
    }

    public RequestObject setClientMetadata(ClientMetadata clientMetadata) {
        this.clientMetadata = clientMetadata;
        return this;
    }

    public RequestObject setIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public RequestObject setAudience(String... audience) {
        this.audience = audience;
        return this;
    }
}
