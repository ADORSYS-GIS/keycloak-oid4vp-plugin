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
import org.keycloak.protocol.oid4vc.oid4vp.model.prex.ClaimFormat;

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
