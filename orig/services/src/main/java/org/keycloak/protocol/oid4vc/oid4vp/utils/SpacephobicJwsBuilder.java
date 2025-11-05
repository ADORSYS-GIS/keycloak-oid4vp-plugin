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

package org.keycloak.protocol.oid4vc.oid4vp.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.keycloak.common.util.Base64Url;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.util.JsonSerialization;

import java.nio.charset.StandardCharsets;

/**
 * A JWS builder that avoids adding spaces in the pre-encoded JSON.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SpacephobicJwsBuilder extends JWSBuilder {

    @Override
    protected String encodeHeader(String sigAlgName) {
        StringBuilder builder = new StringBuilder("{");

        if (org.keycloak.crypto.Algorithm.Ed25519.equals(sigAlgName) || org.keycloak.crypto.Algorithm.Ed448.equals(sigAlgName)) {
            builder.append("\"alg\":\"").append(org.keycloak.crypto.Algorithm.EdDSA).append("\"");
            builder.append(",\"crv\":\"").append(sigAlgName).append("\"");
        } else {
            builder.append("\"alg\":\"").append(sigAlgName).append("\"");
        }

        if (type != null) builder.append(",\"typ\":\"").append(type).append("\"");
        if (kid != null) builder.append(",\"kid\":\"").append(kid).append("\"");
        if (x5t != null) builder.append(",\"x5t\":\"").append(x5t).append("\"");
        if (x5c != null && !x5c.isEmpty()) {
            builder.append(",\"x5c\":[");
            for (int i = 0; i < x5c.size(); i++) {
                String certificate = x5c.get(i);
                if (i > 0) {
                    builder.append(",");
                }
                builder.append("\"").append(certificate).append("\"");
            }
            builder.append("]");
        }
        if (jwk != null) {
            try {
                builder.append(",\"jwk\":").append(JsonSerialization.mapper.writeValueAsString(jwk));
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
        if (contentType != null) builder.append(",\"cty\":\"").append(contentType).append("\"");
        builder.append("}");
        return Base64Url.encode(builder.toString().getBytes(StandardCharsets.UTF_8));
    }
}
