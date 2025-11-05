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

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * OpenID4VP Client ID Schemes
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#name-authorization-request">
 * Authorization Request</a>
 */
public enum ClientIdScheme {

    PRE_REGISTERED("pre-registered"),
    REDIRECT_URI("redirect_uri"),
    ENTITY_ID("entity_id"),
    DID("did"),
    VERIFIER_ATTESTATION("verifier_attestation"),
    X509_SAN_DNS("x509_san_dns"),
    X509_SAN_URI("x509_san_uri");

    private final String value;

    ClientIdScheme(String value) {
        this.value = value;
    }

    @JsonValue
    public String getValue() {
        return value;
    }
}
