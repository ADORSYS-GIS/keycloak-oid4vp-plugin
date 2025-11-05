/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.protocol.oid4vc.tokenstatus.http;

import org.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;

/**
 * Functional interface for fetching Status List JWT tokens.
 *
 * @author <a href="mailto:Forkim.Akwichek@adorsys.com">Forkim Akwichek</a>
 */
public interface StatusListJwtFetcher {

    /**
     * Performs an HTTP GET at the URI and returns the response as a JWT string.
     * This method is specifically for fetching Status List JWT tokens with the
     * appropriate Accept header (application/statuslist+jwt).
     *
     * @param uri The URI to fetch the Status List JWT from
     * @return The Status List JWT as a string
     * @throws ReferencedTokenValidationException if any issue arises or HTTP status not OK (200)
     */
    String fetchStatusListJwt(String uri) throws ReferencedTokenValidationException;
}
