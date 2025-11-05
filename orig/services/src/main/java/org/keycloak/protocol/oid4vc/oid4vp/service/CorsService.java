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

package org.keycloak.protocol.oid4vc.oid4vp.service;

import org.keycloak.services.cors.Cors;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Service class for handling CORS (Cross-Origin Resource Sharing) policies.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class CorsService {

    private static final String HTTP_METHOD_OPTIONS = "OPTIONS";
    private static final String HTTP_METHOD_POST = "POST";

    /**
     * Creates a CORS policy that allows all origins.
     * This is used for endpoints that need to be accessible from any origin.
     *
     * @return CORS builder configured for open access
     */
    public static Cors open() {
        return Cors.builder().allowAllOrigins().auth();
    }

    /**
     * Creates a CORS policy for preflight requests.
     * This allows OPTIONS and POST methods from any origin.
     *
     * @return CORS builder configured for preflight requests
     */
    public static Cors openPreflight() {
        return Cors.builder().preflight()
                .allowedMethods(HTTP_METHOD_OPTIONS, HTTP_METHOD_POST)
                .auth();
    }

    /**
     * Creates a CORS policy based on the client's configured web origins.
     * This restricts access to only the origins configured for the client
     * associated with the authentication session.
     *
     * @param authSession the authentication session containing client information
     * @return CORS builder configured for client-specific origins
     */
    public static Cors forWebOrigins(AuthenticationSessionModel authSession) {
        String[] clientWebOrigins = authSession.getClient().getWebOrigins().toArray(new String[0]);
        return Cors.builder()
                .allowedOrigins(clientWebOrigins)
                .auth();
    }
}
