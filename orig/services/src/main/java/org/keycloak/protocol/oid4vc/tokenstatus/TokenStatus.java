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

package org.keycloak.protocol.oid4vc.tokenstatus;

/**
 * Enum representing the different token status values according to the IETF Token Status List specification.
 *
 * @author <a href="mailto:Forkim.Akwichek@adorsys.com">Forkim Akwichek</a>
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-11.html">Token Status List</a>
 */
public enum TokenStatus {

    /**
     * Token is valid (status value: 0)
     */
    VALID(0),

    /**
     * Token is invalid (status value: 1)
     */
    INVALID(1),

    /**
     * Token is suspended (status value: 2)
     */
    SUSPENDED(2),

    /**
     * Reserved for future use (status value: 3)
     */
    RESERVED(3);

    private final int value;

    TokenStatus(int value) {
        this.value = value;
    }

    /**
     * Gets the numeric value of this status.
     *
     * @return the numeric value
     */
    public int getValue() {
        return value;
    }

    /**
     * Gets the TokenStatus enum from a numeric value.
     *
     * @param value the numeric value
     * @return the corresponding TokenStatus enum, or null if not found
     */
    public static TokenStatus fromValue(int value) {
        for (TokenStatus status : values()) {
            if (status.value == value) {
                return status;
            }
        }
        return null;
    }

    /**
     * Checks if this status represents a valid token.
     *
     * @return true if the status is VALID, false otherwise
     */
    public boolean isValid() {
        return this == VALID;
    }
}
