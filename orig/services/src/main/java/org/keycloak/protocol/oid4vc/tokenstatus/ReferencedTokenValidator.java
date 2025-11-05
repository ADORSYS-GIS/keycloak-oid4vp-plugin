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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.jose.JOSE;
import org.keycloak.jose.JOSEParser;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import org.keycloak.util.JsonSerialization;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.List;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Validator for Referenced Token payloads
 *
 * @author <a href="mailto:Forkim.Akwichek@adorsys.com">Forkim Akwichek</a>
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-11.html">Token Status List</a>
 */
public class ReferencedTokenValidator {

    public static final String STATUS_FIELD = "status";
    public static final String STATUS_LIST_FIELD = "status_list";
    private static final String IDX_FIELD = "idx";
    private static final String URI_FIELD = "uri";
    private static final String BITS_FIELD = "bits";
    private static final String LST_FIELD = "lst";
    private static final String EXP_FIELD = "exp";

    private static final String JWT_TYPE_STATUS_LIST = "statuslist+jwt";

    private final StatusListJwtFetcher statusListJwtFetcher;

    public ReferencedTokenValidator(StatusListJwtFetcher statusListJwtFetcher) {
        this.statusListJwtFetcher = statusListJwtFetcher;
    }

    /**
     * Validates a Referenced Token payload by checking its status in the status list.
     * status claim is REQUIRED when using the status mechanism.
     *
     * @param tokenPayload The JSON payload of the Referenced Token
     * @throws ReferencedTokenValidationException if validation fails
     */
    public void validate(JsonNode tokenPayload) throws ReferencedTokenValidationException {
        try {
            // Validate basic token properties (expiration, etc.)
            validateBasicTokenProperties(tokenPayload);

            // Extract and validate status information
            StatusInfo statusInfo = extractStatusInfo(tokenPayload);

            // Fetch and validate status list token
            JsonNode statusListToken = fetchStatusListToken(statusInfo.uri);

            // Extract and validate status list data
            StatusList statusList = extractStatusList(statusListToken);

            // Read and validate the actual status value
            int statusValue = ReferencedTokenValidator.readStatusValue(statusList.lst, statusInfo.idx, statusList.bits);
            TokenStatus tokenStatus = TokenStatus.fromValue(statusValue);

            if (tokenStatus == null) {
                throw new ReferencedTokenValidationException("Unknown token status value: " + statusValue);
            }

            if (!tokenStatus.isValid()) {
                throw new ReferencedTokenValidationException(
                        "Token status is not valid. Status: " + tokenStatus.name() + " (value: " + statusValue + ")");
            }

        } catch (ReferencedTokenValidationException e) {
            // Re-throw validation exceptions as-is
            throw e;
        } catch (Exception e) {
            // Wrap other exceptions with context
            throw new ReferencedTokenValidationException("Failed to validate referenced token", e);
        }
    }

    /**
     * Validates basic token properties including expiration time.
     * This validation should be performed before status list validation.
     *
     * @param tokenPayload The JSON payload of the Referenced Token
     * @throws ReferencedTokenValidationException if basic validation fails
     */
    private void validateBasicTokenProperties(JsonNode tokenPayload) throws ReferencedTokenValidationException {
        JsonNode exp = tokenPayload.get(EXP_FIELD);
        if (exp != null && exp.isNumber()) {
            long expirationTime = exp.asLong();
            long currentTime = System.currentTimeMillis() / 1000;

            if (currentTime > expirationTime) {
                throw new ReferencedTokenValidationException(
                        "Token has expired. Expiration time: " + expirationTime + ", Current time: " + currentTime);
            }
        }
        // Additional basic validations can be added here as needed
    }

    /**
     * Extracts status information from the token payload.
     * According to IETF specification, the status claim is REQUIRED when using the status mechanism.
     *
     * @param tokenPayload The JSON payload of the Referenced Token
     * @return StatusInfo object containing index and URI
     * @throws ReferencedTokenValidationException if status information is missing or malformed
     */
    private StatusInfo extractStatusInfo(JsonNode tokenPayload) throws ReferencedTokenValidationException {
        JsonNode status = tokenPayload.get(STATUS_FIELD);
        if (status == null) {
            throw new ReferencedTokenValidationException("Missing required '" + STATUS_FIELD + "' claim");
        }

        if (!status.isObject()) {
            throw new ReferencedTokenValidationException("'" + STATUS_FIELD + "' claim must be a JSON object");
        }

        JsonNode statusList = status.get(STATUS_LIST_FIELD);
        if (statusList == null) {
            throw new ReferencedTokenValidationException("Missing required '" + STATUS_LIST_FIELD + "' claim");
        }

        if (!statusList.isObject()) {
            throw new ReferencedTokenValidationException("'" + STATUS_LIST_FIELD + "' claim must be a JSON object");
        }

        // Check for missing required fields before Jackson deserialization
        if (!statusList.has(IDX_FIELD)) {
            throw new ReferencedTokenValidationException("Missing required '" + IDX_FIELD + "' field");
        }
        if (!statusList.has(URI_FIELD)) {
            throw new ReferencedTokenValidationException("Missing required '" + URI_FIELD + "' field");
        }

        JsonNode idxNode = statusList.get(IDX_FIELD);
        JsonNode uriNode = statusList.get(URI_FIELD);

        // Check for null values
        if (uriNode.isNull()) {
            throw new ReferencedTokenValidationException("'" + URI_FIELD + "' cannot be null");
        }

        // Check data types
        if (!idxNode.isNumber()) {
            throw new ReferencedTokenValidationException("'" + IDX_FIELD + "' must be a number");
        }
        if (!uriNode.isTextual()) {
            throw new ReferencedTokenValidationException("'" + URI_FIELD + "' must be a string");
        }

        // Check for empty string
        if (uriNode.asText().trim().isEmpty()) {
            throw new ReferencedTokenValidationException("'" + URI_FIELD + "' cannot be empty");
        }

        // Check for negative index
        if (idxNode.asInt() < 0) {
            throw new ReferencedTokenValidationException("'" + IDX_FIELD + "' value must be non-negative");
        }

        try {
            StatusInfo statusInfo = JsonSerialization.mapper.treeToValue(statusList, StatusInfo.class);
            return statusInfo;
        } catch (JsonProcessingException e) {
            throw new ReferencedTokenValidationException("Failed to parse status information: " + e.getMessage(), e);
        }
    }

    /**
     * Fetches the status list token from the specified URI.
     * The status list server returns a JWT token, not raw JSON.
     *
     * @param uri The URI to fetch the status list token from
     * @return The status list token as JsonNode
     * @throws ReferencedTokenValidationException if fetching fails
     */
    private JsonNode fetchStatusListToken(String uri) throws ReferencedTokenValidationException {
        try {
            String jwtToken = statusListJwtFetcher.fetchStatusListJwt(uri);

            JOSE joseToken = JOSEParser.parse(jwtToken);

            if (!(joseToken instanceof JWSInput)) {
                throw new ReferencedTokenValidationException("Status List Token must be a signed JWS (JWT), got: " + joseToken.getClass().getSimpleName());
            }

            JWSInput jws = (JWSInput) joseToken;

            // Validate the JWT header type
            String typ = jws.getHeader().getType();
            if (typ == null || !typ.equals(JWT_TYPE_STATUS_LIST)) {
                throw new ReferencedTokenValidationException("Status List Token must have type 'statuslist+jwt', got: " + typ);
            }

            // Extract the payload and parse as JSON
            return jws.readJsonContent(JsonNode.class);

        } catch (JWSInputException e) {
            throw new ReferencedTokenValidationException("Failed to parse Status List JWT from: " + uri, e);
        }
    }

    /**
     * Extracts status list information from the status list token.
     *
     * @param statusListToken The status list token as JsonNode
     * @return StatusList object containing bits and lst
     * @throws ReferencedTokenValidationException if extraction fails
     */
    private StatusList extractStatusList(JsonNode statusListToken) throws ReferencedTokenValidationException {
        JsonNode statusList = statusListToken.get(STATUS_LIST_FIELD);
        if (statusList == null) {
            throw new ReferencedTokenValidationException("Missing '" + STATUS_LIST_FIELD + "' claim in status list token");
        }

        // Check for missing required fields before Jackson deserialization
        if (!statusList.has(BITS_FIELD)) {
            throw new ReferencedTokenValidationException("Missing required '" + BITS_FIELD + "' field");
        }
        if (!statusList.has(LST_FIELD)) {
            throw new ReferencedTokenValidationException("Missing required '" + LST_FIELD + "' field");
        }

        JsonNode bitsNode = statusList.get(BITS_FIELD);
        JsonNode lstNode = statusList.get(LST_FIELD);

        // Check for null values
        if (lstNode.isNull()) {
            throw new ReferencedTokenValidationException("'" + LST_FIELD + "' cannot be null");
        }

        // Check data types
        if (!bitsNode.isNumber()) {
            throw new ReferencedTokenValidationException("'" + BITS_FIELD + "' field must be a number");
        }
        if (!lstNode.isTextual()) {
            throw new ReferencedTokenValidationException("'" + LST_FIELD + "' field must be a string");
        }

        // Check for empty string
        if (lstNode.asText().trim().isEmpty()) {
            throw new ReferencedTokenValidationException("'" + LST_FIELD + "' cannot be empty");
        }

        // Check for valid bits value
        int bitsValue = bitsNode.asInt();
        if (!List.of(1, 2, 4, 8).contains(bitsValue)) {
            throw new ReferencedTokenValidationException("'" + BITS_FIELD + "' must be 1, 2, 4, or 8");
        }

        try {
            StatusList statusListObj = JsonSerialization.mapper.treeToValue(statusList, StatusList.class);
            return statusListObj;
        } catch (JsonProcessingException e) {
            throw new ReferencedTokenValidationException("Failed to parse status list information: " + e.getMessage(), e);
        }
    }

    /**
     * Decodes and decompresses the status list data.
     *
     * @param lst The base64url-encoded, DEFLATE-compressed status list
     * @return The decompressed byte array
     * @throws ReferencedTokenValidationException if decoding/decompression fails
     */
    public static byte[] decodeAndDecompress(String lst) throws ReferencedTokenValidationException {
        byte[] compressed;

        try {
            compressed = Base64.getUrlDecoder().decode(lst);
        } catch (IllegalArgumentException e) {
            throw new ReferencedTokenValidationException("Failed to decode base64url status list", e);
        }

        // Decompress using DEFLATE with ZLIB wrapper
        Inflater inflater = new Inflater();
        inflater.setInput(compressed);

        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream(compressed.length)) {
            byte[] buffer = new byte[1024];

            while (!inflater.finished()) {
                int count = inflater.inflate(buffer);
                if (count == 0 && inflater.needsInput()) {
                    throw new DataFormatException("Unexpected end of input");
                }

                outputStream.write(buffer, 0, count);
            }

            return outputStream.toByteArray();
        } catch (DataFormatException | IOException e) {
            throw new ReferencedTokenValidationException("Failed to decompress status list", e);
        } finally {
            inflater.end();
        }
    }

    /**
     * Reads a status value from the status list at the specified index.
     *
     * @param lst  The base64url-encoded, DEFLATE-compressed status list
     * @param idx  The token index to read
     * @param bits The number of bits per status (1, 2, 4, or 8)
     * @return The status value at the given index
     * @throws ReferencedTokenValidationException if the operation fails
     */
    public static int readStatusValue(String lst, int idx, int bits) throws ReferencedTokenValidationException {
        byte[] bytes = decodeAndDecompress(lst);
        return readStatusValueFromBytes(bytes, idx, bits);
    }

    /**
     * Helper method to read status value from a byte array.
     *
     * @param bytes The decompressed byte array
     * @param idx   The token index to read
     * @param bits  The number of bits per status (1, 2, 4, or 8)
     * @return The status value at the given index
     * @throws ReferencedTokenValidationException if the operation fails
     */
    public static int readStatusValueFromBytes(byte[] bytes, int idx, int bits) throws ReferencedTokenValidationException {
        if (!List.of(1, 2, 4, 8).contains(bits)) {
            throw new ReferencedTokenValidationException("Unsupported bits value: " + bits);
        }

        // Calculate total number of entries that can fit in the byte array
        int totalBits = bytes.length * 8;
        int totalEntries = totalBits / bits;

        if (idx < 0 || idx >= totalEntries) {
            throw new ReferencedTokenValidationException(
                    "Index " + idx + " out of range (0-" + (totalEntries - 1) + ")");
        }

        // Calculate the starting bit position for this token
        int startBit = idx * bits;

        // Calculate which byte contains the start of our status value
        int byteIdx = startBit / 8;

        // Calculate the bit position within that byte
        int bitPosInByte = startBit % 8;

        // Create a mask for the number of bits we need to read
        int mask = (1 << bits) - 1;

        // Read the status value
        // With bits values of 1, 2, 4, or 8, status values never span across byte boundaries
        int statusValue = (bytes[byteIdx] >> bitPosInByte) & mask;

        return statusValue;
    }

    /**
     * Exception thrown when Referenced Token validation fails.
     * This exception provides detailed information about what validation rule was violated.
     */
    public static class ReferencedTokenValidationException extends Exception {
        public ReferencedTokenValidationException(String message) {
            super(message);
        }

        public ReferencedTokenValidationException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Record to hold status information from the Referenced Token.
     *
     * @param idx The token index in the status list (must be non-negative)
     * @param uri The URI of the status list token (must not be null or empty)
     */
    public static record StatusInfo(
            @JsonProperty(IDX_FIELD) int idx,
            @JsonProperty(URI_FIELD) String uri
    ) {
        @JsonCreator
        public StatusInfo {
            // Validation handled in extractStatusInfo method
        }
    }

    /**
     * Record to hold status list information from the Status List Token.
     *
     * @param bits The number of bits per status value (must be 1, 2, 4, or 8)
     * @param lst  The base64url-encoded, DEFLATE-compressed status list (must not be null or empty)
     */
    public static record StatusList(
            @JsonProperty(BITS_FIELD) int bits,
            @JsonProperty(LST_FIELD) String lst
    ) {
        @JsonCreator
        public StatusList {
            // Validation handled in extractStatusList method
        }
    }
}
