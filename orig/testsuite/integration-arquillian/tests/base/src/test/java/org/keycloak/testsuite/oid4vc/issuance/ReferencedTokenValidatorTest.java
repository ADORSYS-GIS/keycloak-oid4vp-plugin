package org.keycloak.testsuite.oid4vc.issuance;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import org.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator;
import org.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;
import org.keycloak.util.JsonSerialization;

import java.util.Base64;
import java.util.List;

/**
 * Test for ReferencedTokenValidator using the official IETF specification test vectors.
 *
 * @author <a href="mailto:Forkim.Akwichek@adorsys.com">Forkim Akwichek</a>
 */
public class ReferencedTokenValidatorTest {

    // IETF Test Vector Constants
    private static final String IETF_1BIT_TEST_VECTOR = "eNrt3AENwCAMAEGogklACtKQPg9LugC9k_ACvreiogEAAKkeCQAAAAAAAAAAAAAAAAAAAIBylgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAXG9IAAAAAAAAAPwsJAAAAAAAAAAAAAAAvhsSAAAAAAAAAAAA7KpLAAAAAAAAAAAAAAAAAAAAAJsLCQAAAAAAAAAAADjelAAAAAAAAAAAKjDMAQAAAACAZC8L2AEb";

    private static final String IETF_2BIT_TEST_VECTOR = "eNrt2zENACEQAEEuoaBABP5VIO01fCjIHTMStt9ovGVIAAAAAABAbiEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEB5WwIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAID0ugQAAAAAAAAAAAAAAAAAQG12SgAAAAAAAAAAAAAAAAAAAAAAAAAAAOCSIQEAAAAAAAAAAAAAAAAAAAAAAAD8ExIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwJEuAQAAAAAAAAAAAAAAAAAAAAAAAMB9SwIAAAAAAAAAAAAAAAAAAACoYUoAAAAAAAAAAAAAAEBqH81gAQw";

    private static final String IETF_1BIT_SMALL_TEST_VECTOR = "eNrbuRgAAhcBXQ";

    private static final String IETF_2BIT_SMALL_TEST_VECTOR = "eNo76fITAAPfAgc";

    private ReferencedTokenValidator validator;

    @Before
    public void setUp() {

        // Create a mock Status List JWT fetcher
        StatusListJwtFetcher mockStatusListJwtFetcher = uri -> {
            // Return a mock JWT token that contains the status list data
            // In a real scenario, this would be a signed JWT with the status_list claim
            String mockJwtPayload = """
                    {
                        "status_list": {
                            "bits": 1,
                            "lst": "%s"
                        }
                    }
                    """.formatted(IETF_1BIT_TEST_VECTOR);

            // Create a simple JWT structure (header.payload.signature)
            String header = "eyJ0eXAiOiJzdGF0dXNsaXN0K2p3dCJ9"; // {"typ":"statuslist+jwt"}
            String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(mockJwtPayload.getBytes());
            String signature = "mock_signature";

            return header + "." + payload + "." + signature;
        };

        validator = new ReferencedTokenValidator(mockStatusListJwtFetcher);
    }

    @Test
    public void testIETFSpecVectorSize_1Bit() throws Exception {
        // Test to understand the actual size of the IETF 1-bit test vector
        String lst = IETF_1BIT_TEST_VECTOR;
        int bits = 1;

        // Try to read beyond the valid range - should throw exception
        try {
            int maxIndex = 1048576; // Known size from IETF spec (2^20)
            ReferencedTokenValidator.readStatusValue(lst, maxIndex, bits);
            Assert.fail("Expected test vector to fail for index " + maxIndex + " but it succeeded.");
        } catch (ReferencedTokenValidationException e) {
            // Assert the exact expected error message
            Assert.assertEquals("Index 1048576 out of range (0-1048575)", e.getMessage());
        }
    }

    @Test
    public void testIETFSpecVectorSize_2Bit() throws Exception {
        // Test to understand the actual size of the IETF 2-bit test vector
        String lst = IETF_2BIT_TEST_VECTOR;
        int bits = 2;

        // Try to read beyond the valid range - should throw exception
        try {
            int maxIndex = 1048576; // Known size from IETF spec (2^20)
            ReferencedTokenValidator.readStatusValue(lst, maxIndex, bits);
            Assert.fail("Expected test vector to fail for index " + maxIndex + " but it succeeded.");
        } catch (ReferencedTokenValidationException e) {
            // Assert the exact expected error message
            Assert.assertEquals("Index 1048576 out of range (0-1048575)", e.getMessage());
        }
    }

    @Test
    public void testIETF_1Bit_OfficialTestVector() throws Exception {
        // Test the official IETF 1-bit test vector from the specification
        // This test vector has 2^20 = 1,048,576 entries (range 0-1048575)
        // Only specific indices have status=1, all others should be 0

        String lst = IETF_1BIT_TEST_VECTOR;
        int bits = 1;

        // Test the specific indices that should have status = 1 according to the IETF spec
        // Only test indices within the valid range (0-1048575 for 2^20 entries)
        int[] indicesWithStatus1 = {0, 1993, 25460, 159495, 495669, 554353, 645645, 723232, 854545, 934534, 1000345};
        for (int idx : indicesWithStatus1) {
            Assert.assertEquals("status[" + idx + "] should be 1", 1, ReferencedTokenValidator.readStatusValue(lst, idx, bits));
        }

        // Test some indices that should have status = 0 (VALID) - not mentioned in spec
        for (int idx : List.of(1, 100, 1000, 5000, 10000, 15000)) {
            Assert.assertEquals("status[" + idx + "] should be 0 (not mentioned in spec)", 0, ReferencedTokenValidator.readStatusValue(lst, idx, bits));
        }

        // Test boundary conditions
        Assert.assertEquals("status[1048575] should be 0 (last valid index)", 0, ReferencedTokenValidator.readStatusValue(lst, 1048575, bits));
    }

    @Test
    public void testIETF_2Bit_OfficialTestVector() throws Exception {
        // Test the official IETF 2-bit test vector from the specification
        // This test vector has 2^20 = 1,048,576 entries (range 0-1048575)
        // Only specific indices have non-zero status values, all others should be 0

        String lst = IETF_2BIT_TEST_VECTOR;
        int bits = 2;

        // Test the specific indices that should have specific status values according to the IETF spec
        // Only test indices within the valid range (0-1048575 for 2^20 entries)
        int[] indicesWithStatus1 = {0, 25460, 495669, 554353, 723232, 854545};
        int[] indicesWithStatus2 = {1993, 645645, 934534};
        int[] indicesWithStatus3 = {159495, 1000345};

        for (int idx : indicesWithStatus1) {
            Assert.assertEquals("status[" + idx + "] should be 1", 1, ReferencedTokenValidator.readStatusValue(lst, idx, bits));
        }
        for (int idx : indicesWithStatus2) {
            Assert.assertEquals("status[" + idx + "] should be 2", 2, ReferencedTokenValidator.readStatusValue(lst, idx, bits));
        }
        for (int idx : indicesWithStatus3) {
            Assert.assertEquals("status[" + idx + "] should be 3", 3, ReferencedTokenValidator.readStatusValue(lst, idx, bits));
        }

        // Test some indices that should have status = 0 (VALID) - not mentioned in spec
        for (int idx : List.of(1, 100, 1000, 5000, 10000, 12000)) {
            Assert.assertEquals("status[" + idx + "] should be 0 (not mentioned in spec)", 0, ReferencedTokenValidator.readStatusValue(lst, idx, bits));
        }

        // Test boundary conditions
        Assert.assertEquals("status[1048575] should be 0 (last valid index)", 0, ReferencedTokenValidator.readStatusValue(lst, 1048575, bits));
    }

    @Test
    public void testIETF_2Bit_Small() throws Exception {
        // Test the small 2-bit example from the IETF specification
        // This example has 12 Referenced Tokens with 2-bit status values
        // status[0]=1, status[1]=2, status[2]=0, status[3]=3, etc.

        // The compressed and encoded string for the example
        // Original bytes: [0xC9, 0x44, 0xF9] (3 bytes, 24 bits, 12 status values)
        String lst = IETF_2BIT_SMALL_TEST_VECTOR;
        int bits = 2;

        // Test all 12 status values according to the IETF spec example
        int[] expectedValues = {1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3};
        for (int i = 0; i < expectedValues.length; i++) {
            Assert.assertEquals("status[" + i + "] should be " + expectedValues[i], expectedValues[i], ReferencedTokenValidator.readStatusValue(lst, i, bits));
        }

        // Test that accessing beyond the valid range throws an exception
        try {
            ReferencedTokenValidator.readStatusValue(lst, 12, bits);
            Assert.fail("Should throw exception for index 12 (beyond valid range 0-11)");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention out of range",
                    e.getMessage().contains("out of range"));
        }
    }

    @Test
    public void testIETF_1Bit_Small() throws Exception {
        // Test the small 1-bit example from the IETF specification
        // This example has 16 Referenced Tokens with 1-bit status values
        // status[0]=1, status[1]=0, status[2]=0, status[3]=1, etc.

        // The compressed and encoded string for the example
        // Original bytes: [0xB9, 0xA3] (2 bytes, 16 bits, 16 status values)
        String lst = IETF_1BIT_SMALL_TEST_VECTOR;
        int bits = 1;

        // Test all 16 status values
        int[] expectedValues = {1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1};
        for (int i = 0; i < expectedValues.length; i++) {
            Assert.assertEquals("status[" + i + "] should be " + expectedValues[i], expectedValues[i], ReferencedTokenValidator.readStatusValue(lst, i, bits));
        }

        // Test that accessing beyond the valid range throws an exception
        try {
            ReferencedTokenValidator.readStatusValue(lst, 16, bits);
            Assert.fail("Should throw exception for index 16 (beyond valid range 0-15)");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention out of range",
                    e.getMessage().contains("out of range"));
        }
    }

    @Test
    public void testIETF_1Bit_OfficialTestVector_WithMock() throws Exception {
        // Test the official IETF 1-bit test vector using the mock HTTP fetcher

        // Test with status[0] = 1 (INVALID) - should throw exception
        JsonNode invalidTokenPayload = JsonSerialization.mapper.readTree("""
                {
                    "status": {
                        "status_list": {
                            "idx": 0,
                            "uri": "https://status.example.com/list"
                        }
                    }
                }
                """);

        ReferencedTokenValidationException exception = Assert.assertThrows(
                "Should throw exception for invalid status (status[0] = 1)",
                ReferencedTokenValidationException.class,
                () -> validator.validate(invalidTokenPayload)
        );
        Assert.assertTrue("Exception should mention invalid status. Actual message: " + exception.getMessage(),
                exception.getMessage().contains("Token status is not valid"));

        // Test with status[1] = 0 (VALID) - should pass
        JsonNode validTokenPayload = JsonSerialization.mapper.readTree("""
                {
                    "status": {
                        "status_list": {
                            "idx": 1,
                            "uri": "https://status.example.com/list"
                        }
                    }
                }
                """);

        // This should pass because status[1] = 0 (VALID)
        validator.validate(validTokenPayload);
    }

    @Test
    public void testIETF_2Bit_OfficialTestVector_WithMock() throws Exception {
        // Test the official IETF 2-bit test vector using the mock HTTP fetcher

        // Test with status[0] = 1 (INVALID)
        JsonNode invalidTokenPayload = JsonSerialization.mapper.readTree("""
                {
                    "status": {
                        "status_list": {
                            "idx": 0,
                            "uri": "https://status.example.com/list"
                        }
                    }
                }
                """);

        ReferencedTokenValidationException exception1 = Assert.assertThrows(
                "Should throw exception for invalid status (status[0] = 1)",
                ReferencedTokenValidationException.class,
                () -> validator.validate(invalidTokenPayload)
        );
        Assert.assertTrue("Exception should mention invalid status",
                exception1.getMessage().contains("Token status is not valid"));

        // Test with status[1993] = 2 (SUSPENDED)
        JsonNode suspendedTokenPayload = JsonSerialization.mapper.readTree("""
                {
                    "status": {
                        "status_list": {
                            "idx": 1993,
                            "uri": "https://status.example.com/list"
                        }
                    }
                }
                """);

        ReferencedTokenValidationException exception2 = Assert.assertThrows(
                "Should throw exception for suspended status (status[1993] = 2)",
                ReferencedTokenValidationException.class,
                () -> validator.validate(suspendedTokenPayload)
        );
        Assert.assertTrue("Exception should mention invalid status",
                exception2.getMessage().contains("Token status is not valid"));

        // Test with a valid status (any index not mentioned in spec should be 0)
        JsonNode validTokenPayload = JsonSerialization.mapper.readTree("""
                {
                    "status": {
                        "status_list": {
                            "idx": 1,
                            "uri": "https://status.example.com/list"
                        }
                    }
                }
                """);

        // This should pass because status[1] = 0 (VALID)
        validator.validate(validTokenPayload);
    }


    @Test
    public void testRequiredFieldsEnforcement() throws Exception {

        try {
            JsonNode tokenPayload = JsonSerialization.mapper.readTree("{}");
            validator.validate(tokenPayload);
            Assert.fail("Should throw exception for missing 'status' claim");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention missing status claim",
                    e.getMessage().contains("Missing required 'status' claim"));
        }

        try {
            JsonNode tokenPayload = JsonSerialization.mapper.readTree("{\"status\": {}}");
            validator.validate(tokenPayload);
            Assert.fail("Should throw exception for missing 'status_list'");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention missing status_list",
                    e.getMessage().contains("Missing required 'status_list'"));
        }

        try {
            JsonNode tokenPayload = JsonSerialization.mapper.readTree("{\"status\": {\"status_list\": {\"idx\": -1, \"uri\": \"https://example.com\"}}}");
            validator.validate(tokenPayload);
            Assert.fail("Should throw exception for negative 'idx' value");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention non-negative idx",
                    e.getMessage().contains("non-negative"));
        }

        try {
            JsonNode tokenPayload = JsonSerialization.mapper.readTree("{\"status\": {\"status_list\": {\"idx\": 999999999, \"uri\": \"https://example.com\"}}}");
            validator.validate(tokenPayload);
            Assert.fail("Should throw exception for very large 'idx' value");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention out of range",
                    e.getMessage().contains("out of range"));
        }

        // Test missing idx field
        try {
            JsonNode tokenPayload = JsonSerialization.mapper.readTree("{\"status\": {\"status_list\": {\"uri\": \"https://example.com\"}}}");
            validator.validate(tokenPayload);
            Assert.fail("Should throw exception for missing 'idx' field");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention missing idx field",
                    e.getMessage().contains("Missing required 'idx' field"));
        }

        // Test missing uri field
        try {
            JsonNode tokenPayload = JsonSerialization.mapper.readTree("{\"status\": {\"status_list\": {\"idx\": 123}}}");
            validator.validate(tokenPayload);
            Assert.fail("Should throw exception for missing 'uri' field");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention missing uri field",
                    e.getMessage().contains("Missing required 'uri' field"));
        }

        // Test null uri value
        try {
            JsonNode tokenPayload = JsonSerialization.mapper.readTree("{\"status\": {\"status_list\": {\"idx\": 123, \"uri\": null}}}");
            validator.validate(tokenPayload);
            Assert.fail("Should throw exception for null 'uri' value");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention uri cannot be null",
                    e.getMessage().contains("cannot be null"));
        }

        // Test empty uri string
        try {
            JsonNode tokenPayload = JsonSerialization.mapper.readTree("{\"status\": {\"status_list\": {\"idx\": 123, \"uri\": \"\"}}}");
            validator.validate(tokenPayload);
            Assert.fail("Should throw exception for empty 'uri' value");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention uri cannot be empty",
                    e.getMessage().contains("cannot be empty"));
        }

        // Test wrong idx data type
        try {
            JsonNode tokenPayload = JsonSerialization.mapper.readTree("{\"status\": {\"status_list\": {\"idx\": \"not-a-number\", \"uri\": \"https://example.com\"}}}");
            validator.validate(tokenPayload);
            Assert.fail("Should throw exception for wrong 'idx' data type");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention idx must be a number",
                    e.getMessage().contains("must be a number"));
        }

        // Test wrong uri data type
        try {
            JsonNode tokenPayload = JsonSerialization.mapper.readTree("{\"status\": {\"status_list\": {\"idx\": 123, \"uri\": 456}}}");
            validator.validate(tokenPayload);
            Assert.fail("Should throw exception for wrong 'uri' data type");
        } catch (ReferencedTokenValidationException e) {
            Assert.assertTrue("Exception should mention uri must be a string",
                    e.getMessage().contains("must be a string"));
        }
    }
}
