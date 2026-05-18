package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.CredentialSet;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.VCFormat;

/**
 * Covers final-spec vp_token matching rules for DCQL query IDs, presentation arrays,
 * credential-set satisfaction, and SD-JWT candidate extraction.
 */
class VpTokenCandidateExtractorTest {

    private static final String PID_QUERY_ID = "pid";
    private static final String ALT_QUERY_ID = "pid_alt";

    private final VpTokenCandidateExtractor extractor = new VpTokenCandidateExtractor();

    @Test
    void shouldExtractSingleSdJwtPresentationByCredentialQueryId() throws Exception {
        DcqlQuery query = query(List.of(credential(PID_QUERY_ID, VCFormat.SD_JWT_VC, null)), null);
        ResponseObject responseObject = responseObject("""
                {"pid":["sd-jwt-vp"]}
                """);

        List<String> candidates = extractor.extractSdJwtCandidates(query, responseObject.getVpToken());

        assertEquals(List.of("sd-jwt-vp"), candidates);
    }

    @Test
    void shouldExtractMultipleSdJwtPresentationsWhenQueryAllowsMultiple() throws Exception {
        DcqlQuery query = query(List.of(credential(PID_QUERY_ID, VCFormat.SD_JWT_VC, true)), null);
        ResponseObject responseObject = responseObject("""
                {"pid":["sd-jwt-vp-1","sd-jwt-vp-2"]}
                """);

        List<String> candidates = extractor.extractSdJwtCandidates(query, responseObject.getVpToken());

        assertEquals(List.of("sd-jwt-vp-1", "sd-jwt-vp-2"), candidates);
    }

    @Test
    void shouldRejectMultipleSdJwtPresentationsForSingleCredentialLogin() throws Exception {
        DcqlQuery query = query(List.of(credential(PID_QUERY_ID, VCFormat.SD_JWT_VC, true)), null);
        ResponseObject responseObject = responseObject("""
                {"pid":["sd-jwt-vp-1","sd-jwt-vp-2"]}
                """);

        VpTokenCandidateExtractor.InvalidVpTokenException exception = assertThrows(
                VpTokenCandidateExtractor.InvalidVpTokenException.class,
                () -> extractor.extractSingleSdJwtCandidate(query, responseObject.getVpToken()));

        assertTrue(exception.getMessage().contains("login supports exactly one SD-JWT VP candidate"));
    }

    @Test
    void shouldRejectMultiplePresentationsWhenQueryDoesNotAllowMultiple() throws Exception {
        DcqlQuery query = query(List.of(credential(PID_QUERY_ID, VCFormat.SD_JWT_VC, null)), null);
        ResponseObject responseObject = responseObject("""
                {"pid":["sd-jwt-vp-1","sd-jwt-vp-2"]}
                """);

        VpTokenCandidateExtractor.InvalidVpTokenException exception = assertThrows(
                VpTokenCandidateExtractor.InvalidVpTokenException.class,
                () -> extractor.extractSdJwtCandidates(query, responseObject.getVpToken()));

        assertTrue(exception.getMessage().contains("does not allow multiple presentations"));
    }

    @Test
    void shouldRejectUnknownCredentialQueryId() throws Exception {
        DcqlQuery query = query(List.of(credential(PID_QUERY_ID, VCFormat.SD_JWT_VC, null)), null);
        ResponseObject responseObject = responseObject("""
                {"unknown":["sd-jwt-vp"]}
                """);

        VpTokenCandidateExtractor.InvalidVpTokenException exception = assertThrows(
                VpTokenCandidateExtractor.InvalidVpTokenException.class,
                () -> extractor.extractSdJwtCandidates(query, responseObject.getVpToken()));

        assertTrue(exception.getMessage().contains("unknown DCQL credential query IDs"));
    }

    @Test
    void shouldRejectMissingRequiredCredentialWithoutCredentialSets() throws Exception {
        DcqlQuery query = query(
                List.of(
                        credential(PID_QUERY_ID, VCFormat.SD_JWT_VC, null),
                        credential(ALT_QUERY_ID, VCFormat.SD_JWT_VC, null)),
                null);
        ResponseObject responseObject = responseObject("""
                {"pid":["sd-jwt-vp"]}
                """);

        VpTokenCandidateExtractor.InvalidVpTokenException exception = assertThrows(
                VpTokenCandidateExtractor.InvalidVpTokenException.class,
                () -> extractor.extractSdJwtCandidates(query, responseObject.getVpToken()));

        assertTrue(exception.getMessage().contains("missing required DCQL credential query IDs"));
    }

    @Test
    void shouldAcceptAlternativeRequiredCredentialSetOption() throws Exception {
        // Required credential sets may be satisfied by any one complete option.
        DcqlQuery query = query(
                List.of(
                        credential(PID_QUERY_ID, VCFormat.SD_JWT_VC, null),
                        credential(ALT_QUERY_ID, VCFormat.SD_JWT_VC, null)),
                List.of(requiredSet(List.of(List.of(PID_QUERY_ID), List.of(ALT_QUERY_ID)))));
        ResponseObject responseObject = responseObject("""
                {"pid_alt":["sd-jwt-vp-alt"]}
                """);

        List<String> candidates = extractor.extractSdJwtCandidates(query, responseObject.getVpToken());

        assertEquals(List.of("sd-jwt-vp-alt"), candidates);
    }

    @Test
    void shouldAcceptMissingOptionalCredentialSet() throws Exception {
        // Optional credential sets are allowed to be absent from the vp_token map.
        DcqlQuery query = query(
                List.of(
                        credential(PID_QUERY_ID, VCFormat.SD_JWT_VC, null),
                        credential(ALT_QUERY_ID, VCFormat.SD_JWT_VC, null)),
                List.of(requiredSet(List.of(List.of(PID_QUERY_ID))), optionalSet(List.of(List.of(ALT_QUERY_ID)))));
        ResponseObject responseObject = responseObject("""
                {"pid":["sd-jwt-vp"]}
                """);

        List<String> candidates = extractor.extractSdJwtCandidates(query, responseObject.getVpToken());

        assertEquals(List.of("sd-jwt-vp"), candidates);
    }

    @Test
    void shouldRejectRequiredCredentialSetWhenNoOptionSatisfied() throws Exception {
        DcqlQuery query = query(
                List.of(
                        credential(PID_QUERY_ID, VCFormat.SD_JWT_VC, null),
                        credential("given_name", VCFormat.SD_JWT_VC, null),
                        credential("family_name", VCFormat.SD_JWT_VC, null)),
                List.of(requiredSet(List.of(List.of(PID_QUERY_ID), List.of("given_name", "family_name")))));
        ResponseObject responseObject = responseObject("""
                {"given_name":["sd-jwt-vp"]}
                """);

        VpTokenCandidateExtractor.InvalidVpTokenException exception = assertThrows(
                VpTokenCandidateExtractor.InvalidVpTokenException.class,
                () -> extractor.extractSdJwtCandidates(query, responseObject.getVpToken()));

        assertTrue(exception.getMessage().contains("does not satisfy a required DCQL credential set"));
    }

    @Test
    void shouldRejectBlankPresentation() throws Exception {
        DcqlQuery query = query(List.of(credential(PID_QUERY_ID, VCFormat.SD_JWT_VC, null)), null);
        ResponseObject responseObject = responseObject("""
                {"pid":[" "]}
                """);

        VpTokenCandidateExtractor.InvalidVpTokenException exception = assertThrows(
                VpTokenCandidateExtractor.InvalidVpTokenException.class,
                () -> extractor.extractSdJwtCandidates(query, responseObject.getVpToken()));

        assertTrue(exception.getMessage().contains("non-blank presentation strings"));
    }

    @Test
    void shouldRejectVpTokenEntriesWithNonArrayValues() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> responseObject("""
                        {"pid":"sd-jwt-vp"}
                        """));

        assertTrue(exception.getMessage().contains("must be an array of presentations"));
    }

    @Test
    void shouldAcceptObjectPresentationsAtResponseParsingLayer() throws Exception {
        ResponseObject responseObject = responseObject("""
                {"pid":[{"vp":"ldp-vp"}]}
                """);

        assertTrue(responseObject.getVpToken().get(PID_QUERY_ID).getFirst().isObject());
    }

    @Test
    void shouldRejectScalarPresentationsAtResponseParsingLayer() {
        // The response-parameter parser stays format-neutral, but presentations are still strings or JSON objects.
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> responseObject("""
                        {"pid":[123]}
                        """));

        assertTrue(exception.getMessage().contains("must contain string or object presentations"));
    }

    @Test
    void shouldRejectObjectPresentationForSdJwtCredential() throws Exception {
        DcqlQuery query = query(List.of(credential(PID_QUERY_ID, VCFormat.SD_JWT_VC, null)), null);
        ResponseObject responseObject = responseObject("""
                {"pid":[{"vp":"sd-jwt-vp"}]}
                """);

        VpTokenCandidateExtractor.InvalidVpTokenException exception = assertThrows(
                VpTokenCandidateExtractor.InvalidVpTokenException.class,
                () -> extractor.extractSdJwtCandidates(query, responseObject.getVpToken()));

        assertTrue(exception.getMessage().contains("must contain string presentations for SD-JWT"));
    }

    @Test
    void shouldRejectNonObjectVpToken() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> responseObject("""
                        ["sd-jwt-vp"]
                        """));

        assertTrue(exception.getMessage().contains("must be a JSON object"));
    }

    private static ResponseObject responseObject(String vpToken) throws Exception {
        return new ResponseObject(vpToken, "state");
    }

    private static DcqlQuery query(List<Credential> credentials, List<CredentialSet> credentialSets) {
        DcqlQuery query = new DcqlQuery();
        query.setCredentials(credentials);
        query.setCredentialSets(credentialSets);
        return query;
    }

    private static Credential credential(String id, String format, Boolean multiple) {
        Credential credential = new Credential();
        credential.setId(id);
        credential.setFormat(format);
        // null keeps `multiple` omitted, which exercises the final-spec default of false.
        credential.setMultiple(multiple);
        return credential;
    }

    private static CredentialSet requiredSet(List<List<String>> options) {
        CredentialSet credentialSet = new CredentialSet();
        credentialSet.setOptions(options);
        return credentialSet;
    }

    private static CredentialSet optionalSet(List<List<String>> options) {
        CredentialSet credentialSet = requiredSet(options);
        credentialSet.setRequired(false);
        return credentialSet;
    }
}
