package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.RSATestUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import java.util.List;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.VCFormat;
import org.keycloak.common.VerificationException;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.sdjwt.DisclosureSpec;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.SdJwt;
import org.keycloak.util.JsonSerialization;

class DcqlPresentationValidatorTest {

    private static final String VCT = "https://credentials.example.com/identity_credential";

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(DcqlPresentationValidatorTest.class.getClassLoader());
    }

    @Test
    void validatesRequestedClaimsThroughNestedDisclosedPath() throws Exception {
        String token = buildSdJwtToken(
                claimSet -> {
                    ObjectNode address = JsonSerialization.mapper.createObjectNode();
                    address.put("street_address", "123 Main St");
                    claimSet.set("address", address);
                },
                DisclosureSpec.builder()
                        .withUndisclosedClaim("address", "address-salt")
                        .build());

        DcqlQuery query = queryWithClaims(claim("address-street", List.of("address", "street_address")));

        assertDoesNotThrow(
                () -> DcqlPresentationValidator.validatePresentation(query, token),
                "Should accept presentation that satisfies nested disclosed claim path");
    }

    @Test
    void validatesMatchingClaimValues() throws Exception {
        String token = buildSdJwtToken(
                claimSet -> claimSet.put("given_name", "Alice"),
                DisclosureSpec.builder().build());

        DcqlQuery query = queryWithClaims(claimWithValues("given-name", List.of("given_name"), List.of("Alice")));

        assertDoesNotThrow(
                () -> DcqlPresentationValidator.validatePresentation(query, token),
                "Should accept presentation when claim values match");
    }

    @Test
    void rejectsMismatchedClaimValues() throws Exception {
        String token = buildSdJwtToken(
                claimSet -> claimSet.put("given_name", "Alice"),
                DisclosureSpec.builder().build());

        DcqlQuery query = queryWithClaims(claimWithValues("given-name", List.of("given_name"), List.of("Bob")));

        assertThrows(
                VerificationException.class,
                () -> DcqlPresentationValidator.validatePresentation(query, token),
                "Should reject presentation when claim values do not match");
    }

    @Test
    void validatesClaimSetsWhenOneOptionIsSatisfied() throws Exception {
        String token = buildSdJwtToken(
                claimSet -> {
                    claimSet.put("given_name", "Alice");
                    claimSet.put("family_name", "Smith");
                },
                DisclosureSpec.builder().build());

        Claim givenName = claim("given-name", List.of("given_name"));
        Claim familyName = claim("family-name", List.of("family_name"));
        Credential credential = credentialWithClaims(List.of(givenName, familyName));
        credential.setClaimSets(List.of(List.of("given-name", "family-name"), List.of("given-name")));

        DcqlQuery query = DcqlQueryBuilder.singleCredentialQuery(credential);

        assertDoesNotThrow(
                () -> DcqlPresentationValidator.validatePresentation(query, token),
                "Should accept presentation when any claim_sets option is fully satisfied");
    }

    @Test
    void rejectsClaimSetsWhenNoOptionIsSatisfied() throws Exception {
        String token = buildSdJwtToken(
                claimSet -> claimSet.put("given_name", "Alice"),
                DisclosureSpec.builder().build());

        Claim givenName = claim("given-name", List.of("given_name"));
        Claim familyName = claim("family-name", List.of("family_name"));
        Credential credential = credentialWithClaims(List.of(givenName, familyName));
        credential.setClaimSets(List.of(List.of("given-name", "family-name")));

        DcqlQuery query = DcqlQueryBuilder.singleCredentialQuery(credential);

        assertThrows(
                VerificationException.class,
                () -> DcqlPresentationValidator.validatePresentation(query, token),
                "Should reject presentation when no claim_sets option is satisfied");
    }

    private static DcqlQuery queryWithClaims(Claim... claims) {
        return DcqlQueryBuilder.singleCredentialQuery(credentialWithClaims(List.of(claims)));
    }

    private static Credential credentialWithClaims(List<Claim> claims) {
        Meta meta = new Meta();
        meta.setVctValues(List.of(VCT));

        Credential credential = new Credential();
        credential.setId("cred-1");
        credential.setFormat(VCFormat.SD_JWT_VC);
        credential.setMeta(meta);
        credential.setClaims(claims);
        credential.setRequireCryptographicHolderBinding(Boolean.FALSE);
        return credential;
    }

    private static Claim claim(String id, List<String> path) {
        Claim claim = new Claim();
        claim.setId(id);
        claim.setPath(path);
        return claim;
    }

    private static Claim claimWithValues(String id, List<String> path, List<String> values) {
        Claim claim = claim(id, path);
        claim.setValues(values);
        return claim;
    }

    private static String buildSdJwtToken(Consumer<ObjectNode> claimCustomizer, DisclosureSpec disclosureSpec)
            throws Exception {
        ObjectNode claimSet = JsonSerialization.mapper.createObjectNode();
        claimSet.put("iss", "https://example.com/realms/test");
        claimSet.put("vct", VCT);
        claimSet.put("sub", "user-id");
        claimCustomizer.accept(claimSet);

        IssuerSignedJWT issuerSignedJWT =
                IssuerSignedJWT.builder().withClaims(claimSet, disclosureSpec).build();

        JWK issuerJwk = SdJwtVPTestUtils.getKeycloakJwk();
        KeyWrapper issuerKey = RSATestUtils.getRsaKeyWrapper(issuerJwk);
        return SdJwt.builder()
                .withIssuerSignedJwt(issuerSignedJWT)
                .withIssuerSigningContext(new AsymmetricSignatureSignerContext(issuerKey))
                .build()
                .toSdJwtString();
    }
}
