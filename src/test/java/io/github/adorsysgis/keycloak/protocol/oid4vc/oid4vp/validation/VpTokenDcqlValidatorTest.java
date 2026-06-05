package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.RSATestUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.VCFormat;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.sdjwt.DisclosureSpec;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.SdJwt;

class VpTokenDcqlValidatorTest {

    private static SignatureSignerContext ISSUER_SIGNER;
    private final VpTokenDcqlValidator validator = new VpTokenDcqlValidator();

    @BeforeAll
    static void initCrypto() throws Exception {
        CryptoIntegration.init(VpTokenDcqlValidatorTest.class.getClassLoader());
        JWK issuerJwk = SdJwtVPTestUtils.getKeycloakJwk();
        ISSUER_SIGNER = new AsymmetricSignatureSignerContext(RSATestUtils.getRsaKeyWrapper(issuerJwk));
    }

    @Test
    void rejectsEmptyVpTokenMap() {
        Credential credentialQuery = credentialWithClaim("username", List.of("alice"));
        DcqlQuery query = queryWithCredentials(credentialQuery);

        assertThrows(VpTokenValidationException.class, () -> validator.validate(Map.of(), query));
    }

    @Test
    void rejectsUnknownCredentialQueryId() {
        Credential credentialQuery = credentialWithClaim("username", List.of("alice"));
        DcqlQuery query = queryWithCredentials(credentialQuery);

        assertThrows(
                VpTokenValidationException.class,
                () -> validator.validate(Map.of("unknown-id", List.of("vp-token")), query));
    }

    @Test
    void rejectsDuplicatePresentationsForSameCredentialQueryId() {
        Credential credentialQuery = credentialWithClaim("username", List.of("alice"));
        DcqlQuery query = queryWithCredentials(credentialQuery);

        assertThrows(
                VpTokenValidationException.class,
                () -> validator.validate(Map.of(credentialQuery.getId(), List.of("vp-token-1", "vp-token-2")), query));
    }

    @Test
    void rejectsUnparseablePresentation() {
        Credential credentialQuery = credentialWithClaim("username", List.of("alice"));
        DcqlQuery query = queryWithCredentials(credentialQuery);

        assertThrows(
                VpTokenValidationException.class,
                () -> validator.validate(Map.of(credentialQuery.getId(), List.of("not-a-valid-sd-jwt")), query));
    }

    @Test
    void returnsParsedPresentationWhenDcqlQueryIsSatisfied() throws Exception {
        Credential credentialQuery = credentialWithClaim("username", List.of("alice"));
        DcqlQuery query = queryWithCredentials(credentialQuery);
        String sdJwtVp = sdJwtWithUsername("alice");

        List<PresentedCredential> validated =
                validator.validate(Map.of(credentialQuery.getId(), List.of(sdJwtVp)), query);

        assertEquals(1, validated.size());
        assertEquals(sdJwtVp, validated.getFirst().encodedPresentation());
        assertEquals(credentialQuery.getId(), validated.getFirst().credentialQueryId());
    }

    private static DcqlQuery queryWithCredentials(Credential credential) {
        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(credential));
        return query;
    }

    private static Credential credentialWithClaim(String claimName, List<Object> values) {
        Claim claim = new Claim();
        claim.setPath(List.<Object>of(claimName));
        claim.setValues(values);

        Credential credential = new Credential();
        credential.setId("cred-1");
        credential.setFormat(VCFormat.SD_JWT_VC);
        credential.setMeta(new Meta());
        credential.getMeta().setVctValues(List.of("https://example.com/vct"));
        credential.setClaims(List.of(claim));
        return credential;
    }

    private static String sdJwtWithUsername(String username) throws Exception {
        ObjectNode claimSet = JsonNodeFactory.instance.objectNode();
        claimSet.put("vct", "https://example.com/vct");
        claimSet.put("exp", Time.currentTime() + 300);
        claimSet.put("username", username);

        DisclosureSpec disclosureSpec = DisclosureSpec.builder()
                .withUndisclosedClaim("username", "username-salt")
                .build();

        IssuerSignedJWT issuerSignedJwt =
                IssuerSignedJWT.builder().withClaims(claimSet, disclosureSpec).build();

        return SdJwt.builder()
                .withIssuerSignedJwt(issuerSignedJwt)
                .withIssuerSigningContext(ISSUER_SIGNER)
                .build()
                .toSdJwtString();
    }
}
