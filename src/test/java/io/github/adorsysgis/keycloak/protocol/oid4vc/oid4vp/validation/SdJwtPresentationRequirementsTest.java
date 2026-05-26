package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import java.util.List;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.VCFormat;
import org.keycloak.common.VerificationException;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.sdjwt.consumer.PresentationRequirements;

class SdJwtPresentationRequirementsTest {

    @Test
    void requiresNestedDcqlPathNotOnlyLeafName() throws Exception {
        Claim claim = new Claim();
        claim.setPath(List.of("address", "street_address"));

        Credential credential = new Credential();
        credential.setId("cred-1");
        credential.setFormat(VCFormat.SD_JWT_VC);
        credential.setMeta(new Meta());
        credential.getMeta().setVctValues(List.of("https://example.com/vct"));
        credential.setClaims(List.of(claim));

        SdJwtAuthRequirements authRequirements = mock(SdJwtAuthRequirements.class);
        when(authRequirements.getRequiredClaims()).thenReturn(List.of(JsonWebToken.SUBJECT, OAuth2Constants.USERNAME));
        when(authRequirements.getVctPatternForCredential(credential))
                .thenReturn(Pattern.quote("\"https://example.com/vct\""));
        when(authRequirements.isVerifyIssuerClaim()).thenReturn(false);

        PresentationRequirements requirements =
                SdJwtPresentationRequirements.forCredential(authRequirements, credential);

        var flatClaims = JsonNodeFactory.instance.objectNode();
        flatClaims.put("street_address", "42 Market Street");
        flatClaims.put("vct", "https://example.com/vct");
        flatClaims.put("sub", "user-1");
        flatClaims.put("username", "alice");

        assertThrows(VerificationException.class, () -> requirements.checkIfSatisfiedBy(flatClaims));

        var nestedClaims = JsonNodeFactory.instance.objectNode();
        var address = nestedClaims.putObject("address");
        address.put("street_address", "42 Market Street");
        nestedClaims.put("vct", "https://example.com/vct");
        nestedClaims.put("sub", "user-1");
        nestedClaims.put("username", "alice");

        assertDoesNotThrow(() -> requirements.checkIfSatisfiedBy(nestedClaims));
    }
}
