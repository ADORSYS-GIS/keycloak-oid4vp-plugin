package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import java.util.List;
import org.junit.jupiter.api.Test;

class VpTokenValidationResultTest {

    @Test
    void requireSinglePresentationRejectsMultipleCredentials() {
        var result =
                new VpTokenValidationResult(List.of(mock(PresentedCredential.class), mock(PresentedCredential.class)));

        VpTokenValidationException error =
                assertThrows(VpTokenValidationException.class, result::requireSinglePresentation);

        assertEquals(VpTokenValidationException.Phase.STRUCTURE, error.getPhase());
        assertEquals("User authentication requires exactly one presented credential, found: 2", error.getMessage());
    }
}
