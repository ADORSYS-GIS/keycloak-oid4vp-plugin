package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.keycloak.common.VerificationException;

public class MdocVerificationTest extends MdocBaseTest {

    @Test
    @Disabled
    public void shouldVerifyValidMdocSuccessfully() throws Exception {
        String mdoc = buildDeviceResponse().encodeToBase64Url();
        new MdocVerificationContext(mdoc).verifyPresentation(null, null, null);
    }

    @Test
    public void shouldVerifyValidMdocSuccessfully_SpecSample() throws VerificationException {
        String mdoc = readResource("/mdoc/spec-sample.txt");
        new MdocVerificationContext(mdoc).verifyPresentation(null, null, null);
    }
}
