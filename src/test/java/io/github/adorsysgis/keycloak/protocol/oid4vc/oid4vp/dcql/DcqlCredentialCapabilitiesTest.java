package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.VCFormat;

class DcqlCredentialCapabilitiesTest {

    @Test
    void defaultRegistryContributesSdJwtVpFormatMetadata() {
        ClientMetadata.VpFormat vpFormat = new ClientMetadata.VpFormat();
        DcqlCredentialCapabilities.createDefault()
                .all()
                .forEach(capability -> capability.contributeVpFormatsSupported(vpFormat, List.of("ES256")));

        assertNotNull(vpFormat.getDcSdJwt());
    }

    @Test
    void defaultRegistryContributesMdocVpFormatMetadata() {
        ClientMetadata.VpFormat vpFormat = new ClientMetadata.VpFormat();
        DcqlCredentialCapabilities.createDefault()
                .all()
                .forEach(capability -> capability.contributeVpFormatsSupported(vpFormat, List.of("ES256")));

        assertNotNull(vpFormat.getMsoMdoc());
        assertEquals(List.of(-7), vpFormat.getMsoMdoc().getIssuerAuthAlgValues());
        assertEquals(List.of(-7), vpFormat.getMsoMdoc().getDeviceAuthAlgValues());
    }

    @Test
    void defaultRegistryIncludesBothSdJwtAndMdocCapabilities() {
        DcqlCredentialCapabilities capabilities = DcqlCredentialCapabilities.createDefault();
        assertEquals(2, capabilities.all().size());
    }

    @Test
    void resolvesCapabilitiesByFormat() {
        DcqlCredentialCapabilities capabilities = DcqlCredentialCapabilities.createDefault();

        assertSame(
                SdJwtDcqlCredentialCapability.class,
                capabilities.resolve(VCFormat.SD_JWT_VC).getClass());
        assertSame(
                MdocDcqlCredentialCapability.class,
                capabilities.resolve("mso_mdoc").getClass());
    }

    @Test
    void rejectsDuplicateCapabilityFormats() {
        IllegalArgumentException error = assertThrows(
                IllegalArgumentException.class,
                () -> new DcqlCredentialCapabilities(
                        List.of(new SdJwtDcqlCredentialCapability(), new SdJwtDcqlCredentialCapability())));

        assertEquals("Duplicate DCQL credential capability format: " + VCFormat.SD_JWT_VC, error.getMessage());
    }

    @Test
    void rejectsUnsupportedFormats() {
        DcqlCredentialCapabilities capabilities = DcqlCredentialCapabilities.createDefault();

        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> capabilities.resolve("jwt_vc_json"));

        assertEquals("No DCQL credential capability for format: jwt_vc_json", error.getMessage());
    }

    @Test
    void reportsPresentationPreValidationSupportPerCapability() {
        DcqlCredentialCapabilities capabilities = DcqlCredentialCapabilities.createDefault();

        assertTrue(capabilities.resolve(VCFormat.SD_JWT_VC).supportsPresentationPreValidation());
        assertTrue(capabilities.resolve("mso_mdoc").supportsPresentationPreValidation());
    }
}
