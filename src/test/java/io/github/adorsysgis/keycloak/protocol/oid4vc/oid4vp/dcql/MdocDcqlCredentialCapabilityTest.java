package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.common.VerificationException;

class MdocDcqlCredentialCapabilityTest {

    private final MdocDcqlCredentialCapability capability = new MdocDcqlCredentialCapability();

    @Test
    void formatReturnsMsoMdoc() {
        assertEquals("mso_mdoc", capability.format());
    }

    @Test
    void contributeVpFormatsSupportedConvertsJoseToCoseAlgorithms() {
        ClientMetadata.VpFormat vpFormat = new ClientMetadata.VpFormat();
        capability.contributeVpFormatsSupported(vpFormat, List.of("ES256", "ES384"));

        assertNotNull(vpFormat.getMsoMdoc());
        assertEquals(List.of(-7, -35), vpFormat.getMsoMdoc().getIssuerAuthAlgValues());
        assertEquals(List.of(-7, -35), vpFormat.getMsoMdoc().getDeviceAuthAlgValues());
    }

    @Test
    void contributeVpFormatsSupportedResolvesUnknownAlgorithmsToZero() {
        ClientMetadata.VpFormat vpFormat = new ClientMetadata.VpFormat();
        capability.contributeVpFormatsSupported(vpFormat, List.of("UNKNOWN_ALG"));

        assertNotNull(vpFormat.getMsoMdoc());
        assertEquals(List.of(0), vpFormat.getMsoMdoc().getIssuerAuthAlgValues());
        assertEquals(List.of(0), vpFormat.getMsoMdoc().getDeviceAuthAlgValues());
    }

    @Test
    void contributeVpFormatsSupportedHandlesEdDSA() {
        ClientMetadata.VpFormat vpFormat = new ClientMetadata.VpFormat();
        capability.contributeVpFormatsSupported(vpFormat, List.of("EdDSA"));

        assertNotNull(vpFormat.getMsoMdoc());
        assertEquals(List.of(-8), vpFormat.getMsoMdoc().getIssuerAuthAlgValues());
        assertEquals(List.of(-8), vpFormat.getMsoMdoc().getDeviceAuthAlgValues());
    }

    @Test
    void validatePresentationThrowsUnsupported() {
        DcqlQuery query = new DcqlQuery();
        assertThrows(VerificationException.class, () -> capability.validatePresentation(query, "token"));
    }
}
