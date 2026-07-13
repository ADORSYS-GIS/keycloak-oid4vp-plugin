package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import java.util.List;
import org.junit.jupiter.api.Test;

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
}
