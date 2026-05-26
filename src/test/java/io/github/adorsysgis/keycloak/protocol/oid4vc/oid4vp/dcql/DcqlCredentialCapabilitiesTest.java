package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.VerifierConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.VCFormat;
import org.mockito.Mockito;

class DcqlCredentialCapabilitiesTest {

    @Test
    void defaultRegistryBuildsSdJwtAuthorizationQuery() {
        var capabilities = DcqlCredentialCapabilities.createDefault();
        VerifierConfig config = Mockito.mock(VerifierConfig.class);
        SdJwtAuthRequirements authRequirements = Mockito.mock(SdJwtAuthRequirements.class);
        Mockito.when(config.getAuthRequirements()).thenReturn(authRequirements);
        Mockito.when(authRequirements.getSdJwtQuerySpec())
                .thenReturn(
                        SdJwtCredentialConstrainer.QuerySpec.of(List.of("https://example.com/vct"), List.of("sub")));

        var query = capabilities.resolve(config).buildAuthorizationQuery(config);

        assertEquals(1, query.getCredentials().size());
        assertEquals(VCFormat.SD_JWT_VC, query.getCredentials().getFirst().getFormat());
    }

    @Test
    void defaultRegistryContributesSdJwtVpFormatMetadata() {
        ClientMetadata.VpFormat vpFormat = new ClientMetadata.VpFormat();
        DcqlCredentialCapabilities.createDefault()
                .all()
                .forEach(capability -> capability.contributeVpFormatsSupported(vpFormat, List.of("ES256")));

        assertNotNull(vpFormat.getDcSdJwt());
    }
}
