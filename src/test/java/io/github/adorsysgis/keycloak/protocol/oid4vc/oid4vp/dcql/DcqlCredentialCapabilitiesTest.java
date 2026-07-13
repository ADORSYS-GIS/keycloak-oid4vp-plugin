package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRole;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.VCFormat;

class DcqlCredentialCapabilitiesTest {

    @Test
    void defaultRegistryBuildsSdJwtAuthorizationQuery() {
        AuthenticationProfile profile = new AuthenticationProfile()
                .setId("default")
                .setCredentials(List.of(new CredentialRequirement()
                        .setId("identity")
                        .setRole(CredentialRole.PRIMARY)
                        .setCredentialTypes(List.of("https://example.com/vct"))
                        .setClaims(List.of("sub"))));

        DcqlQuery query = DcqlQueryGenerator.create().buildQuery(profile, true);

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
