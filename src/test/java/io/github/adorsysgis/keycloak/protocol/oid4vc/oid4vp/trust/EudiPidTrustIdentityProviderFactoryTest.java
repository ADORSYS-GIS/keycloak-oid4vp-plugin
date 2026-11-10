package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.provider.ProviderConfigProperty;

class EudiPidTrustIdentityProviderFactoryTest {

    @Test
    void shouldExposeOnlyRequiredTrustListSettingsInAdminConsole() {
        List<ProviderConfigProperty> properties = new EudiPidTrustIdentityProviderFactory().getConfigProperties();
        List<String> propertyNames = properties.stream().map(ProviderConfigProperty::getName).toList();

        assertEquals(
                List.of(
                        EudiPidTrustIdentityProviderConfig.TRUST_LIST_URL,
                        EudiPidTrustIdentityProviderConfig.TRUST_LIST_SIGNING_CERTIFICATE),
                propertyNames);

        assertEquals(
                List.of(true, true),
                properties.stream().map(ProviderConfigProperty::isRequired).toList());
    }
}
