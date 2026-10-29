package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.ACCESS_CERTIFICATE_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.CREDENTIAL_TYPES_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.CUSTOM_URL_SCHEME_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.PROFILES_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.REGISTRATION_CERTIFICATE_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.RESPONSE_MODE_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.STATUS_LIST_TRUST_MATERIAL_IDPS_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.TRANSACTION_DATA_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.VERIFIER_INFO_CONFIG;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.keycloak.provider.ProviderConfigProperty;

class OID4VPAuthenticatorFactoryTest {

    @Test
    void shouldUseTextAreasForLargeConfigurationValues() {
        Map<String, String> propertyTypes = new OID4VPAuthenticatorFactory()
                .getConfigProperties().stream()
                        .collect(Collectors.toMap(ProviderConfigProperty::getName, ProviderConfigProperty::getType));

        assertEquals(ProviderConfigProperty.TEXT_TYPE, propertyTypes.get(ACCESS_CERTIFICATE_CONFIG));
        assertEquals(ProviderConfigProperty.TEXT_TYPE, propertyTypes.get(REGISTRATION_CERTIFICATE_CONFIG));
        assertEquals(ProviderConfigProperty.TEXT_TYPE, propertyTypes.get(TRANSACTION_DATA_CONFIG));
        assertEquals(ProviderConfigProperty.TEXT_TYPE, propertyTypes.get(VERIFIER_INFO_CONFIG));
    }

    @Test
    void shouldTrimOnlySurroundingWhitespaceFromTextualConfigurationValues() {
        Map<String, String> normalized = OID4VPAuthenticatorFactory.normalizeTextConfigValues(Map.of(
                PROFILES_CONFIG, "  [\\n]  ",
                CREDENTIAL_TYPES_CONFIG, "  credential-type  ",
                CUSTOM_URL_SCHEME_CONFIG, "  openid4vp://  ",
                ACCESS_CERTIFICATE_CONFIG, "  certificate  ",
                REGISTRATION_CERTIFICATE_CONFIG, "  registration  ",
                TRANSACTION_DATA_CONFIG, "  transaction-data\nnext-entry  ",
                VERIFIER_INFO_CONFIG, "  [{\\\"format\\\":\\\"example\\\"}]  ",
                STATUS_LIST_TRUST_MATERIAL_IDPS_CONFIG, "  trust-provider  ",
                RESPONSE_MODE_CONFIG, "  direct_post  "));

        assertEquals("[\\n]", normalized.get(PROFILES_CONFIG));
        assertEquals("credential-type", normalized.get(CREDENTIAL_TYPES_CONFIG));
        assertEquals("openid4vp://", normalized.get(CUSTOM_URL_SCHEME_CONFIG));
        assertEquals("certificate", normalized.get(ACCESS_CERTIFICATE_CONFIG));
        assertEquals("registration", normalized.get(REGISTRATION_CERTIFICATE_CONFIG));
        assertEquals("transaction-data\nnext-entry", normalized.get(TRANSACTION_DATA_CONFIG));
        assertEquals("[{\\\"format\\\":\\\"example\\\"}]", normalized.get(VERIFIER_INFO_CONFIG));
        assertEquals("trust-provider", normalized.get(STATUS_LIST_TRUST_MATERIAL_IDPS_CONFIG));
        assertEquals("  direct_post  ", normalized.get(RESPONSE_MODE_CONFIG));
    }
}
