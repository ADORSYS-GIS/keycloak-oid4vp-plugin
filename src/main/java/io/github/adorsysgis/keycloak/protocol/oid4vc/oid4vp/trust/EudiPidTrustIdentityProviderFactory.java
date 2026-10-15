package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import java.util.List;
import java.util.Map;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

/** Registers the ETSI PID Provider LoTE as a Keycloak trust-material identity provider. */
public class EudiPidTrustIdentityProviderFactory extends AbstractIdentityProviderFactory<EudiPidTrustIdentityProvider> {

    public static final String PROVIDER_ID = "eudi-pid-trust-list";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = List.of(
            property(
                    EudiPidTrustIdentityProviderConfig.TRUST_LIST_URL,
                    "Trust-list URL",
                    ProviderConfigProperty.STRING_TYPE,
                    null,
                    "Absolute HTTPS URL of the signed ETSI PID Provider List of Trusted Entities."),
            property(
                    EudiPidTrustIdentityProviderConfig.TRUST_LIST_SIGNING_CERTIFICATE,
                    "Trust-list signing certificate",
                    ProviderConfigProperty.TEXT_TYPE,
                    null,
                    "Base64 DER or PEM certificate trusted to sign the ETSI trust list."),
            property(
                    EudiPidTrustIdentityProviderConfig.SERVICE_TYPE,
                    "Service type",
                    ProviderConfigProperty.STRING_TYPE,
                    EudiPidTrustListProvider.PID_ISSUANCE_SERVICE_TYPE,
                    "ETSI service type whose X.509 service identities establish trust."),
            property(
                    EudiPidTrustIdentityProviderConfig.ISSUER,
                    "PID Provider identifier",
                    ProviderConfigProperty.STRING_TYPE,
                    null,
                    "Optional official PID Provider registration identifier. When set, only that provider's service certificates establish trust."));

    @Override
    public String getName() {
        return "EUDI PID Trust List";
    }

    @Override
    public EudiPidTrustIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new EudiPidTrustIdentityProvider(session, new EudiPidTrustIdentityProviderConfig(model));
    }

    @Override
    public Map<String, String> parseConfig(KeycloakSession session, String config) {
        throw new UnsupportedOperationException();
    }

    @Override
    public IdentityProviderModel createConfig() {
        return new EudiPidTrustIdentityProviderConfig();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    @Override
    public String getHelpText() {
        return "Provides X.509 trust from a signed ETSI TS 119 602 PID Provider trust list.";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    private static ProviderConfigProperty property(
            String name, String label, String type, Object defaultValue, String helpText) {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(name);
        property.setLabel(label);
        property.setType(type);
        property.setDefaultValue(defaultValue);
        property.setHelpText(helpText);
        return property;
    }
}
