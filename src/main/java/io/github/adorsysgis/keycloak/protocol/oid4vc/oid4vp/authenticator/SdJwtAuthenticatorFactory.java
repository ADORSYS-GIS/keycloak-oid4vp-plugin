package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPEnvironmentProviderFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientIdentifierPrefix;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestUriMethod;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseMode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.TrustedStatusListJwtFetcher;
import java.util.ArrayList;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtAuthenticatorFactory implements AuthenticatorFactory, OID4VPEnvironmentProviderFactory {

    public static final String PROVIDER_ID = "sd-jwt-authenticator";
    public static final String REFERENCE_CATEGORY = "verifiable-credential";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    public static final String VCT_CONFIG = "vct";
    public static final String VCT_CONFIG_DEFAULT = "https://credentials.example.com/identity_credential";

    public static final String KBJWT_MAX_AGE_CONFIG = "kbJwtMaxAge";
    public static final int KBJWT_MAX_AGE_CONFIG_DEFAULT = 60;

    public static final String REQUIRE_NBF_CLAIM_CONFIG = "requireNbfClaim";
    public static final boolean REQUIRE_NBF_CLAIM_CONFIG_DEFAULT = false;

    public static final String REQUIRE_EXP_CLAIM_CONFIG = "requireExpClaim";
    public static final boolean REQUIRE_EXP_CLAIM_CONFIG_DEFAULT = false;

    public static final String VERIFY_ISSUER_CLAIM_CONFIG = "verifyIssuerClaim";
    public static final boolean VERIFY_ISSUER_CLAIM_CONFIG_DEFAULT = true;

    public static final String ENFORCE_REVOCATION_STATUS_CONFIG = "enforceRevocationStatus";
    public static final boolean ENFORCE_REVOCATION_STATUS_CONFIG_DEFAULT = false;

    public static final String CLIENT_IDENTIFIER_PREFIX_CONFIG = "clientIdentifierPrefix";
    public static final String CLIENT_IDENTIFIER_PREFIX_CONFIG_DEFAULT = ClientIdentifierPrefix.X509_SAN_DNS.getValue();

    public static final String RESPONSE_MODE_CONFIG = "responseMode";
    public static final String RESPONSE_MODE_CONFIG_DEFAULT = ResponseMode.DIRECT_POST.getValue();

    public static final String CUSTOM_URL_SCHEME_CONFIG = "customUrlScheme";
    public static final String CUSTOM_URL_SCHEME_CONFIG_DEFAULT = "openid4vp://";

    public static final String ACCESS_CERTIFICATE_CONFIG = "accessCertificate";

    public static final String REGISTRATION_CERTIFICATE_CONFIG = "registrationCertificate";

    public static final String TRANSACTION_DATA_CONFIG = "transactionData";

    public static final String REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING_CONFIG = "requireCryptographicHolderBinding";
    public static final boolean REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING_CONFIG_DEFAULT = true;

    public static final String VERIFIER_INFO_CONFIG = "verifierInfo";
    public static final String REQUEST_URI_METHOD_CONFIG = "requestUriMethod";
    public static final String REQUEST_URI_METHOD_CONFIG_DEFAULT = RequestUriMethod.GET.getValue();

    public static final String PROFILES_CONFIG = "profiles";

    static {
        ProviderConfigProperty property;

        property = new ProviderConfigProperty();
        property.setName(VCT_CONFIG);
        property.setLabel("Credential types allowed");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue(VCT_CONFIG_DEFAULT);
        property.setHelpText(
                "Only SD-JWTs of this comma-separated list of types (vct) will be accepted by the authenticator.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(REQUIRE_NBF_CLAIM_CONFIG);
        property.setLabel("Require Not Before claim");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setDefaultValue(REQUIRE_NBF_CLAIM_CONFIG_DEFAULT);
        property.setHelpText(
                "Verification policy whether or not to require the presence of the nbf time claim in presented credentials.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(REQUIRE_EXP_CLAIM_CONFIG);
        property.setLabel("Require Expiration claim");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setDefaultValue(REQUIRE_EXP_CLAIM_CONFIG_DEFAULT);
        property.setHelpText(
                "Verification policy whether or not to require the presence of the exp time claim in presented credentials.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(VERIFY_ISSUER_CLAIM_CONFIG);
        property.setLabel("Verify issuer claim");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setDefaultValue(VERIFY_ISSUER_CLAIM_CONFIG_DEFAULT);
        property.setHelpText("Require the iss claim to match this realm's issuer URL.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(KBJWT_MAX_AGE_CONFIG);
        property.setLabel("Maximum age (in seconds) of presented key-binding JWT");
        property.setType(ProviderConfigProperty.INTEGER_TYPE);
        property.setDefaultValue(KBJWT_MAX_AGE_CONFIG_DEFAULT);
        property.setHelpText(
                "Define a maximum age of accepted key-binding JWTs as part of measures to protect against replay.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(CLIENT_IDENTIFIER_PREFIX_CONFIG);
        property.setLabel("Client Identifier Prefix");
        property.setType(ProviderConfigProperty.LIST_TYPE);
        property.setDefaultValue(CLIENT_IDENTIFIER_PREFIX_CONFIG_DEFAULT);
        property.setOptions(
                List.of(ClientIdentifierPrefix.X509_SAN_DNS.getValue(), ClientIdentifierPrefix.X509_HASH.getValue()));
        property.setHelpText("Client Identifier Prefix to conform to as per OpenID4VP spec.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(RESPONSE_MODE_CONFIG);
        property.setLabel("Response mode");
        property.setType(ProviderConfigProperty.LIST_TYPE);
        property.setDefaultValue(RESPONSE_MODE_CONFIG_DEFAULT);
        property.setOptions(List.of(ResponseMode.DIRECT_POST.getValue(), ResponseMode.DIRECT_POST_JWT.getValue()));
        property.setHelpText("How wallets should respond to authorization requests.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(CUSTOM_URL_SCHEME_CONFIG);
        property.setLabel("Custom URL scheme");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue(CUSTOM_URL_SCHEME_CONFIG_DEFAULT);
        property.setHelpText("Custom URL scheme for authorization requests.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(ACCESS_CERTIFICATE_CONFIG);
        property.setLabel("Access certificate");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText(
                "PEM-encoded certificate to include in the X5C header of request objects. Do not include PEM delimiters.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(REGISTRATION_CERTIFICATE_CONFIG);
        property.setLabel("Registration certificate");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Opaque string to advertise under the verifier_info claim of request objects.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(REQUEST_URI_METHOD_CONFIG);
        property.setLabel("Request URI method");
        property.setType(ProviderConfigProperty.LIST_TYPE);
        property.setDefaultValue(REQUEST_URI_METHOD_CONFIG_DEFAULT);
        property.setOptions(List.of(RequestUriMethod.GET.getValue(), RequestUriMethod.POST.getValue()));
        property.setHelpText("How wallets should dereference request_uri (default get, optionally post).");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(ENFORCE_REVOCATION_STATUS_CONFIG);
        property.setLabel("Reject revoked credentials (Token Status List)");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setDefaultValue(ENFORCE_REVOCATION_STATUS_CONFIG_DEFAULT);
        property.setHelpText(
                "Reject credentials whose status indicates they are no longer valid as per the Token Status List mechanism.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING_CONFIG);
        property.setLabel("Require cryptographic holder binding");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setDefaultValue(REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING_CONFIG_DEFAULT);
        property.setHelpText(
                "When false, the DCQL query requests a presentation without Key Binding JWT and state binding is enforced on the response (OpenID4VP §5.3).");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(TRANSACTION_DATA_CONFIG);
        property.setLabel("Transaction data (base64url)");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText(
                "Optional comma-separated or newline-separated base64url-encoded transaction_data JSON objects (OpenID4VP §5.1). Requires holder binding. Entries are normalized before signing; use the signed request JWT payload as the canonical wire form when debugging hash mismatches. Only sha-256 is supported for transaction_data_hashes.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(VERIFIER_INFO_CONFIG);
        property.setLabel("Verifier info (JSON array)");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText(
                "Optional JSON array of verifier_info objects ({format, data, credential_ids?}) merged with the registration certificate entry.");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(PROFILES_CONFIG);
        property.setLabel("OpenID4VP authentication profiles");
        property.setType(ProviderConfigProperty.TEXT_TYPE);
        property.setHelpText(
                "Optional JSON array of authentication profiles. Leave empty to use the legacy single-credential profile.");
        configProperties.add(property);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        StatusListJwtFetcher httpFetcher = new TrustedStatusListJwtFetcher(session);
        return new SdJwtAuthenticator(httpFetcher);
    }

    @Override
    public String getDisplayType() {
        return "SD-JWT Authenticator";
    }

    @Override
    public String getHelpText() {
        return "Authenticates users via presentation of a Keycloak-issued SD-JWT identity credential";
    }

    @Override
    public String getReferenceCategory() {
        return REFERENCE_CATEGORY;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}
}
