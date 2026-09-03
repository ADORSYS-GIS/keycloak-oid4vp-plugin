package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config;

import com.apicatalog.jsonld.StringUtils;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientIdentifierPrefix;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestUriMethod;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseMode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.OID4VPProfileConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.TransactionDataSupport;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;

/**
 * Access configurations that modulate the verifier's behavior.
 *
 * <p>Use {@link #resolve(String, AuthenticatorConfigModel)} to avoid re-parsing and re-validating
 * the same configuration on every request. The constructor remains public for direct use
 * in tests.
 *
 * <p>Read full descriptions of configurations in {@link OID4VPAuthenticatorFactory}.
 */
public class VerifierConfig {

    private static final Logger logger = Logger.getLogger(VerifierConfig.class);

    private static final int MAX_CACHE_SIZE = 50;

    private static final Cache<CacheKey, VerifierConfig> CACHE =
            Caffeine.newBuilder().maximumSize(MAX_CACHE_SIZE).build();

    private final ClientIdentifierPrefix clientIdentifierPrefix;
    private final ResponseMode responseMode;
    private final RequestUriMethod requestUriMethod;
    private final String authReqUrlScheme;
    private final X509Certificate accessCertificate;
    private final String registrationCertificate;
    private final OID4VPProfileConfig profileConfig;
    private final boolean requireCryptographicHolderBinding;
    private final List<String> transactionDataRaw;
    private final String verifierInfoConfig;

    /**
     * Returns a cached {@code VerifierConfig} for the given authenticator config.
     * The cache is scoped by realm ID and bounded by {@link #MAX_CACHE_SIZE} entries.
     */
    public static VerifierConfig resolve(String realmId, AuthenticatorConfigModel authConfig) {
        Map<String, String> config =
                (authConfig != null && authConfig.getConfig() != null) ? authConfig.getConfig() : Map.of();
        CacheKey key = new CacheKey(realmId, Map.copyOf(config));
        return CACHE.get(key, k -> new VerifierConfig(realmId, authConfig));
    }

    private record CacheKey(String realmId, Map<String, String> config) {}

    public VerifierConfig(String realmId, AuthenticatorConfigModel authConfig) {
        logger.debugf("Collecting verifier config properties");

        Map<String, String> config =
                (authConfig != null && authConfig.getConfig() != null) ? authConfig.getConfig() : Map.of();

        this.profileConfig = OID4VPProfileConfig.resolve(realmId, authConfig);

        this.clientIdentifierPrefix = validateClientIdentifierPrefix(config.getOrDefault(
                OID4VPAuthenticatorFactory.CLIENT_IDENTIFIER_PREFIX_CONFIG,
                OID4VPAuthenticatorFactory.CLIENT_IDENTIFIER_PREFIX_CONFIG_DEFAULT));

        this.responseMode = validateResponseMode(config.getOrDefault(
                OID4VPAuthenticatorFactory.RESPONSE_MODE_CONFIG,
                OID4VPAuthenticatorFactory.RESPONSE_MODE_CONFIG_DEFAULT));

        this.requestUriMethod = validateRequestUriMethod(config.getOrDefault(
                OID4VPAuthenticatorFactory.REQUEST_URI_METHOD_CONFIG,
                OID4VPAuthenticatorFactory.REQUEST_URI_METHOD_CONFIG_DEFAULT));

        this.authReqUrlScheme = validateCustomUrlScheme(config.getOrDefault(
                OID4VPAuthenticatorFactory.CUSTOM_URL_SCHEME_CONFIG,
                OID4VPAuthenticatorFactory.CUSTOM_URL_SCHEME_CONFIG_DEFAULT));

        this.accessCertificate =
                validateX5CCertificate(config.get(OID4VPAuthenticatorFactory.ACCESS_CERTIFICATE_CONFIG));

        this.registrationCertificate = config.get(OID4VPAuthenticatorFactory.REGISTRATION_CERTIFICATE_CONFIG);

        this.requireCryptographicHolderBinding = Boolean.parseBoolean(config.getOrDefault(
                OID4VPAuthenticatorFactory.REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING_CONFIG,
                String.valueOf(OID4VPAuthenticatorFactory.REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING_CONFIG_DEFAULT)));

        this.transactionDataRaw = validateTransactionData(
                TransactionDataSupport.parseConfigValue(config.get(OID4VPAuthenticatorFactory.TRANSACTION_DATA_CONFIG)),
                requireCryptographicHolderBinding);

        this.verifierInfoConfig = config.get(OID4VPAuthenticatorFactory.VERIFIER_INFO_CONFIG);
    }

    private static ClientIdentifierPrefix validateClientIdentifierPrefix(String clientIdentifierPrefix) {
        try {
            return ClientIdentifierPrefix.fromValue(clientIdentifierPrefix);
        } catch (IllegalArgumentException e) {
            String defaultClientIdentifierPrefix = OID4VPAuthenticatorFactory.CLIENT_IDENTIFIER_PREFIX_CONFIG_DEFAULT;
            logger.warnf(
                    "Invalid client identifier prefix: %s. Defaulting to %s",
                    clientIdentifierPrefix, defaultClientIdentifierPrefix);
            return ClientIdentifierPrefix.fromValue(defaultClientIdentifierPrefix);
        }
    }

    private static ResponseMode validateResponseMode(String responseMode) {
        try {
            return ResponseMode.fromValue(responseMode);
        } catch (IllegalArgumentException e) {
            String defaultResponseMode = OID4VPAuthenticatorFactory.RESPONSE_MODE_CONFIG_DEFAULT;
            logger.warnf("Invalid response mode: %s. Defaulting to %s", responseMode, defaultResponseMode);
            return ResponseMode.fromValue(defaultResponseMode);
        }
    }

    private static String validateCustomUrlScheme(String customUrlScheme) {
        String defaultCustomUrlScheme = OID4VPAuthenticatorFactory.CUSTOM_URL_SCHEME_CONFIG_DEFAULT;
        if (StringUtils.isBlank(customUrlScheme)) {
            return defaultCustomUrlScheme;
        }

        if (!customUrlScheme.endsWith("://")) {
            logger.warnf(
                    "Custom URL scheme '%s' does not end with '://'. Defaulting to %s",
                    customUrlScheme, defaultCustomUrlScheme);
            return defaultCustomUrlScheme;
        }

        return customUrlScheme;
    }

    private static RequestUriMethod validateRequestUriMethod(String requestUriMethod) {
        try {
            return RequestUriMethod.fromValue(requestUriMethod);
        } catch (IllegalArgumentException e) {
            String fallback = OID4VPAuthenticatorFactory.REQUEST_URI_METHOD_CONFIG_DEFAULT;
            logger.warnf("Invalid request URI method: %s. Defaulting to %s", requestUriMethod, fallback);
            return RequestUriMethod.fromValue(fallback);
        }
    }

    private static X509Certificate validateX5CCertificate(String certificate) {
        if (StringUtils.isBlank(certificate)) {
            return null;
        }

        try {
            byte[] certBytes = Base64.getDecoder().decode(certificate);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
        } catch (Exception e) {
            throw new IllegalStateException(String.format("Invalid X5C certificate '%s'", certificate), e);
        }
    }

    private static List<String> validateTransactionData(
            List<String> transactionDataRaw, boolean requireCryptographicHolderBinding) {
        if (transactionDataRaw.isEmpty()) {
            return transactionDataRaw;
        }

        if (!requireCryptographicHolderBinding) {
            throw new IllegalStateException(
                    "transactionData cannot be used when requireCryptographicHolderBinding is false (OpenID4VP B.3.3)");
        }

        return transactionDataRaw;
    }

    public ClientIdentifierPrefix getClientIdentifierPrefix() {
        return clientIdentifierPrefix;
    }

    public ResponseMode getResponseMode() {
        return responseMode;
    }

    public String getAuthReqUrlScheme() {
        return authReqUrlScheme;
    }

    public RequestUriMethod getRequestUriMethod() {
        return requestUriMethod;
    }

    public X509Certificate getAccessCertificate() {
        return accessCertificate;
    }

    public String getRegistrationCertificate() {
        return registrationCertificate;
    }

    public OID4VPProfileConfig getProfileConfig() {
        return profileConfig;
    }

    public boolean shouldRequireCryptographicHolderBinding() {
        return this.requireCryptographicHolderBinding;
    }

    public List<String> getTransactionDataRaw() {
        return transactionDataRaw;
    }

    public String getVerifierInfoConfig() {
        return verifierInfoConfig;
    }
}
