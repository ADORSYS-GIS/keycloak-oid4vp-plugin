package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config;

import com.apicatalog.jsonld.StringUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseMode;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakContext;

/**
 * Access configurations that modulate the verifier's behavior.
 * <p></p>
 * Read full descriptions of configurations in {@link SdJwtAuthenticatorFactory}.
 */
public class VerifierConfig {

    private static final Logger logger = Logger.getLogger(VerifierConfig.class);

    private final SdJwtAuthRequirements authRequirements;

    private final ResponseMode responseMode;
    private final String authReqUrlScheme;
    private final X509Certificate accessCertificate;
    private final String registrationCertificate;

    public VerifierConfig(KeycloakContext context, AuthenticatorConfigModel authConfig) {
        logger.debugf("Collecting verifier config properties");

        Map<String, String> config =
                (authConfig != null && authConfig.getConfig() != null) ? authConfig.getConfig() : Map.of();

        // TODO: Relocate these non-SD-JWT-specific configurations.
        //  They should normally not be exposed through SdJwtAuthenticatorFactory.

        this.responseMode = validateResponseMode(config.getOrDefault(
                SdJwtAuthenticatorFactory.RESPONSE_MODE_CONFIG,
                SdJwtAuthenticatorFactory.RESPONSE_MODE_CONFIG_DEFAULT));

        this.authReqUrlScheme = validateCustomUrlScheme(config.getOrDefault(
                SdJwtAuthenticatorFactory.CUSTOM_URL_SCHEME_CONFIG,
                SdJwtAuthenticatorFactory.CUSTOM_URL_SCHEME_CONFIG_DEFAULT));

        this.accessCertificate =
                validateX5CCertificate(config.get(SdJwtAuthenticatorFactory.ACCESS_CERTIFICATE_CONFIG));

        this.registrationCertificate = config.get(SdJwtAuthenticatorFactory.REGISTRATION_CERTIFICATE_CONFIG);

        // Collect authentication requirements
        this.authRequirements = new SdJwtAuthRequirements(context, authConfig);
    }

    private static ResponseMode validateResponseMode(String responseMode) {
        try {
            return ResponseMode.fromValue(responseMode);
        } catch (IllegalArgumentException e) {
            String defaultResponseMode = SdJwtAuthenticatorFactory.RESPONSE_MODE_CONFIG_DEFAULT;
            logger.warnf("Invalid response mode: %s. Defaulting to %s", responseMode, defaultResponseMode);
            return ResponseMode.fromValue(defaultResponseMode);
        }
    }

    private static String validateCustomUrlScheme(String customUrlScheme) {
        String defaultCustomUrlScheme = SdJwtAuthenticatorFactory.CUSTOM_URL_SCHEME_CONFIG_DEFAULT;
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

        // TODO: Validate that the configured certificate matches the current active
        //  key that will be used for signing authorization requests.
    }

    public SdJwtAuthRequirements getAuthRequirements() {
        return authRequirements;
    }

    public ResponseMode getResponseMode() {
        return responseMode;
    }

    public String getAuthReqUrlScheme() {
        return authReqUrlScheme;
    }

    public X509Certificate getAccessCertificate() {
        return accessCertificate;
    }

    public String getRegistrationCertificate() {
        return registrationCertificate;
    }
}
