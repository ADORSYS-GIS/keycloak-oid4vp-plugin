package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.TrustPolicy;
import java.net.URI;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.RealmModel;
import org.keycloak.utils.StringUtil;

/** Configuration for an ETSI PID Provider LoTE trust-material identity provider. */
public class EudiPidTrustIdentityProviderConfig extends IdentityProviderModel {

    public static final String TRUST_LIST_URL = "trustListUrl";
    public static final String TRUST_LIST_SIGNING_CERTIFICATE = "trustListSigningCertificate";
    public static final String SERVICE_TYPE = "serviceType";
    public static final String ISSUER = "issuer";

    public EudiPidTrustIdentityProviderConfig() {}

    public EudiPidTrustIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    @Override
    public Boolean isHideOnLogin() {
        return true;
    }

    @Override
    public void validate(RealmModel realm) {
        super.validate(realm);
        validateHttpsUrl(getTrustListUrl());
        if (StringUtil.isBlank(getTrustListSigningCertificate())) {
            throw new IllegalArgumentException("EUDI PID trust-list signing certificate is required");
        }
        try {
            CertificateUtil.parseCertificate(getTrustListSigningCertificate());
        } catch (Exception e) {
            throw new IllegalArgumentException("EUDI PID trust-list signing certificate is invalid", e);
        }
    }

    public String getTrustListUrl() {
        return getConfig().get(TRUST_LIST_URL);
    }

    public String getTrustListSigningCertificate() {
        return getConfig().get(TRUST_LIST_SIGNING_CERTIFICATE);
    }

    public String getServiceType() {
        return getConfig().getOrDefault(SERVICE_TYPE, EudiPidTrustListProvider.PID_ISSUANCE_SERVICE_TYPE);
    }

    public String getIssuer() {
        return getConfig().get(ISSUER);
    }

    TrustPolicy toTrustPolicy() {
        return new TrustPolicy()
                .setType(TrustPolicy.EUDI_PID_TRUST_LIST)
                .setTrustListUrl(getTrustListUrl())
                .setTrustListSigningCertificate(getTrustListSigningCertificate())
                .setServiceType(getServiceType())
                .setIssuer(getIssuer());
    }

    private static void validateHttpsUrl(String value) {
        if (StringUtil.isBlank(value)) {
            throw new IllegalArgumentException("EUDI PID trust-list URL is required");
        }
        try {
            URI uri = URI.create(value);
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null) {
                throw new IllegalArgumentException("EUDI PID trust-list URL must be an absolute HTTPS URL");
            }
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("EUDI PID trust-list URL must be an absolute HTTPS URL", e);
        }
    }
}
