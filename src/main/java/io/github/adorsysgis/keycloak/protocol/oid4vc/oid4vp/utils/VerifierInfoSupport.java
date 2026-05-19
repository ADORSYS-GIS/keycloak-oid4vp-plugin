package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.VerifierInfo;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationRequestService;
import java.util.ArrayList;
import java.util.List;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Builds and validates OpenID4VP {@code verifier_info} request parameter values (§5.1, §5.11).
 */
public final class VerifierInfoSupport {

    private VerifierInfoSupport() {}

    public static List<VerifierInfo> build(
            String registrationCertificate, String verifierInfoConfigJson, String dcqlCredentialId) {
        List<VerifierInfo> entries = new ArrayList<>();

        if (!StringUtil.isBlank(registrationCertificate)) {
            entries.add(new VerifierInfo()
                    .setFormat(AuthorizationRequestService.REGISTRATION_CERT_FORMAT)
                    .setData(registrationCertificate)
                    .setCredentialIds(List.of(dcqlCredentialId)));
        }

        entries.addAll(parseConfigEntries(verifierInfoConfigJson));

        if (entries.isEmpty()) {
            return null;
        }

        validate(entries, dcqlCredentialId);
        return entries;
    }

    private static List<VerifierInfo> parseConfigEntries(String verifierInfoConfigJson) {
        if (StringUtil.isBlank(verifierInfoConfigJson)) {
            return List.of();
        }

        try {
            List<VerifierInfo> parsed =
                    JsonSerialization.readValue(verifierInfoConfigJson, new TypeReference<List<VerifierInfo>>() {});
            return parsed != null ? parsed : List.of();
        } catch (Exception e) {
            throw new IllegalArgumentException("verifierInfo must be a JSON array of verifier_info objects", e);
        }
    }

    public static void validate(List<VerifierInfo> entries, String dcqlCredentialId) {
        for (VerifierInfo entry : entries) {
            if (StringUtil.isBlank(entry.getFormat())) {
                throw new IllegalArgumentException("verifier_info format must not be blank");
            }
            if (StringUtil.isBlank(entry.getData())) {
                throw new IllegalArgumentException("verifier_info data must not be blank");
            }
            List<String> credentialIds = entry.getCredentialIds();
            if (credentialIds != null) {
                if (credentialIds.isEmpty()) {
                    throw new IllegalArgumentException("verifier_info credential_ids must be non-empty when present");
                }
                boolean matches = credentialIds.stream().anyMatch(dcqlCredentialId::equals);
                if (!matches) {
                    throw new IllegalArgumentException(String.format(
                            "verifier_info credential_ids must reference DCQL credential id '%s'", dcqlCredentialId));
                }
            }
        }
    }
}
