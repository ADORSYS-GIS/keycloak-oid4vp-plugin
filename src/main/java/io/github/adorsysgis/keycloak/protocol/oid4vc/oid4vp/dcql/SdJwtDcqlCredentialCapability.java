package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.SdGenericFormat;
import java.util.List;
import org.keycloak.VCFormat;
import org.keycloak.common.VerificationException;
import org.keycloak.utils.StringUtil;

/** Production DCQL path for {@code dc+sd-jwt} user authentication. */
public final class SdJwtDcqlCredentialCapability implements DcqlCredentialCapability {

    @Override
    public String format() {
        return VCFormat.SD_JWT_VC;
    }

    @Override
    public void validateCredentialQuery(Credential credential) {
        validateMeta(credential.getMeta());
        validateClaimPaths(credential);
    }

    @Override
    public boolean supportsPresentationPreValidation() {
        return true;
    }

    @Override
    public void validatePresentation(Credential credential, String presentedToken) throws VerificationException {
        DcqlPresentationValidator.validatePresentation(credential, presentedToken);
    }

    @Override
    public void contributeVpFormatsSupported(ClientMetadata.VpFormat vpFormat, List<String> signatureAlgorithms) {
        SdGenericFormat format = new SdGenericFormat();
        format.setSdJwtAlgValues(signatureAlgorithms);
        format.setKbJwtAlgValues(signatureAlgorithms);
        vpFormat.setDcSdJwt(format);
    }

    private static void validateMeta(Meta meta) {
        if (meta.getVctValues() == null || meta.getVctValues().isEmpty()) {
            throw new IllegalArgumentException("meta.vct_values must be non-empty for dc+sd-jwt credential queries");
        }
        if (meta.getVctValues().stream().anyMatch(StringUtil::isBlank)) {
            throw new IllegalArgumentException("meta.vct_values must not contain blank entries");
        }
    }

    private static void validateClaimPaths(Credential credential) {
        if (credential.getClaims() == null) {
            return;
        }
        credential.getClaims().forEach(claim -> {
            List<String> path = claim.getPath();
            if (path.stream().anyMatch(SdJwtDcqlCredentialCapability::isUnsupportedPathSegment)) {
                throw new IllegalArgumentException(
                        "dcql_query claim path supports object property names only; array indexes and null wildcards are not supported");
            }
            if (isVpWrapperPath(path)) {
                throw new IllegalArgumentException(credential.getFormat()
                        + " claim paths must be relative to the VC root, not the VP wrapper: "
                        + path);
            }
        });
    }

    private static boolean isUnsupportedPathSegment(String segment) {
        return "null".equals(segment) || (!segment.isEmpty() && segment.chars().allMatch(Character::isDigit));
    }

    private static boolean isVpWrapperPath(List<String> path) {
        String first = path.getFirst();
        return "verifiableCredential".equals(first) || "vp".equals(first);
    }
}
