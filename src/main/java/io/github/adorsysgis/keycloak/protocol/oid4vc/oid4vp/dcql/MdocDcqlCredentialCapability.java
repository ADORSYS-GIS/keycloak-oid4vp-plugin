package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import com.authlete.cose.constants.COSEAlgorithms;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialFormat;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.MdocGenericFormat;
import java.util.List;
import org.keycloak.common.VerificationException;
import org.keycloak.utils.StringUtil;

/**
 * DCQL capability for {@code mso_mdoc} (ISO/IEC 18013-5) credentials.
 *
 * <p>Contributes VP format metadata with COSE algorithm identifiers for
 * issuer authentication and device authentication per OpenID4VP Final 1.0
 * Appendix B.2.2.
 */
public final class MdocDcqlCredentialCapability implements DcqlCredentialCapability {

    @Override
    public String format() {
        return CredentialFormat.MSO_MDOC.getValue();
    }

    @Override
    public void validateCredentialQuery(Credential credential) {
        if (StringUtil.isBlank(credential.getMeta().getDoctypeValue())) {
            throw new IllegalArgumentException("meta.doctype_value must be non-empty for mso_mdoc credential queries");
        }
        if (credential.getClaims() == null) {
            return;
        }
        credential.getClaims().forEach(claim -> {
            if (claim.getPath().size() != 2) {
                throw new IllegalArgumentException(
                        "mso_mdoc claim paths must contain exactly namespace and element identifier");
            }
        });
    }

    @Override
    public boolean supportsPresentationPreValidation() {
        return false;
    }

    @Override
    public void validatePresentation(Credential credential, String presentedToken) throws VerificationException {
        throw new UnsupportedOperationException(
                "DCQL presentation validation is not yet supported for mso_mdoc credentials");
    }

    @Override
    public void contributeVpFormatsSupported(ClientMetadata.VpFormat vpFormat, List<String> signatureAlgorithms) {
        MdocGenericFormat format = new MdocGenericFormat();
        // `COSEAlgorithms.getValueByName` returns 0 (the reserved COSE algorithm) for JOSE names
        // it cannot map; advertising a reserved algorithm is misleading to wallets, so drop them.
        List<Integer> coseAlgorithms = signatureAlgorithms.stream()
                .map(COSEAlgorithms::getValueByName)
                .filter(value -> value != 0)
                .toList();
        format.setIssuerAuthAlgValues(coseAlgorithms);
        format.setDeviceAuthAlgValues(coseAlgorithms);
        vpFormat.setMsoMdoc(format);
    }
}
