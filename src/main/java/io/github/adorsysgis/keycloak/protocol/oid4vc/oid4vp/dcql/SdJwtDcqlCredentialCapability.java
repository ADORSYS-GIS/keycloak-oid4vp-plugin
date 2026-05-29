package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.VerifierConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.SdGenericFormat;
import java.util.List;
import org.keycloak.VCFormat;
import org.keycloak.common.VerificationException;

/** Production DCQL path for {@code dc+sd-jwt} user authentication. */
public final class SdJwtDcqlCredentialCapability implements DcqlCredentialCapability {

    private final SdJwtCredentialConstrainer constrainer = new SdJwtCredentialConstrainer();

    @Override
    public String format() {
        return VCFormat.SD_JWT_VC;
    }

    @Override
    public boolean supports(VerifierConfig config) {
        return true;
    }

    @Override
    public DcqlQuery buildAuthorizationQuery(VerifierConfig config) {
        return constrainer.buildQuery(config.buildSdJwtQuerySpec());
    }

    @Override
    public void validatePresentation(DcqlQuery query, String presentedToken) throws VerificationException {
        DcqlPresentationValidator.validatePresentation(query, presentedToken);
    }

    @Override
    public void contributeVpFormatsSupported(ClientMetadata.VpFormat vpFormat, List<String> signatureAlgorithms) {
        SdGenericFormat format = new SdGenericFormat();
        format.setSdJwtAlgValues(signatureAlgorithms);
        format.setKbJwtAlgValues(signatureAlgorithms);
        vpFormat.setDcSdJwt(format);
    }
}
