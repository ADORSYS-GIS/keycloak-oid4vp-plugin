package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.VerifierConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.util.List;
import org.keycloak.common.VerificationException;

/**
 * Format-specific DCQL support for authorization requests and presentation validation.
 *
 * <p>Each capability owns VP format metadata advertisement, DCQL query construction for a
 * {@link VerifierConfig}, and presentation validation for responses keyed by credential query id.
 */
public interface DcqlCredentialCapability {

    String format();

    boolean supports(VerifierConfig config);

    DcqlQuery buildAuthorizationQuery(VerifierConfig config);

    void validatePresentation(DcqlQuery query, String presentedToken) throws VerificationException;

    void contributeVpFormatsSupported(ClientMetadata.VpFormat vpFormat, List<String> signatureAlgorithms);
}
