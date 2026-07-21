package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import java.util.List;
import org.keycloak.common.VerificationException;

/**
 * Format-specific DCQL support for presentation validation.
 *
 * <p>Each capability owns VP format metadata advertisement and DCQL presentation validation
 * for responses keyed by credential query id.
 */
public interface DcqlCredentialCapability {

    String format();

    void validateCredentialQuery(Credential credential);

    boolean supportsPresentationPreValidation();

    void validatePresentation(Credential credential, String presentedToken) throws VerificationException;

    void contributeVpFormatsSupported(ClientMetadata.VpFormat vpFormat, List<String> signatureAlgorithms);
}
