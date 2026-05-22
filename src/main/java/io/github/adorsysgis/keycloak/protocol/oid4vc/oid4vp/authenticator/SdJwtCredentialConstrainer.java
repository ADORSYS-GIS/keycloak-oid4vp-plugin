package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.util.List;

/**
 * Constructs a DCQL query for requesting an SD-JWT credential.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtCredentialConstrainer {

    private final io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql.SdJwtCredentialConstrainer delegate =
            new io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql.SdJwtCredentialConstrainer();

    /**
     * Constructs a DCQL query requiring the disclosure of some claims.
     */
    public DcqlQuery generateDcqlQuery(QueryMap queryMap) {
        var spec = io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql.SdJwtCredentialConstrainer.QuerySpec.of(
                queryMap.expectedVcts(), queryMap.requiredClaims());
        return delegate.buildQuery(spec);
    }

    public record QueryMap(List<String> expectedVcts, List<String> requiredClaims) {}
}
